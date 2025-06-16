#!/usr/bin/env python3
"""
MCP Stress Testing and Load Testing Module

Specialized stress testing capabilities for MCP server deployment validation.
Agent 5: Advanced stress testing with load simulation, chaos engineering, and failure injection.
"""

import asyncio
import time
import random
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from pathlib import Path
import sys
import psutil
import statistics
from concurrent.futures import ThreadPoolExecutor
import threading
from enum import Enum

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.mcp.manager import get_mcp_manager
from src.mcp.servers import MCPServerRegistry

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LoadPattern(Enum):
    """Load testing patterns."""
    CONSTANT = "constant"
    RAMP_UP = "ramp_up"
    SPIKE = "spike"
    BURST = "burst"
    GRADUAL = "gradual"


class StressTestType(Enum):
    """Stress test types."""
    LOAD = "load"
    VOLUME = "volume"
    SPIKE = "spike"
    ENDURANCE = "endurance"
    CAPACITY = "capacity"
    MEMORY = "memory"
    CONCURRENT = "concurrent"


@dataclass
class StressTestConfig:
    """Stress test configuration."""
    test_type: StressTestType
    load_pattern: LoadPattern
    duration_seconds: int
    max_concurrent_users: int
    operations_per_second: float
    ramp_up_time_seconds: int = 30
    ramp_down_time_seconds: int = 30
    spike_duration_seconds: int = 10
    memory_target_mb: int = 1000
    enable_chaos: bool = False
    chaos_probability: float = 0.1


@dataclass
class StressTestMetrics:
    """Stress test metrics."""
    test_id: str
    start_time: str
    end_time: str
    duration_seconds: float
    total_operations: int
    successful_operations: int
    failed_operations: int
    success_rate: float
    failure_rate: float
    operations_per_second: float
    avg_response_time_ms: float
    min_response_time_ms: float
    max_response_time_ms: float
    p50_response_time_ms: float
    p95_response_time_ms: float
    p99_response_time_ms: float
    throughput_peak: float
    memory_usage_peak_mb: float
    memory_usage_avg_mb: float
    cpu_usage_peak_percent: float
    cpu_usage_avg_percent: float
    error_breakdown: Dict[str, int] = field(default_factory=dict)
    chaos_events_triggered: int = 0


@dataclass
class OperationResult:
    """Individual operation result."""
    operation_id: str
    start_time: float
    end_time: float
    duration_ms: float
    success: bool
    error_type: Optional[str] = None
    error_message: Optional[str] = None
    memory_usage_mb: float = 0
    cpu_usage_percent: float = 0


class MCPStressTester:
    """
    Advanced MCP Stress Testing Framework.
    
    Provides comprehensive stress testing capabilities:
    - Load testing with various patterns
    - Volume testing for data handling
    - Spike testing for sudden load increases
    - Endurance testing for long-running stability
    - Memory and resource stress testing
    - Chaos engineering with failure injection
    """
    
    def __init__(self):
        self.manager = get_mcp_manager()
        self.registry = MCPServerRegistry()
        self.session_id = f"stress_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.process = psutil.Process()
        self.results: List[OperationResult] = []
        self.metrics_history: List[Dict[str, Any]] = []
        self.active_operations = 0
        self.stop_event = threading.Event()
        
        # Resource monitoring
        self.monitor_thread = None
        self.monitoring_active = False
        
    async def initialize(self):
        """Initialize stress testing environment."""
        logger.info("Initializing MCP Stress Testing Framework...")
        await self.manager.initialize()
        
        # Create test context
        self.test_context_id = f"stress_context_{self.session_id}"
        self.test_context = self.manager.create_context(self.test_context_id)
        
        # Enable all servers
        for server_name in self.registry.list_servers():
            self.manager.enable_server(self.test_context_id, server_name)
        
        logger.info(f"Stress testing initialized with {len(self.registry.list_servers())} servers")
    
    async def run_stress_test(self, config: StressTestConfig) -> StressTestMetrics:
        """
        Run comprehensive stress test based on configuration.
        
        Args:
            config: Stress test configuration
            
        Returns:
            Detailed stress test metrics
        """
        logger.info(f"Starting {config.test_type.value} stress test with {config.load_pattern.value} pattern")
        
        test_id = f"{config.test_type.value}_{config.load_pattern.value}_{self.session_id}"
        start_time = datetime.now()
        
        # Start resource monitoring
        self._start_resource_monitoring()
        
        try:
            # Execute stress test based on type
            if config.test_type == StressTestType.LOAD:
                await self._run_load_test(config)
            elif config.test_type == StressTestType.VOLUME:
                await self._run_volume_test(config)
            elif config.test_type == StressTestType.SPIKE:
                await self._run_spike_test(config)
            elif config.test_type == StressTestType.ENDURANCE:
                await self._run_endurance_test(config)
            elif config.test_type == StressTestType.CAPACITY:
                await self._run_capacity_test(config)
            elif config.test_type == StressTestType.MEMORY:
                await self._run_memory_test(config)
            elif config.test_type == StressTestType.CONCURRENT:
                await self._run_concurrent_test(config)
                
        finally:
            # Stop resource monitoring
            self._stop_resource_monitoring()
        
        end_time = datetime.now()
        
        # Calculate metrics
        metrics = self._calculate_stress_metrics(test_id, start_time, end_time, config)
        
        # Save results
        await self._save_stress_results(metrics, config)
        
        return metrics
    
    async def _run_load_test(self, config: StressTestConfig):
        """Run load testing with specified pattern."""
        if config.load_pattern == LoadPattern.CONSTANT:
            await self._constant_load(config)
        elif config.load_pattern == LoadPattern.RAMP_UP:
            await self._ramp_up_load(config)
        elif config.load_pattern == LoadPattern.SPIKE:
            await self._spike_load(config)
        elif config.load_pattern == LoadPattern.BURST:
            await self._burst_load(config)
        elif config.load_pattern == LoadPattern.GRADUAL:
            await self._gradual_load(config)
    
    async def _constant_load(self, config: StressTestConfig):
        """Execute constant load pattern."""
        logger.info(f"Executing constant load: {config.operations_per_second} ops/sec for {config.duration_seconds}s")
        
        operation_interval = 1.0 / config.operations_per_second
        end_time = time.time() + config.duration_seconds
        operation_count = 0
        
        while time.time() < end_time and not self.stop_event.is_set():
            # Create batch of operations
            batch_size = min(config.max_concurrent_users, int(config.operations_per_second))
            tasks = []
            
            for _ in range(batch_size):
                if time.time() >= end_time:
                    break
                task = self._execute_test_operation(f"const_{operation_count}", config)
                tasks.append(task)
                operation_count += 1
            
            # Execute batch
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            
            # Wait for next interval
            await asyncio.sleep(operation_interval)
    
    async def _ramp_up_load(self, config: StressTestConfig):
        """Execute ramp-up load pattern."""
        logger.info(f"Executing ramp-up load: 0 to {config.operations_per_second} ops/sec over {config.ramp_up_time_seconds}s")
        
        start_time = time.time()
        operation_count = 0
        
        # Ramp up phase
        ramp_end_time = start_time + config.ramp_up_time_seconds
        while time.time() < ramp_end_time and not self.stop_event.is_set():
            elapsed = time.time() - start_time
            progress = elapsed / config.ramp_up_time_seconds
            current_ops_per_sec = config.operations_per_second * progress
            
            if current_ops_per_sec > 0:
                batch_size = max(1, int(current_ops_per_sec))
                tasks = []
                
                for _ in range(batch_size):
                    task = self._execute_test_operation(f"ramp_{operation_count}", config)
                    tasks.append(task)
                    operation_count += 1
                
                await asyncio.gather(*tasks, return_exceptions=True)
            
            await asyncio.sleep(1.0)
        
        # Sustained load phase
        sustained_end_time = ramp_end_time + config.duration_seconds
        while time.time() < sustained_end_time and not self.stop_event.is_set():
            batch_size = int(config.operations_per_second)
            tasks = []
            
            for _ in range(batch_size):
                task = self._execute_test_operation(f"sust_{operation_count}", config)
                tasks.append(task)
                operation_count += 1
            
            await asyncio.gather(*tasks, return_exceptions=True)
            await asyncio.sleep(1.0)
        
        # Ramp down phase
        ramp_down_end_time = sustained_end_time + config.ramp_down_time_seconds
        while time.time() < ramp_down_end_time and not self.stop_event.is_set():
            elapsed = time.time() - sustained_end_time
            progress = 1.0 - (elapsed / config.ramp_down_time_seconds)
            current_ops_per_sec = config.operations_per_second * progress
            
            if current_ops_per_sec > 0:
                batch_size = max(1, int(current_ops_per_sec))
                tasks = []
                
                for _ in range(batch_size):
                    task = self._execute_test_operation(f"down_{operation_count}", config)
                    tasks.append(task)
                    operation_count += 1
                
                await asyncio.gather(*tasks, return_exceptions=True)
            
            await asyncio.sleep(1.0)
    
    async def _spike_load(self, config: StressTestConfig):
        """Execute spike load pattern."""
        logger.info(f"Executing spike load: {config.operations_per_second}x spikes for {config.spike_duration_seconds}s")
        
        normal_ops = config.operations_per_second
        spike_ops = normal_ops * 5  # 5x spike
        end_time = time.time() + config.duration_seconds
        operation_count = 0
        
        while time.time() < end_time and not self.stop_event.is_set():
            # Normal load for 30 seconds
            normal_end = min(time.time() + 30, end_time)
            while time.time() < normal_end and not self.stop_event.is_set():
                tasks = []
                for _ in range(int(normal_ops)):
                    task = self._execute_test_operation(f"norm_{operation_count}", config)
                    tasks.append(task)
                    operation_count += 1
                
                await asyncio.gather(*tasks, return_exceptions=True)
                await asyncio.sleep(1.0)
            
            # Spike load for configured duration
            if time.time() < end_time:
                spike_end = min(time.time() + config.spike_duration_seconds, end_time)
                logger.info(f"Starting spike: {spike_ops} ops/sec")
                
                while time.time() < spike_end and not self.stop_event.is_set():
                    tasks = []
                    for _ in range(int(spike_ops)):
                        task = self._execute_test_operation(f"spike_{operation_count}", config)
                        tasks.append(task)
                        operation_count += 1
                    
                    await asyncio.gather(*tasks, return_exceptions=True)
                    await asyncio.sleep(1.0)
                
                logger.info("Spike completed")
    
    async def _burst_load(self, config: StressTestConfig):
        """Execute burst load pattern."""
        logger.info(f"Executing burst load: bursts of {config.max_concurrent_users} operations")
        
        end_time = time.time() + config.duration_seconds
        operation_count = 0
        
        while time.time() < end_time and not self.stop_event.is_set():
            # Create burst of operations
            tasks = []
            burst_size = config.max_concurrent_users
            
            for _ in range(burst_size):
                task = self._execute_test_operation(f"burst_{operation_count}", config)
                tasks.append(task)
                operation_count += 1
            
            # Execute burst
            await asyncio.gather(*tasks, return_exceptions=True)
            
            # Wait before next burst
            await asyncio.sleep(5.0)
    
    async def _gradual_load(self, config: StressTestConfig):
        """Execute gradual load increase pattern."""
        logger.info(f"Executing gradual load: gradual increase to {config.operations_per_second} ops/sec")
        
        steps = 10
        step_duration = config.duration_seconds / steps
        operation_count = 0
        
        for step in range(steps):
            if self.stop_event.is_set():
                break
                
            step_ops = (step + 1) * (config.operations_per_second / steps)
            logger.info(f"Step {step + 1}: {step_ops:.1f} ops/sec")
            
            step_end_time = time.time() + step_duration
            while time.time() < step_end_time and not self.stop_event.is_set():
                batch_size = max(1, int(step_ops))
                tasks = []
                
                for _ in range(batch_size):
                    task = self._execute_test_operation(f"grad_{operation_count}", config)
                    tasks.append(task)
                    operation_count += 1
                
                await asyncio.gather(*tasks, return_exceptions=True)
                await asyncio.sleep(1.0)
    
    async def _run_volume_test(self, config: StressTestConfig):
        """Run volume testing with large data sets."""
        logger.info("Executing volume test with large data operations")
        
        # Create large data operations
        large_data_operations = [
            ("desktop-commander", "execute_command", {
                "command": f"echo '{'x' * 1000}'",  # 1KB output
                "description": "Volume test with large output"
            }),
            ("brave", "brave_web_search", {
                "query": "volume test " + "x" * 100,  # Large query
                "count": 10
            })
        ]
        
        end_time = time.time() + config.duration_seconds
        operation_count = 0
        
        while time.time() < end_time and not self.stop_event.is_set():
            # Execute volume operations
            tasks = []
            for server, tool, params in large_data_operations:
                if server in self.registry.list_servers():
                    task = self._execute_specific_operation(
                        f"vol_{operation_count}",
                        server,
                        tool,
                        params,
                        config
                    )
                    tasks.append(task)
                    operation_count += 1
            
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            
            await asyncio.sleep(2.0)
    
    async def _run_spike_test(self, config: StressTestConfig):
        """Run dedicated spike testing."""
        await self._spike_load(config)
    
    async def _run_endurance_test(self, config: StressTestConfig):
        """Run endurance testing for long-term stability."""
        logger.info(f"Executing endurance test for {config.duration_seconds}s")
        
        # Use modest but sustained load
        ops_per_interval = max(1, int(config.operations_per_second / 4))  # 25% of max
        interval_seconds = 10  # Check every 10 seconds
        
        end_time = time.time() + config.duration_seconds
        operation_count = 0
        
        while time.time() < end_time and not self.stop_event.is_set():
            tasks = []
            
            for _ in range(ops_per_interval):
                task = self._execute_test_operation(f"endur_{operation_count}", config)
                tasks.append(task)
                operation_count += 1
            
            await asyncio.gather(*tasks, return_exceptions=True)
            
            # Log progress every 5 minutes
            if operation_count % 100 == 0:
                elapsed = time.time() - (end_time - config.duration_seconds)
                logger.info(f"Endurance test progress: {elapsed/60:.1f} minutes, {operation_count} operations")
            
            await asyncio.sleep(interval_seconds)
    
    async def _run_capacity_test(self, config: StressTestConfig):
        """Run capacity testing to find limits."""
        logger.info("Executing capacity test to find system limits")
        
        # Gradually increase load until failure
        current_ops = 1
        max_ops = config.operations_per_second
        step_duration = 30  # 30 seconds per step
        
        while current_ops <= max_ops and not self.stop_event.is_set():
            logger.info(f"Testing capacity at {current_ops} ops/sec")
            
            step_end_time = time.time() + step_duration
            step_successes = 0
            step_failures = 0
            operation_count = 0
            
            while time.time() < step_end_time and not self.stop_event.is_set():
                tasks = []
                
                for _ in range(current_ops):
                    task = self._execute_test_operation(f"cap_{current_ops}_{operation_count}", config)
                    tasks.append(task)
                    operation_count += 1
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Count successes and failures
                for result in results:
                    if isinstance(result, Exception):
                        step_failures += 1
                    else:
                        step_successes += 1
                
                await asyncio.sleep(1.0)
            
            # Check if failure rate is too high
            total_operations = step_successes + step_failures
            failure_rate = step_failures / total_operations if total_operations > 0 else 0
            
            logger.info(f"Capacity {current_ops} ops/sec: {failure_rate:.1%} failure rate")
            
            if failure_rate > 0.1:  # More than 10% failure rate
                logger.info(f"Capacity limit reached at {current_ops} ops/sec")
                break
            
            # Increase load for next step
            current_ops = min(current_ops * 2, max_ops)
    
    async def _run_memory_test(self, config: StressTestConfig):
        """Run memory stress testing."""
        logger.info(f"Executing memory stress test targeting {config.memory_target_mb}MB")
        
        # Create memory-intensive operations
        memory_operations = []
        base_memory = self.process.memory_info().rss / 1024 / 1024
        
        end_time = time.time() + config.duration_seconds
        operation_count = 0
        
        while time.time() < end_time and not self.stop_event.is_set():
            current_memory = self.process.memory_info().rss / 1024 / 1024
            memory_delta = current_memory - base_memory
            
            if memory_delta < config.memory_target_mb:
                # Create more operations to increase memory usage
                batch_size = min(10, config.max_concurrent_users)
                tasks = []
                
                for _ in range(batch_size):
                    task = self._execute_test_operation(f"mem_{operation_count}", config)
                    tasks.append(task)
                    operation_count += 1
                
                await asyncio.gather(*tasks, return_exceptions=True)
            else:
                logger.info(f"Memory target reached: {memory_delta:.1f}MB")
                # Maintain current memory level
                await asyncio.sleep(5.0)
            
            await asyncio.sleep(1.0)
    
    async def _run_concurrent_test(self, config: StressTestConfig):
        """Run concurrent user simulation."""
        logger.info(f"Executing concurrent test with {config.max_concurrent_users} simulated users")
        
        # Create concurrent user sessions
        user_tasks = []
        
        for user_id in range(config.max_concurrent_users):
            task = self._simulate_user_session(user_id, config)
            user_tasks.append(task)
        
        # Run all user sessions concurrently
        await asyncio.gather(*user_tasks, return_exceptions=True)
    
    async def _simulate_user_session(self, user_id: int, config: StressTestConfig):
        """Simulate individual user session."""
        end_time = time.time() + config.duration_seconds
        operation_count = 0
        
        while time.time() < end_time and not self.stop_event.is_set():
            # Simulate user think time
            think_time = random.uniform(0.5, 2.0)
            await asyncio.sleep(think_time)
            
            # Execute user operation
            await self._execute_test_operation(f"user_{user_id}_{operation_count}", config)
            operation_count += 1
    
    async def _execute_test_operation(self, operation_id: str, config: StressTestConfig) -> OperationResult:
        """Execute a single test operation."""
        start_time = time.time()
        memory_before = self.process.memory_info().rss / 1024 / 1024
        
        try:
            # Apply chaos engineering if enabled
            if config.enable_chaos and random.random() < config.chaos_probability:
                await self._inject_chaos()
            
            # Select random operation
            operation = self._get_random_operation()
            server_name, tool_name, params = operation
            
            # Execute operation
            result = await self._execute_specific_operation(
                operation_id, server_name, tool_name, params, config
            )
            
            return result
            
        except Exception as e:
            end_time = time.time()
            memory_after = self.process.memory_info().rss / 1024 / 1024
            
            return OperationResult(
                operation_id=operation_id,
                start_time=start_time,
                end_time=end_time,
                duration_ms=(end_time - start_time) * 1000,
                success=False,
                error_type=type(e).__name__,
                error_message=str(e),
                memory_usage_mb=memory_after - memory_before
            )
    
    async def _execute_specific_operation(
        self,
        operation_id: str,
        server_name: str,
        tool_name: str,
        params: Dict[str, Any],
        config: StressTestConfig
    ) -> OperationResult:
        """Execute specific MCP operation."""
        start_time = time.time()
        memory_before = self.process.memory_info().rss / 1024 / 1024
        cpu_before = self.process.cpu_percent()
        
        self.active_operations += 1
        
        try:
            result = await self.manager.call_tool(
                f"{server_name}.{tool_name}",
                params,
                self.test_context_id
            )
            
            end_time = time.time()
            memory_after = self.process.memory_info().rss / 1024 / 1024
            cpu_after = self.process.cpu_percent()
            
            operation_result = OperationResult(
                operation_id=operation_id,
                start_time=start_time,
                end_time=end_time,
                duration_ms=(end_time - start_time) * 1000,
                success=True,
                memory_usage_mb=memory_after - memory_before,
                cpu_usage_percent=(cpu_before + cpu_after) / 2
            )
            
            self.results.append(operation_result)
            return operation_result
            
        except Exception as e:
            end_time = time.time()
            memory_after = self.process.memory_info().rss / 1024 / 1024
            cpu_after = self.process.cpu_percent()
            
            operation_result = OperationResult(
                operation_id=operation_id,
                start_time=start_time,
                end_time=end_time,
                duration_ms=(end_time - start_time) * 1000,
                success=False,
                error_type=type(e).__name__,
                error_message=str(e),
                memory_usage_mb=memory_after - memory_before,
                cpu_usage_percent=(cpu_before + cpu_after) / 2
            )
            
            self.results.append(operation_result)
            return operation_result
            
        finally:
            self.active_operations -= 1
    
    def _get_random_operation(self) -> Tuple[str, str, Dict[str, Any]]:
        """Get random test operation."""
        operations = [
            ("desktop-commander", "execute_command", {
                "command": "echo 'stress test'",
                "description": "Stress test operation"
            }),
            ("brave", "brave_web_search", {
                "query": "stress test",
                "count": 1
            }),
        ]
        
        # Filter by available servers
        available_operations = [
            op for op in operations
            if op[0] in self.registry.list_servers()
        ]
        
        if available_operations:
            return random.choice(available_operations)
        else:
            # Fallback operation
            return ("desktop-commander", "execute_command", {
                "command": "echo 'fallback'",
                "description": "Fallback operation"
            })
    
    async def _inject_chaos(self):
        """Inject chaos for failure testing."""
        chaos_types = [
            "delay",
            "memory_spike",
            "cpu_spike"
        ]
        
        chaos_type = random.choice(chaos_types)
        
        if chaos_type == "delay":
            # Random delay
            delay = random.uniform(0.1, 1.0)
            await asyncio.sleep(delay)
        elif chaos_type == "memory_spike":
            # Brief memory allocation
            temp_data = "x" * (1024 * 1024)  # 1MB
            await asyncio.sleep(0.1)
            del temp_data
        elif chaos_type == "cpu_spike":
            # Brief CPU intensive operation
            start = time.time()
            while time.time() - start < 0.1:
                _ = sum(range(1000))
    
    def _start_resource_monitoring(self):
        """Start resource monitoring thread."""
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_resources)
        self.monitor_thread.start()
    
    def _monitor_resources(self):
        """Monitor system resources during testing."""
        while self.monitoring_active:
            try:
                metrics = {
                    "timestamp": datetime.now().isoformat(),
                    "memory_mb": self.process.memory_info().rss / 1024 / 1024,
                    "cpu_percent": self.process.cpu_percent(),
                    "active_operations": self.active_operations,
                    "total_operations": len(self.results)
                }
                self.metrics_history.append(metrics)
                
            except Exception as e:
                logger.error(f"Resource monitoring error: {e}")
            
            time.sleep(1.0)
    
    def _stop_resource_monitoring(self):
        """Stop resource monitoring."""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5.0)
    
    def _calculate_stress_metrics(
        self,
        test_id: str,
        start_time: datetime,
        end_time: datetime,
        config: StressTestConfig
    ) -> StressTestMetrics:
        """Calculate comprehensive stress test metrics."""
        
        if not self.results:
            return StressTestMetrics(
                test_id=test_id,
                start_time=start_time.isoformat(),
                end_time=end_time.isoformat(),
                duration_seconds=0,
                total_operations=0,
                successful_operations=0,
                failed_operations=0,
                success_rate=0,
                failure_rate=0,
                operations_per_second=0,
                avg_response_time_ms=0,
                min_response_time_ms=0,
                max_response_time_ms=0,
                p50_response_time_ms=0,
                p95_response_time_ms=0,
                p99_response_time_ms=0,
                throughput_peak=0,
                memory_usage_peak_mb=0,
                memory_usage_avg_mb=0,
                cpu_usage_peak_percent=0,
                cpu_usage_avg_percent=0
            )
        
        duration = (end_time - start_time).total_seconds()
        successful_ops = [r for r in self.results if r.success]
        failed_ops = [r for r in self.results if not r.success]
        
        # Response time statistics
        response_times = [r.duration_ms for r in successful_ops]
        sorted_times = sorted(response_times) if response_times else [0]
        
        # Memory and CPU statistics
        memory_usage = [m["memory_mb"] for m in self.metrics_history]
        cpu_usage = [m["cpu_percent"] for m in self.metrics_history]
        
        # Error breakdown
        error_breakdown = {}
        for result in failed_ops:
            error_type = result.error_type or "Unknown"
            error_breakdown[error_type] = error_breakdown.get(error_type, 0) + 1
        
        # Calculate percentiles
        def percentile(data, p):
            if not data:
                return 0
            index = int(len(data) * p / 100)
            return data[min(index, len(data) - 1)]
        
        return StressTestMetrics(
            test_id=test_id,
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            duration_seconds=duration,
            total_operations=len(self.results),
            successful_operations=len(successful_ops),
            failed_operations=len(failed_ops),
            success_rate=len(successful_ops) / len(self.results),
            failure_rate=len(failed_ops) / len(self.results),
            operations_per_second=len(self.results) / duration if duration > 0 else 0,
            avg_response_time_ms=statistics.mean(response_times) if response_times else 0,
            min_response_time_ms=min(response_times) if response_times else 0,
            max_response_time_ms=max(response_times) if response_times else 0,
            p50_response_time_ms=percentile(sorted_times, 50),
            p95_response_time_ms=percentile(sorted_times, 95),
            p99_response_time_ms=percentile(sorted_times, 99),
            throughput_peak=max([m["total_operations"] for m in self.metrics_history[-10:]]) / 10 if self.metrics_history else 0,
            memory_usage_peak_mb=max(memory_usage) if memory_usage else 0,
            memory_usage_avg_mb=statistics.mean(memory_usage) if memory_usage else 0,
            cpu_usage_peak_percent=max(cpu_usage) if cpu_usage else 0,
            cpu_usage_avg_percent=statistics.mean(cpu_usage) if cpu_usage else 0,
            error_breakdown=error_breakdown,
            chaos_events_triggered=0  # Would track actual chaos events
        )
    
    async def _save_stress_results(self, metrics: StressTestMetrics, config: StressTestConfig):
        """Save stress test results."""
        try:
            results_dir = Path("stress_test_results")
            results_dir.mkdir(exist_ok=True)
            
            # Save metrics
            metrics_path = results_dir / f"stress_metrics_{metrics.test_id}.json"
            with open(metrics_path, 'w') as f:
                json.dump(asdict(metrics), f, indent=2, default=str)
            
            # Save detailed results
            results_path = results_dir / f"stress_results_{metrics.test_id}.json"
            with open(results_path, 'w') as f:
                json.dump({
                    "config": asdict(config),
                    "detailed_results": [asdict(r) for r in self.results],
                    "metrics_history": self.metrics_history
                }, f, indent=2, default=str)
            
            # Generate report
            report_path = results_dir / f"stress_report_{metrics.test_id}.md"
            with open(report_path, 'w') as f:
                f.write(self._generate_stress_report(metrics, config))
            
            logger.info(f"Stress test results saved:")
            logger.info(f"  Metrics: {metrics_path}")
            logger.info(f"  Results: {results_path}")
            logger.info(f"  Report: {report_path}")
            
        except Exception as e:
            logger.error(f"Failed to save stress test results: {e}")
    
    def _generate_stress_report(self, metrics: StressTestMetrics, config: StressTestConfig) -> str:
        """Generate stress test report."""
        return f"""# MCP Stress Test Report

## Test Configuration
- **Test Type**: {config.test_type.value}
- **Load Pattern**: {config.load_pattern.value}
- **Duration**: {config.duration_seconds} seconds
- **Max Concurrent Users**: {config.max_concurrent_users}
- **Target Operations/Second**: {config.operations_per_second}

## Test Results
- **Test ID**: {metrics.test_id}
- **Duration**: {metrics.duration_seconds:.1f} seconds
- **Total Operations**: {metrics.total_operations}
- **Success Rate**: {metrics.success_rate:.1%}
- **Failure Rate**: {metrics.failure_rate:.1%}

## Performance Metrics
- **Operations/Second**: {metrics.operations_per_second:.1f}
- **Average Response Time**: {metrics.avg_response_time_ms:.1f}ms
- **P95 Response Time**: {metrics.p95_response_time_ms:.1f}ms
- **P99 Response Time**: {metrics.p99_response_time_ms:.1f}ms

## Resource Utilization
- **Peak Memory Usage**: {metrics.memory_usage_peak_mb:.1f}MB
- **Average Memory Usage**: {metrics.memory_usage_avg_mb:.1f}MB
- **Peak CPU Usage**: {metrics.cpu_usage_peak_percent:.1f}%
- **Average CPU Usage**: {metrics.cpu_usage_avg_percent:.1f}%

## Error Analysis
"""
        
        if metrics.error_breakdown:
            for error_type, count in metrics.error_breakdown.items():
                percentage = (count / metrics.total_operations) * 100
                return f"- **{error_type}**: {count} ({percentage:.1f}%)\n"
        else:
            return "- No errors detected\n"
    
    async def cleanup(self):
        """Cleanup stress testing resources."""
        self.stop_event.set()
        self._stop_resource_monitoring()
        
        if self.manager:
            await self.manager.cleanup()
        
        logger.info("Stress testing cleanup completed")


# Predefined stress test configurations
STRESS_TEST_CONFIGS = {
    "light_load": StressTestConfig(
        test_type=StressTestType.LOAD,
        load_pattern=LoadPattern.CONSTANT,
        duration_seconds=60,
        max_concurrent_users=5,
        operations_per_second=2.0
    ),
    "moderate_load": StressTestConfig(
        test_type=StressTestType.LOAD,
        load_pattern=LoadPattern.RAMP_UP,
        duration_seconds=300,
        max_concurrent_users=20,
        operations_per_second=10.0,
        ramp_up_time_seconds=60
    ),
    "heavy_load": StressTestConfig(
        test_type=StressTestType.LOAD,
        load_pattern=LoadPattern.CONSTANT,
        duration_seconds=600,
        max_concurrent_users=50,
        operations_per_second=25.0
    ),
    "spike_test": StressTestConfig(
        test_type=StressTestType.SPIKE,
        load_pattern=LoadPattern.SPIKE,
        duration_seconds=300,
        max_concurrent_users=100,
        operations_per_second=10.0,
        spike_duration_seconds=30
    ),
    "endurance_test": StressTestConfig(
        test_type=StressTestType.ENDURANCE,
        load_pattern=LoadPattern.CONSTANT,
        duration_seconds=3600,  # 1 hour
        max_concurrent_users=10,
        operations_per_second=5.0
    ),
    "capacity_test": StressTestConfig(
        test_type=StressTestType.CAPACITY,
        load_pattern=LoadPattern.GRADUAL,
        duration_seconds=600,
        max_concurrent_users=100,
        operations_per_second=50.0
    ),
    "memory_stress": StressTestConfig(
        test_type=StressTestType.MEMORY,
        load_pattern=LoadPattern.CONSTANT,
        duration_seconds=300,
        max_concurrent_users=20,
        operations_per_second=10.0,
        memory_target_mb=500
    ),
    "chaos_test": StressTestConfig(
        test_type=StressTestType.LOAD,
        load_pattern=LoadPattern.CONSTANT,
        duration_seconds=300,
        max_concurrent_users=15,
        operations_per_second=8.0,
        enable_chaos=True,
        chaos_probability=0.2
    )
}


async def main():
    """Run MCP stress testing suite."""
    print("🔥 MCP Stress Testing and Load Testing Suite")
    print("=" * 60)
    print("Agent 5: Advanced stress testing with failure injection and chaos engineering")
    print()
    
    tester = MCPStressTester()
    
    try:
        await tester.initialize()
        
        # Run predefined stress tests
        test_configs = [
            ("Light Load Test", STRESS_TEST_CONFIGS["light_load"]),
            ("Spike Test", STRESS_TEST_CONFIGS["spike_test"]),
            ("Memory Stress Test", STRESS_TEST_CONFIGS["memory_stress"]),
        ]
        
        for test_name, config in test_configs:
            print(f"\n🚀 Running {test_name}...")
            metrics = await tester.run_stress_test(config)
            
            print(f"✅ {test_name} completed:")
            print(f"   Total Operations: {metrics.total_operations}")
            print(f"   Success Rate: {metrics.success_rate:.1%}")
            print(f"   Avg Response Time: {metrics.avg_response_time_ms:.1f}ms")
            print(f"   Peak Memory: {metrics.memory_usage_peak_mb:.1f}MB")
            
            # Reset results for next test
            tester.results = []
            tester.metrics_history = []
        
        print("\n" + "=" * 60)
        print("🎉 Stress testing suite completed!")
        print("📊 Check stress_test_results/ directory for detailed reports")
        
    except Exception as e:
        print(f"\n❌ Stress testing failed: {e}")
        import traceback
        traceback.print_exc()
        
    finally:
        await tester.cleanup()


if __name__ == "__main__":
    asyncio.run(main())