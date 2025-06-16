"""
Chaos engineering and recovery testing scenario.

Tests system resilience, failure detection, and recovery mechanisms under chaotic conditions.
"""

import asyncio
import random
import time
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
import numpy as np
import logging
from enum import Enum
import psutil

from mcp_learning_system.core import LearningMCPCluster
from ..monitoring import MetricsCollector

logger = logging.getLogger(__name__)


class ChaosType(Enum):
    """Types of chaos that can be injected."""
    INSTANCE_KILL = "instance_kill"
    NETWORK_PARTITION = "network_partition"
    MEMORY_PRESSURE = "memory_pressure"
    CPU_SPIKE = "cpu_spike"
    DISK_FULL = "disk_full"
    RANDOM_ERRORS = "random_errors"
    LATENCY_INJECTION = "latency_injection"
    DATA_CORRUPTION = "data_corruption"


@dataclass
class ChaosEvent:
    """Represents a single chaos event."""
    chaos_type: ChaosType
    target: str
    start_time: float
    duration: float
    parameters: Dict[str, Any] = field(default_factory=dict)
    recovery_time: Optional[float] = None
    impact_metrics: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'chaos_type': self.chaos_type.value,
            'target': self.target,
            'start_time': self.start_time,
            'duration': self.duration,
            'recovery_time': self.recovery_time,
            'parameters': self.parameters,
            'impact_metrics': self.impact_metrics
        }


@dataclass
class ChaosScenarioResult:
    """Results from a chaos testing scenario."""
    scenario_name: str
    duration: float
    chaos_events: List[ChaosEvent]
    system_availability: float
    mean_recovery_time: float
    data_integrity_maintained: bool
    performance_degradation: float
    chaos_metrics: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    
    @property
    def total_chaos_events(self) -> int:
        """Get total number of chaos events."""
        return len(self.chaos_events)
    
    @property
    def successful_recoveries(self) -> int:
        """Count successful recoveries."""
        return sum(1 for event in self.chaos_events if event.recovery_time is not None)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'scenario_name': self.scenario_name,
            'duration': self.duration,
            'total_chaos_events': self.total_chaos_events,
            'successful_recoveries': self.successful_recoveries,
            'recovery_success_rate': self.successful_recoveries / self.total_chaos_events if self.total_chaos_events > 0 else 0,
            'system_availability': self.system_availability,
            'mean_recovery_time': self.mean_recovery_time,
            'data_integrity_maintained': self.data_integrity_maintained,
            'performance_degradation': self.performance_degradation,
            'chaos_events': [event.to_dict() for event in self.chaos_events],
            'chaos_metrics': self.chaos_metrics,
            'errors': self.errors
        }


class ChaosRecoveryScenario:
    """Chaos engineering stress testing scenarios."""
    
    def __init__(self, mcp_cluster: Optional[LearningMCPCluster] = None):
        """Initialize chaos scenario."""
        self.mcp_cluster = mcp_cluster or LearningMCPCluster()
        self.metrics_collector = MetricsCollector()
        
        # Instance configurations
        self.instance_names = ['development', 'devops', 'quality', 'bash_god']
        
        # Recovery targets
        self.targets = {
            'max_recovery_time_s': 5.0,
            'min_availability': 0.99,
            'max_performance_degradation': 0.2,  # 20%
            'data_integrity_required': True
        }
        
        # Chaos injection strategies
        self.chaos_strategies = {
            ChaosType.INSTANCE_KILL: self._chaos_instance_kill,
            ChaosType.NETWORK_PARTITION: self._chaos_network_partition,
            ChaosType.MEMORY_PRESSURE: self._chaos_memory_pressure,
            ChaosType.CPU_SPIKE: self._chaos_cpu_spike,
            ChaosType.DISK_FULL: self._chaos_disk_full,
            ChaosType.RANDOM_ERRORS: self._chaos_random_errors,
            ChaosType.LATENCY_INJECTION: self._chaos_latency_injection,
            ChaosType.DATA_CORRUPTION: self._chaos_data_corruption
        }
        
    async def run_scenario(self, duration: int = 600) -> Dict[str, ChaosScenarioResult]:
        """Run complete chaos engineering scenario."""
        logger.info(f"Starting chaos engineering scenario for {duration} seconds")
        
        results = {}
        
        try:
            # Initialize cluster
            await self.mcp_cluster.initialize()
            
            # Baseline data for comparison
            await self._establish_baseline()
            
            # Run different chaos scenarios
            results['random_chaos'] = await self.test_random_chaos_injection(duration // 4)
            results['cascading_failures'] = await self.test_cascading_failures(duration // 4)
            results['stress_with_chaos'] = await self.test_stress_with_chaos(duration // 4)
            results['recovery_validation'] = await self.test_recovery_mechanisms(duration // 4)
            
            # Generate summary
            results['summary'] = self._generate_chaos_summary(results)
            
        finally:
            # Ensure clean state
            await self._cleanup_chaos_effects()
            await self.mcp_cluster.shutdown()
            
        return results
    
    async def test_random_chaos_injection(self, duration: int) -> ChaosScenarioResult:
        """Test system resilience with random chaos injection."""
        logger.info("Testing random chaos injection")
        
        result = ChaosScenarioResult(
            scenario_name="random_chaos",
            duration=0,
            chaos_events=[],
            system_availability=0,
            mean_recovery_time=0,
            data_integrity_maintained=True,
            performance_degradation=0
        )
        
        start_time = time.time()
        availability_samples = []
        performance_samples = []
        baseline_performance = await self._measure_baseline_performance()
        
        # Random chaos injection parameters
        chaos_probability = 0.1  # 10% chance per interval
        check_interval = 5  # seconds
        
        while time.time() - start_time < duration:
            interval_start = time.time()
            
            # Decide whether to inject chaos
            if random.random() < chaos_probability:
                chaos_type = random.choice(list(ChaosType))
                target = random.choice(self.instance_names)
                
                logger.info(f"Injecting chaos: {chaos_type.value} on {target}")
                
                # Create and execute chaos event
                chaos_event = ChaosEvent(
                    chaos_type=chaos_type,
                    target=target,
                    start_time=time.time(),
                    duration=random.uniform(5, 30),  # 5-30 seconds
                    parameters=self._generate_chaos_parameters(chaos_type)
                )
                
                # Execute chaos
                await self._execute_chaos_event(chaos_event)
                
                # Monitor recovery
                recovery_start = time.time()
                recovered = await self._wait_for_recovery(chaos_event, timeout=60.0)
                
                if recovered:
                    chaos_event.recovery_time = time.time() - recovery_start
                    logger.info(f"Recovery completed in {chaos_event.recovery_time:.2f}s")
                else:
                    result.errors.append(f"Recovery failed for {chaos_type.value} on {target}")
                
                # Measure impact
                chaos_event.impact_metrics = await self._measure_chaos_impact(
                    chaos_event, baseline_performance
                )
                
                result.chaos_events.append(chaos_event)
            
            # Sample system metrics
            availability = await self._measure_system_availability()
            performance = await self._measure_current_performance()
            
            availability_samples.append(availability)
            performance_samples.append(performance)
            
            # Wait for next check
            elapsed = time.time() - interval_start
            sleep_time = max(0, check_interval - elapsed)
            await asyncio.sleep(sleep_time)
        
        result.duration = time.time() - start_time
        
        # Calculate metrics
        result.system_availability = np.mean(availability_samples) if availability_samples else 0
        
        if performance_samples and baseline_performance > 0:
            current_avg_performance = np.mean(performance_samples)
            result.performance_degradation = (
                (baseline_performance - current_avg_performance) / baseline_performance
            )
        
        if result.chaos_events:
            recovery_times = [e.recovery_time for e in result.chaos_events if e.recovery_time is not None]
            result.mean_recovery_time = np.mean(recovery_times) if recovery_times else float('inf')
        
        # Check data integrity
        result.data_integrity_maintained = await self._verify_data_integrity()
        
        return result
    
    async def test_cascading_failures(self, duration: int) -> ChaosScenarioResult:
        """Test cascading failure scenarios."""
        logger.info("Testing cascading failures")
        
        result = ChaosScenarioResult(
            scenario_name="cascading_failures",
            duration=0,
            chaos_events=[],
            system_availability=0,
            mean_recovery_time=0,
            data_integrity_maintained=True,
            performance_degradation=0
        )
        
        start_time = time.time()
        baseline_performance = await self._measure_baseline_performance()
        
        # Cascading failure scenarios
        cascade_scenarios = [
            {
                'name': 'instance_cascade',
                'initial': ChaosType.INSTANCE_KILL,
                'follow_up': [ChaosType.MEMORY_PRESSURE, ChaosType.CPU_SPIKE]
            },
            {
                'name': 'network_cascade',
                'initial': ChaosType.NETWORK_PARTITION,
                'follow_up': [ChaosType.LATENCY_INJECTION, ChaosType.RANDOM_ERRORS]
            },
            {
                'name': 'resource_cascade',
                'initial': ChaosType.MEMORY_PRESSURE,
                'follow_up': [ChaosType.DISK_FULL, ChaosType.CPU_SPIKE]
            }
        ]
        
        for scenario in cascade_scenarios:
            if time.time() - start_time >= duration:
                break
                
            logger.info(f"Testing cascade scenario: {scenario['name']}")
            
            # Initial chaos event
            initial_target = random.choice(self.instance_names)
            initial_event = ChaosEvent(
                chaos_type=scenario['initial'],
                target=initial_target,
                start_time=time.time(),
                duration=20,  # 20 seconds
                parameters=self._generate_chaos_parameters(scenario['initial'])
            )
            
            await self._execute_chaos_event(initial_event)
            result.chaos_events.append(initial_event)
            
            # Wait for potential cascade
            await asyncio.sleep(3)
            
            # Check if system is showing stress
            system_stress = await self._measure_system_stress()
            
            if system_stress > 0.7:  # High stress
                # Inject follow-up chaos
                for follow_chaos in scenario['follow_up']:
                    follow_target = random.choice(
                        [i for i in self.instance_names if i != initial_target]
                    )
                    
                    follow_event = ChaosEvent(
                        chaos_type=follow_chaos,
                        target=follow_target,
                        start_time=time.time(),
                        duration=15,
                        parameters=self._generate_chaos_parameters(follow_chaos)
                    )
                    
                    await self._execute_chaos_event(follow_event)
                    result.chaos_events.append(follow_event)
                    
                    # Small delay between cascading events
                    await asyncio.sleep(2)
            
            # Wait for recovery
            recovery_start = time.time()
            
            # Wait for all events in this cascade to recover
            for event in [initial_event] + ([follow_event] if 'follow_event' in locals() else []):
                recovered = await self._wait_for_recovery(event, timeout=90.0)
                
                if recovered:
                    event.recovery_time = time.time() - recovery_start
                else:
                    result.errors.append(
                        f"Cascade recovery failed: {event.chaos_type.value} on {event.target}"
                    )
            
            # Stabilization time
            await asyncio.sleep(10)
        
        result.duration = time.time() - start_time
        
        # Calculate cascade-specific metrics
        cascade_groups = []
        current_group = []
        
        for event in result.chaos_events:
            if not current_group or (event.start_time - current_group[-1].start_time) < 30:
                current_group.append(event)
            else:
                if current_group:
                    cascade_groups.append(current_group)
                current_group = [event]
        
        if current_group:
            cascade_groups.append(current_group)
        
        result.chaos_metrics['cascade_groups'] = len(cascade_groups)
        result.chaos_metrics['avg_cascade_size'] = np.mean([len(group) for group in cascade_groups])
        result.chaos_metrics['max_cascade_size'] = max([len(group) for group in cascade_groups])
        
        # Calculate metrics
        current_performance = await self._measure_current_performance()
        if baseline_performance > 0:
            result.performance_degradation = (
                (baseline_performance - current_performance) / baseline_performance
            )
        
        if result.chaos_events:
            recovery_times = [e.recovery_time for e in result.chaos_events if e.recovery_time is not None]
            result.mean_recovery_time = np.mean(recovery_times) if recovery_times else float('inf')
        
        result.system_availability = await self._measure_system_availability()
        result.data_integrity_maintained = await self._verify_data_integrity()
        
        return result
    
    async def test_stress_with_chaos(self, duration: int) -> ChaosScenarioResult:
        """Test chaos injection during high system load."""
        logger.info("Testing chaos injection under stress")
        
        result = ChaosScenarioResult(
            scenario_name="stress_with_chaos",
            duration=0,
            chaos_events=[],
            system_availability=0,
            mean_recovery_time=0,
            data_integrity_maintained=True,
            performance_degradation=0
        )
        
        start_time = time.time()
        baseline_performance = await self._measure_baseline_performance()
        
        # Start continuous load
        load_task = asyncio.create_task(self._generate_continuous_load())
        
        try:
            # Wait for load to stabilize
            await asyncio.sleep(10)
            
            # Inject chaos while under load
            chaos_interval = 30  # seconds
            chaos_count = 0
            
            while time.time() - start_time < duration:
                # Select chaos type - favor more disruptive types under load
                weighted_chaos_types = [
                    (ChaosType.INSTANCE_KILL, 0.3),
                    (ChaosType.MEMORY_PRESSURE, 0.25),
                    (ChaosType.CPU_SPIKE, 0.2),
                    (ChaosType.NETWORK_PARTITION, 0.15),
                    (ChaosType.LATENCY_INJECTION, 0.1)
                ]
                
                chaos_type = np.random.choice(
                    [ct for ct, _ in weighted_chaos_types],
                    p=[weight for _, weight in weighted_chaos_types]
                )
                
                target = random.choice(self.instance_names)
                
                logger.info(f"Injecting chaos under load: {chaos_type.value} on {target}")
                
                chaos_event = ChaosEvent(
                    chaos_type=chaos_type,
                    target=target,
                    start_time=time.time(),
                    duration=random.uniform(10, 45),
                    parameters=self._generate_chaos_parameters(chaos_type)
                )
                
                # Execute chaos
                await self._execute_chaos_event(chaos_event)
                
                # Monitor system under stress + chaos
                stress_metrics = await self._monitor_stress_with_chaos(chaos_event)
                chaos_event.impact_metrics.update(stress_metrics)
                
                # Wait for recovery
                recovery_start = time.time()
                recovered = await self._wait_for_recovery(chaos_event, timeout=120.0)
                
                if recovered:
                    chaos_event.recovery_time = time.time() - recovery_start
                else:
                    result.errors.append(
                        f"Recovery under stress failed: {chaos_type.value} on {target}"
                    )
                
                result.chaos_events.append(chaos_event)
                chaos_count += 1
                
                # Wait before next chaos injection
                await asyncio.sleep(chaos_interval)
                
        finally:
            # Stop load generation
            load_task.cancel()
            try:
                await load_task
            except asyncio.CancelledError:
                pass
        
        result.duration = time.time() - start_time
        
        # Calculate stress-specific metrics
        under_load_recoveries = [
            e.recovery_time for e in result.chaos_events 
            if e.recovery_time is not None
        ]
        
        result.mean_recovery_time = np.mean(under_load_recoveries) if under_load_recoveries else float('inf')
        
        # Performance degradation under stress + chaos
        final_performance = await self._measure_current_performance()
        if baseline_performance > 0:
            result.performance_degradation = (
                (baseline_performance - final_performance) / baseline_performance
            )
        
        result.system_availability = await self._measure_system_availability()
        result.data_integrity_maintained = await self._verify_data_integrity()
        
        # Stress-specific metrics
        result.chaos_metrics['chaos_under_load_count'] = len(result.chaos_events)
        result.chaos_metrics['load_impact_recovery_ratio'] = (
            len(under_load_recoveries) / len(result.chaos_events) if result.chaos_events else 0
        )
        
        return result
    
    async def test_recovery_mechanisms(self, duration: int) -> ChaosScenarioResult:
        """Test specific recovery mechanisms."""
        logger.info("Testing recovery mechanisms")
        
        result = ChaosScenarioResult(
            scenario_name="recovery_validation",
            duration=0,
            chaos_events=[],
            system_availability=0,
            mean_recovery_time=0,
            data_integrity_maintained=True,
            performance_degradation=0
        )
        
        start_time = time.time()
        
        # Test specific recovery scenarios
        recovery_tests = [
            {
                'name': 'single_instance_recovery',
                'chaos': ChaosType.INSTANCE_KILL,
                'expected_recovery_time': 5.0
            },
            {
                'name': 'network_healing',
                'chaos': ChaosType.NETWORK_PARTITION,
                'expected_recovery_time': 10.0
            },
            {
                'name': 'resource_recovery',
                'chaos': ChaosType.MEMORY_PRESSURE,
                'expected_recovery_time': 15.0
            },
            {
                'name': 'data_corruption_recovery',
                'chaos': ChaosType.DATA_CORRUPTION,
                'expected_recovery_time': 20.0
            }
        ]
        
        recovery_results = {}
        
        for test in recovery_tests:
            if time.time() - start_time >= duration:
                break
                
            logger.info(f"Testing recovery: {test['name']}")
            
            # Prepare test data
            test_data = await self._prepare_recovery_test_data()
            
            # Create and execute chaos event
            target = random.choice(self.instance_names)
            chaos_event = ChaosEvent(
                chaos_type=test['chaos'],
                target=target,
                start_time=time.time(),
                duration=10,  # Fixed duration for recovery testing
                parameters=self._generate_chaos_parameters(test['chaos'])
            )
            
            # Execute chaos
            await self._execute_chaos_event(chaos_event)
            
            # Detailed recovery monitoring
            recovery_start = time.time()
            recovery_phases = await self._monitor_detailed_recovery(chaos_event)
            
            # Wait for complete recovery
            recovered = await self._wait_for_recovery(chaos_event, timeout=60.0)
            
            if recovered:
                chaos_event.recovery_time = time.time() - recovery_start
                
                # Verify recovery completeness
                recovery_completeness = await self._verify_recovery_completeness(
                    chaos_event, test_data
                )
                
                chaos_event.impact_metrics.update({
                    'recovery_phases': recovery_phases,
                    'recovery_completeness': recovery_completeness,
                    'meets_sla': chaos_event.recovery_time <= test['expected_recovery_time']
                })
                
            else:
                result.errors.append(f"Recovery test failed: {test['name']}")
            
            result.chaos_events.append(chaos_event)
            
            recovery_results[test['name']] = {
                'success': recovered,
                'recovery_time': chaos_event.recovery_time,
                'expected_time': test['expected_recovery_time'],
                'meets_sla': chaos_event.recovery_time <= test['expected_recovery_time'] if recovered else False
            }
            
            # Stabilization between tests
            await asyncio.sleep(15)
        
        result.duration = time.time() - start_time
        result.chaos_metrics['recovery_tests'] = recovery_results
        
        # Calculate metrics
        recovery_times = [e.recovery_time for e in result.chaos_events if e.recovery_time is not None]
        result.mean_recovery_time = np.mean(recovery_times) if recovery_times else float('inf')
        
        # Check SLA compliance
        sla_compliant = sum(1 for e in result.chaos_events 
                           if e.impact_metrics.get('meets_sla', False))
        result.chaos_metrics['sla_compliance_rate'] = (
            sla_compliant / len(result.chaos_events) if result.chaos_events else 0
        )
        
        result.system_availability = await self._measure_system_availability()
        result.data_integrity_maintained = await self._verify_data_integrity()
        
        return result
    
    # Chaos injection implementations
    async def _chaos_instance_kill(self, event: ChaosEvent):
        """Kill an instance."""
        await self.mcp_cluster.kill_instance(event.target)
    
    async def _chaos_network_partition(self, event: ChaosEvent):
        """Create network partition."""
        other_instances = [i for i in self.instance_names if i != event.target]
        await self.mcp_cluster.partition_instance(event.target, other_instances)
    
    async def _chaos_memory_pressure(self, event: ChaosEvent):
        """Create memory pressure."""
        pressure_mb = event.parameters.get('pressure_mb', 500)
        await self.mcp_cluster.create_memory_pressure(event.target, pressure_mb)
    
    async def _chaos_cpu_spike(self, event: ChaosEvent):
        """Create CPU spike."""
        cpu_percent = event.parameters.get('cpu_percent', 90)
        await self.mcp_cluster.create_cpu_spike(event.target, cpu_percent, event.duration)
    
    async def _chaos_disk_full(self, event: ChaosEvent):
        """Simulate disk full."""
        fill_percent = event.parameters.get('fill_percent', 95)
        await self.mcp_cluster.fill_disk(event.target, fill_percent)
    
    async def _chaos_random_errors(self, event: ChaosEvent):
        """Inject random errors."""
        error_rate = event.parameters.get('error_rate', 0.1)
        await self.mcp_cluster.inject_random_errors(event.target, error_rate, event.duration)
    
    async def _chaos_latency_injection(self, event: ChaosEvent):
        """Inject network latency."""
        latency_ms = event.parameters.get('latency_ms', 100)
        await self.mcp_cluster.inject_latency(event.target, latency_ms, event.duration)
    
    async def _chaos_data_corruption(self, event: ChaosEvent):
        """Corrupt data."""
        corruption_rate = event.parameters.get('corruption_rate', 0.01)
        await self.mcp_cluster.corrupt_data(event.target, corruption_rate)
    
    async def _execute_chaos_event(self, event: ChaosEvent):
        """Execute a chaos event."""
        chaos_func = self.chaos_strategies.get(event.chaos_type)
        if chaos_func:
            try:
                await chaos_func(event)
                logger.info(f"Chaos injected: {event.chaos_type.value} on {event.target}")
            except Exception as e:
                logger.error(f"Chaos injection failed: {e}")
                raise
        else:
            raise ValueError(f"Unknown chaos type: {event.chaos_type}")
    
    def _generate_chaos_parameters(self, chaos_type: ChaosType) -> Dict[str, Any]:
        """Generate parameters for chaos injection."""
        parameters = {}
        
        if chaos_type == ChaosType.MEMORY_PRESSURE:
            parameters['pressure_mb'] = random.randint(200, 1000)
        elif chaos_type == ChaosType.CPU_SPIKE:
            parameters['cpu_percent'] = random.randint(80, 95)
        elif chaos_type == ChaosType.DISK_FULL:
            parameters['fill_percent'] = random.randint(85, 98)
        elif chaos_type == ChaosType.RANDOM_ERRORS:
            parameters['error_rate'] = random.uniform(0.05, 0.2)
        elif chaos_type == ChaosType.LATENCY_INJECTION:
            parameters['latency_ms'] = random.randint(50, 500)
        elif chaos_type == ChaosType.DATA_CORRUPTION:
            parameters['corruption_rate'] = random.uniform(0.001, 0.01)
        
        return parameters
    
    async def _wait_for_recovery(self, event: ChaosEvent, timeout: float) -> bool:
        """Wait for recovery from chaos event."""
        start = time.time()
        
        while time.time() - start < timeout:
            # Check if system has recovered from this specific chaos
            if event.chaos_type == ChaosType.INSTANCE_KILL:
                recovered = await self.mcp_cluster.is_instance_alive(event.target)
            elif event.chaos_type == ChaosType.NETWORK_PARTITION:
                recovered = await self.mcp_cluster.is_network_healed(event.target)
            elif event.chaos_type in [ChaosType.MEMORY_PRESSURE, ChaosType.CPU_SPIKE]:
                recovered = await self.mcp_cluster.is_resource_pressure_relieved(event.target)
            else:
                # General health check
                recovered = await self.mcp_cluster.is_instance_healthy(event.target)
            
            if recovered:
                return True
            
            await asyncio.sleep(1)
        
        return False
    
    async def _measure_chaos_impact(
        self, 
        event: ChaosEvent, 
        baseline_performance: float
    ) -> Dict[str, Any]:
        """Measure the impact of a chaos event."""
        impact = {}
        
        # Performance impact
        current_performance = await self._measure_current_performance()
        if baseline_performance > 0:
            impact['performance_impact'] = (
                (baseline_performance - current_performance) / baseline_performance
            )
        
        # Availability impact
        impact['availability_impact'] = await self._measure_availability_impact(event.target)
        
        # Error rate impact
        impact['error_rate_impact'] = await self._measure_error_rate_impact(event.target)
        
        return impact
    
    async def _establish_baseline(self):
        """Establish baseline metrics before chaos testing."""
        # Store test data for integrity verification
        self.baseline_test_data = []
        for i in range(100):
            data = {
                'id': f'baseline_data_{i}',
                'content': f'test_content_{i}',
                'timestamp': time.time()
            }
            await self.mcp_cluster.store_data(data)
            self.baseline_test_data.append(data)
        
        # Wait for replication
        await asyncio.sleep(5)
    
    async def _measure_baseline_performance(self) -> float:
        """Measure baseline system performance."""
        # Simple performance metric: operations per second
        start = time.time()
        operations = 0
        
        # Test operations for 10 seconds
        while time.time() - start < 10:
            try:
                # Simple pattern matching operation
                await self.mcp_cluster.match_pattern({'test': 'pattern'})
                operations += 1
            except Exception:
                pass
            
            await asyncio.sleep(0.01)
        
        return operations / 10  # ops per second
    
    async def _measure_current_performance(self) -> float:
        """Measure current system performance."""
        return await self._measure_baseline_performance()
    
    async def _measure_system_availability(self) -> float:
        """Measure current system availability."""
        available_instances = 0
        
        for instance in self.instance_names:
            try:
                healthy = await self.mcp_cluster.is_instance_healthy(instance)
                if healthy:
                    available_instances += 1
            except Exception:
                pass
        
        return available_instances / len(self.instance_names)
    
    async def _measure_system_stress(self) -> float:
        """Measure current system stress level."""
        stress_indicators = []
        
        for instance in self.instance_names:
            try:
                # CPU usage
                cpu_usage = await self.mcp_cluster.get_cpu_usage(instance)
                stress_indicators.append(cpu_usage / 100)
                
                # Memory usage
                memory_usage = await self.mcp_cluster.get_memory_usage_percent(instance)
                stress_indicators.append(memory_usage / 100)
                
                # Error rate
                error_rate = await self.mcp_cluster.get_error_rate(instance)
                stress_indicators.append(min(error_rate * 10, 1.0))  # Scale error rate
                
            except Exception:
                stress_indicators.append(1.0)  # Max stress if can't measure
        
        return np.mean(stress_indicators) if stress_indicators else 0
    
    async def _verify_data_integrity(self) -> bool:
        """Verify data integrity after chaos events."""
        try:
            for test_data in self.baseline_test_data:
                retrieved = await self.mcp_cluster.retrieve_data(test_data['id'])
                if retrieved != test_data:
                    logger.error(f"Data integrity violation: {test_data['id']}")
                    return False
            return True
        except Exception as e:
            logger.error(f"Data integrity check failed: {e}")
            return False
    
    async def _generate_continuous_load(self):
        """Generate continuous load on the system."""
        load_operations = [
            'pattern_matching',
            'learning_updates',
            'knowledge_sharing',
            'data_retrieval'
        ]
        
        try:
            while True:
                # Random operation
                operation = random.choice(load_operations)
                
                try:
                    if operation == 'pattern_matching':
                        await self.mcp_cluster.match_pattern({'load': 'test'})
                    elif operation == 'learning_updates':
                        await self.mcp_cluster.update_learning({'load': 'test'})
                    elif operation == 'knowledge_sharing':
                        source = random.choice(self.instance_names)
                        target = random.choice([i for i in self.instance_names if i != source])
                        await self.mcp_cluster.share_knowledge(source, target, {'load': 'test'})
                    elif operation == 'data_retrieval':
                        await self.mcp_cluster.retrieve_data('test_id')
                except Exception:
                    pass  # Expected during chaos
                
                await asyncio.sleep(0.01)  # High frequency
                
        except asyncio.CancelledError:
            pass
    
    async def _monitor_stress_with_chaos(self, event: ChaosEvent) -> Dict[str, Any]:
        """Monitor system behavior during stress + chaos."""
        metrics = {
            'stress_level_during_chaos': await self._measure_system_stress(),
            'availability_during_chaos': await self._measure_system_availability(),
            'error_spike_detected': False
        }
        
        # Check for error spikes
        pre_chaos_error_rate = await self.mcp_cluster.get_overall_error_rate()
        await asyncio.sleep(5)  # Let chaos take effect
        post_chaos_error_rate = await self.mcp_cluster.get_overall_error_rate()
        
        if post_chaos_error_rate > pre_chaos_error_rate * 2:
            metrics['error_spike_detected'] = True
        
        return metrics
    
    async def _prepare_recovery_test_data(self) -> Dict[str, Any]:
        """Prepare data for recovery testing."""
        test_data = {
            'id': f'recovery_test_{time.time()}',
            'patterns': [{'id': f'pattern_{i}', 'data': f'test_{i}'} for i in range(10)],
            'timestamp': time.time()
        }
        
        await self.mcp_cluster.store_data(test_data)
        return test_data
    
    async def _monitor_detailed_recovery(self, event: ChaosEvent) -> Dict[str, Any]:
        """Monitor detailed recovery phases."""
        phases = {
            'detection_time': None,
            'isolation_time': None,
            'restoration_time': None,
            'verification_time': None
        }
        
        start = time.time()
        
        # Detection phase
        detected = await self._wait_for_failure_detection(event.target)
        if detected:
            phases['detection_time'] = time.time() - start
        
        # Isolation phase (if applicable)
        if event.chaos_type in [ChaosType.INSTANCE_KILL, ChaosType.NETWORK_PARTITION]:
            isolated = await self._wait_for_isolation(event.target)
            if isolated:
                phases['isolation_time'] = time.time() - start
        
        # Restoration phase
        restored = await self._wait_for_restoration(event.target)
        if restored:
            phases['restoration_time'] = time.time() - start
        
        # Verification phase
        verified = await self._wait_for_verification(event.target)
        if verified:
            phases['verification_time'] = time.time() - start
        
        return phases
    
    async def _verify_recovery_completeness(
        self, 
        event: ChaosEvent, 
        test_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Verify completeness of recovery."""
        completeness = {
            'instance_operational': await self.mcp_cluster.is_instance_healthy(event.target),
            'data_accessible': True,
            'functionality_restored': True,
            'performance_restored': True
        }
        
        # Test data accessibility
        try:
            retrieved = await self.mcp_cluster.retrieve_data(test_data['id'])
            completeness['data_accessible'] = (retrieved == test_data)
        except Exception:
            completeness['data_accessible'] = False
        
        # Test functionality
        try:
            await self.mcp_cluster.match_pattern({'recovery': 'test'})
        except Exception:
            completeness['functionality_restored'] = False
        
        # Test performance (simplified)
        try:
            start = time.time()
            await self.mcp_cluster.match_pattern({'performance': 'test'})
            latency = time.time() - start
            completeness['performance_restored'] = latency < 1.0  # 1 second threshold
        except Exception:
            completeness['performance_restored'] = False
        
        return completeness
    
    async def _wait_for_failure_detection(self, target: str, timeout: float = 30.0) -> bool:
        """Wait for failure detection."""
        # Simplified: check if monitoring detects the failure
        start = time.time()
        while time.time() - start < timeout:
            try:
                alerts = await self.mcp_cluster.get_active_alerts()
                if any(target in alert.get('instance', '') for alert in alerts):
                    return True
            except Exception:
                pass
            await asyncio.sleep(1)
        return False
    
    async def _wait_for_isolation(self, target: str, timeout: float = 20.0) -> bool:
        """Wait for instance isolation."""
        start = time.time()
        while time.time() - start < timeout:
            try:
                isolated = await self.mcp_cluster.is_instance_isolated(target)
                if isolated:
                    return True
            except Exception:
                pass
            await asyncio.sleep(1)
        return False
    
    async def _wait_for_restoration(self, target: str, timeout: float = 60.0) -> bool:
        """Wait for instance restoration."""
        start = time.time()
        while time.time() - start < timeout:
            try:
                restored = await self.mcp_cluster.is_instance_alive(target)
                if restored:
                    return True
            except Exception:
                pass
            await asyncio.sleep(1)
        return False
    
    async def _wait_for_verification(self, target: str, timeout: float = 30.0) -> bool:
        """Wait for recovery verification."""
        start = time.time()
        while time.time() - start < timeout:
            try:
                healthy = await self.mcp_cluster.is_instance_healthy(target)
                if healthy:
                    return True
            except Exception:
                pass
            await asyncio.sleep(1)
        return False
    
    async def _measure_availability_impact(self, target: str) -> float:
        """Measure availability impact of chaos on target."""
        try:
            healthy = await self.mcp_cluster.is_instance_healthy(target)
            return 0.0 if healthy else 1.0
        except Exception:
            return 1.0
    
    async def _measure_error_rate_impact(self, target: str) -> float:
        """Measure error rate impact of chaos on target."""
        try:
            error_rate = await self.mcp_cluster.get_error_rate(target)
            return min(error_rate, 1.0)
        except Exception:
            return 1.0
    
    async def _cleanup_chaos_effects(self):
        """Clean up any remaining chaos effects."""
        logger.info("Cleaning up chaos effects")
        
        for instance in self.instance_names:
            try:
                # Restore instance if killed
                await self.mcp_cluster.restore_instance(instance)
                
                # Heal network partitions
                await self.mcp_cluster.heal_network_partition_for_instance(instance)
                
                # Release resource pressure
                await self.mcp_cluster.release_resource_pressure(instance)
                
                # Stop error injection
                await self.mcp_cluster.stop_error_injection(instance)
                
            except Exception as e:
                logger.warning(f"Cleanup failed for {instance}: {e}")
        
        # Wait for stabilization
        await asyncio.sleep(10)
    
    def _generate_chaos_summary(
        self, 
        results: Dict[str, ChaosScenarioResult]
    ) -> Dict[str, Any]:
        """Generate summary of chaos testing results."""
        summary = {
            'total_chaos_events': 0,
            'successful_recoveries': 0,
            'mean_recovery_time': 0,
            'system_resilience_score': 0,
            'critical_issues': [],
            'recommendations': []
        }
        
        # Aggregate metrics
        all_events = []
        all_recovery_times = []
        
        for name, result in results.items():
            if isinstance(result, ChaosScenarioResult):
                all_events.extend(result.chaos_events)
                
                recovery_times = [e.recovery_time for e in result.chaos_events if e.recovery_time is not None]
                all_recovery_times.extend(recovery_times)
        
        summary['total_chaos_events'] = len(all_events)
        summary['successful_recoveries'] = len(all_recovery_times)
        
        if all_recovery_times:
            summary['mean_recovery_time'] = np.mean(all_recovery_times)
        
        # Calculate resilience score
        recovery_rate = len(all_recovery_times) / len(all_events) if all_events else 0
        avg_availability = np.mean([
            r.system_availability for r in results.values() 
            if isinstance(r, ChaosScenarioResult)
        ])
        
        summary['system_resilience_score'] = (recovery_rate * 0.6 + avg_availability * 0.4)
        
        # Identify critical issues
        for name, result in results.items():
            if isinstance(result, ChaosScenarioResult):
                if result.mean_recovery_time > self.targets['max_recovery_time_s']:
                    summary['critical_issues'].append(
                        f"{name}: Recovery time ({result.mean_recovery_time:.1f}s) exceeds target"
                    )
                
                if result.system_availability < self.targets['min_availability']:
                    summary['critical_issues'].append(
                        f"{name}: Availability ({result.system_availability:.2f}) below target"
                    )
                
                if not result.data_integrity_maintained:
                    summary['critical_issues'].append(
                        f"{name}: Data integrity compromised"
                    )
        
        # Generate recommendations
        if summary['system_resilience_score'] < 0.8:
            summary['recommendations'].append(
                "Low resilience score - implement more robust failure detection and recovery"
            )
        
        if summary['mean_recovery_time'] > self.targets['max_recovery_time_s']:
            summary['recommendations'].append(
                f"Recovery time ({summary['mean_recovery_time']:.1f}s) exceeds target - "
                "optimize recovery procedures"
            )
        
        if len(summary['critical_issues']) > 0:
            summary['recommendations'].append(
                "Critical issues detected - review and strengthen failure handling mechanisms"
            )
        
        return summary