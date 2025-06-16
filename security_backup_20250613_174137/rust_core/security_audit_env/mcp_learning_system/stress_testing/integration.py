"""
Core stress testing integration for MCP Learning System.

Implements 7-phase stress testing framework with comprehensive metrics collection
and performance validation.
"""

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
import logging
import json
from pathlib import Path

import numpy as np
from prometheus_client import Counter, Histogram, Gauge, Summary

from test_environments.stress_testing.core import CycleManager
from mcp_learning_system.core import LearningMCPCluster
from .monitoring import MetricsCollector, MemoryMonitor, AccuracyTracker, LatencyTracker
from .validators import PerformanceValidator, LearningAccuracyValidator

logger = logging.getLogger(__name__)

# Prometheus metrics
stress_test_counter = Counter('mcp_stress_test_total', 'Total stress tests run', ['phase'])
stress_test_duration = Histogram('mcp_stress_test_duration_seconds', 'Stress test duration', ['phase'])
learning_accuracy = Gauge('mcp_learning_accuracy', 'Learning accuracy under stress', ['phase'])
memory_usage = Gauge('mcp_memory_usage_bytes', 'Memory usage during stress test', ['type'])
recovery_time = Summary('mcp_recovery_time_seconds', 'Recovery time from failures')


class StressTestPhase(Enum):
    """Stress test phases with load percentages."""
    BASELINE = "baseline"      # 0-10% load
    LIGHT = "light"            # 10-25% load
    MEDIUM = "medium"          # 25-50% load
    HEAVY = "heavy"            # 50-75% load
    EXTREME = "extreme"        # 75-90% load
    CRITICAL = "critical"      # 90-95% load
    CHAOS = "chaos"            # 95%+ load


@dataclass
class PhaseResult:
    """Results from a single stress test phase."""
    phase: StressTestPhase
    start_time: datetime
    end_time: datetime
    load_percentage: float
    metrics: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    passed: bool = True
    
    @property
    def duration(self) -> float:
        """Calculate phase duration in seconds."""
        return (self.end_time - self.start_time).total_seconds()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for reporting."""
        return {
            'phase': self.phase.value,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat(),
            'duration': self.duration,
            'load_percentage': self.load_percentage,
            'metrics': self.metrics,
            'errors': self.errors,
            'passed': self.passed
        }


@dataclass
class StressTestReport:
    """Comprehensive stress test report."""
    test_id: str
    start_time: datetime
    end_time: datetime
    results: Dict[StressTestPhase, PhaseResult]
    summary: Dict[str, Any] = field(default_factory=dict)
    
    def to_json(self, path: Optional[Path] = None) -> str:
        """Export report as JSON."""
        report_data = {
            'test_id': self.test_id,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat(),
            'duration': (self.end_time - self.start_time).total_seconds(),
            'results': {
                phase.value: result.to_dict() 
                for phase, result in self.results.items()
            },
            'summary': self.summary
        }
        
        json_str = json.dumps(report_data, indent=2)
        
        if path:
            path.write_text(json_str)
            
        return json_str
    
    def generate_summary(self):
        """Generate test summary statistics."""
        total_errors = sum(len(r.errors) for r in self.results.values())
        phases_passed = sum(1 for r in self.results.values() if r.passed)
        
        self.summary = {
            'total_phases': len(self.results),
            'phases_passed': phases_passed,
            'phases_failed': len(self.results) - phases_passed,
            'total_errors': total_errors,
            'overall_success': phases_passed == len(self.results),
            'performance_metrics': self._aggregate_performance_metrics()
        }
    
    def _aggregate_performance_metrics(self) -> Dict[str, Any]:
        """Aggregate performance metrics across all phases."""
        metrics = {}
        
        # Collect all metrics
        for phase, result in self.results.items():
            for metric, value in result.metrics.items():
                if metric not in metrics:
                    metrics[metric] = []
                metrics[metric].append(value)
        
        # Calculate statistics
        aggregated = {}
        for metric, values in metrics.items():
            if values and all(isinstance(v, (int, float)) for v in values):
                aggregated[metric] = {
                    'min': min(values),
                    'max': max(values),
                    'mean': np.mean(values),
                    'median': np.median(values),
                    'p95': np.percentile(values, 95),
                    'p99': np.percentile(values, 99)
                }
            else:
                aggregated[metric] = values
                
        return aggregated


class MCPLearningStressTest:
    """Main stress testing integration for MCP Learning System."""
    
    def __init__(self, mcp_cluster: Optional[LearningMCPCluster] = None):
        """Initialize stress test framework."""
        self.cycle_manager = CycleManager()
        self.mcp_cluster = mcp_cluster or LearningMCPCluster()
        self.metrics_collector = MetricsCollector()
        self.memory_monitor = MemoryMonitor(self.mcp_cluster)
        self.accuracy_tracker = AccuracyTracker()
        self.latency_tracker = LatencyTracker()
        self.performance_validator = PerformanceValidator()
        self.accuracy_validator = LearningAccuracyValidator()
        
        # Test configuration
        self.phase_configs = {
            StressTestPhase.BASELINE: {'load': 5, 'duration': 60},
            StressTestPhase.LIGHT: {'load': 17, 'duration': 120},
            StressTestPhase.MEDIUM: {'load': 37, 'duration': 180},
            StressTestPhase.HEAVY: {'load': 62, 'duration': 240},
            StressTestPhase.EXTREME: {'load': 82, 'duration': 300},
            StressTestPhase.CRITICAL: {'load': 92, 'duration': 360},
            StressTestPhase.CHAOS: {'load': 98, 'duration': 420}
        }
        
    async def run_comprehensive_stress_test(self) -> StressTestReport:
        """Run complete 7-phase stress test."""
        test_id = f"stress_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        logger.info(f"Starting comprehensive stress test: {test_id}")
        
        start_time = datetime.now()
        results = {}
        
        try:
            # Initialize MCP cluster
            await self.mcp_cluster.initialize()
            
            # Run each phase
            for phase in StressTestPhase:
                logger.info(f"Starting phase: {phase.value}")
                phase_result = await self._run_phase(phase)
                results[phase] = phase_result
                
                # Check if we should continue
                if not phase_result.passed and phase != StressTestPhase.CHAOS:
                    logger.warning(f"Phase {phase.value} failed, stopping test")
                    break
                    
                # Cool down between phases
                if phase != StressTestPhase.CHAOS:
                    await self._cooldown_period()
                    
        except Exception as e:
            logger.error(f"Stress test failed: {e}")
            raise
        finally:
            # Cleanup
            await self.mcp_cluster.shutdown()
            
        end_time = datetime.now()
        
        # Generate report
        report = StressTestReport(
            test_id=test_id,
            start_time=start_time,
            end_time=end_time,
            results=results
        )
        report.generate_summary()
        
        # Save report
        report_path = Path(f"mcp_learning_system/stress_testing/reports/{test_id}.json")
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report.to_json(report_path)
        
        logger.info(f"Stress test completed: {test_id}")
        return report
    
    async def _run_phase(self, phase: StressTestPhase) -> PhaseResult:
        """Run a single stress test phase."""
        config = self.phase_configs[phase]
        start_time = datetime.now()
        
        # Initialize phase result
        result = PhaseResult(
            phase=phase,
            start_time=start_time,
            end_time=start_time,  # Will be updated
            load_percentage=config['load']
        )
        
        try:
            # Start monitoring
            self.metrics_collector.start_collection()
            
            # Apply load
            await self.cycle_manager.set_load_percentage(config['load'])
            
            # Run phase-specific tests
            if phase == StressTestPhase.BASELINE:
                await self._test_baseline_learning(result, config['duration'])
            elif phase == StressTestPhase.LIGHT:
                await self._test_light_load_adaptation(result, config['duration'])
            elif phase == StressTestPhase.MEDIUM:
                await self._test_medium_learning_efficiency(result, config['duration'])
            elif phase == StressTestPhase.HEAVY:
                await self._test_heavy_cross_instance(result, config['duration'])
            elif phase == StressTestPhase.EXTREME:
                await self._test_extreme_resilience(result, config['duration'])
            elif phase == StressTestPhase.CRITICAL:
                await self._test_critical_performance(result, config['duration'])
            elif phase == StressTestPhase.CHAOS:
                await self._test_chaos_recovery(result, config['duration'])
            
            # Validate results
            result.passed = await self._validate_phase_results(phase, result)
            
        except Exception as e:
            logger.error(f"Phase {phase.value} error: {e}")
            result.errors.append(str(e))
            result.passed = False
        finally:
            # Stop monitoring and collect metrics
            metrics = self.metrics_collector.stop_collection()
            result.metrics.update(metrics)
            result.end_time = datetime.now()
            
            # Update Prometheus metrics
            stress_test_counter.labels(phase=phase.value).inc()
            stress_test_duration.labels(phase=phase.value).observe(result.duration)
            
        return result
    
    async def _test_baseline_learning(self, result: PhaseResult, duration: int):
        """Test baseline learning capabilities."""
        logger.info("Testing baseline learning performance")
        
        end_time = time.time() + duration
        interactions = 0
        
        while time.time() < end_time:
            # Simulate learning interaction
            interaction = await self._generate_learning_interaction()
            
            # Measure learning performance
            start = time.perf_counter()
            learning_result = await self.mcp_cluster.learn(interaction)
            latency = time.perf_counter() - start
            
            # Track metrics
            self.latency_tracker.record('learning', latency)
            self.accuracy_tracker.record(learning_result.accuracy)
            
            interactions += 1
            
            # Baseline uses minimal load
            await asyncio.sleep(0.1)
        
        # Record metrics
        result.metrics['total_interactions'] = interactions
        result.metrics['avg_learning_latency'] = self.latency_tracker.get_average('learning')
        result.metrics['learning_accuracy'] = self.accuracy_tracker.get_current()
        
        learning_accuracy.labels(phase='baseline').set(result.metrics['learning_accuracy'])
    
    async def _test_light_load_adaptation(self, result: PhaseResult, duration: int):
        """Test adaptation under light load."""
        logger.info("Testing light load adaptation")
        
        # Generate concurrent learning tasks
        tasks = []
        for _ in range(10):  # 10 concurrent learners
            task = asyncio.create_task(self._continuous_learning_task(duration))
            tasks.append(task)
        
        # Monitor adaptation
        adaptation_metrics = await self._monitor_adaptation(duration)
        
        # Wait for tasks
        await asyncio.gather(*tasks)
        
        # Record metrics
        result.metrics['adaptation_rate'] = adaptation_metrics['rate']
        result.metrics['adaptation_accuracy'] = adaptation_metrics['accuracy']
        result.metrics['concurrent_learners'] = 10
    
    async def _test_medium_learning_efficiency(self, result: PhaseResult, duration: int):
        """Test learning efficiency under medium load."""
        logger.info("Testing medium load learning efficiency")
        
        # Track memory efficiency
        initial_memory = self.memory_monitor.get_current_usage()
        
        # Run efficiency test
        efficiency_metrics = await self._measure_learning_efficiency(
            duration=duration,
            load_level='medium'
        )
        
        # Check memory growth
        final_memory = self.memory_monitor.get_current_usage()
        memory_growth = final_memory - initial_memory
        
        # Record metrics
        result.metrics.update(efficiency_metrics)
        result.metrics['memory_growth_mb'] = memory_growth / (1024 * 1024)
        
        memory_usage.labels(type='growth').set(memory_growth)
    
    async def _test_heavy_cross_instance(self, result: PhaseResult, duration: int):
        """Test cross-instance communication under heavy load."""
        logger.info("Testing heavy load cross-instance sharing")
        
        # Test high-frequency cross-instance operations
        sharing_results = await self._test_cross_instance_sharing(
            duration=duration,
            rate=1000  # 1000 shares per second
        )
        
        result.metrics.update(sharing_results)
    
    async def _test_extreme_resilience(self, result: PhaseResult, duration: int):
        """Test system resilience under extreme load."""
        logger.info("Testing extreme load resilience")
        
        # Inject failures while maintaining load
        resilience_metrics = await self._test_resilience_with_failures(
            duration=duration,
            failure_rate=0.1  # 10% failure rate
        )
        
        result.metrics.update(resilience_metrics)
    
    async def _test_critical_performance(self, result: PhaseResult, duration: int):
        """Test critical performance thresholds."""
        logger.info("Testing critical performance limits")
        
        # Push system to limits
        critical_metrics = await self._test_performance_limits(
            duration=duration,
            target_latency_ms=1.0  # Sub-millisecond target
        )
        
        result.metrics.update(critical_metrics)
    
    async def _test_chaos_recovery(self, result: PhaseResult, duration: int):
        """Test chaos engineering scenarios."""
        logger.info("Testing chaos recovery capabilities")
        
        # Run chaos scenarios
        chaos_metrics = await self._run_chaos_scenarios(duration)
        
        result.metrics.update(chaos_metrics)
        
        # Update recovery metrics
        if 'recovery_times' in chaos_metrics:
            for recovery_time in chaos_metrics['recovery_times']:
                recovery_time.observe(recovery_time)
    
    async def _validate_phase_results(self, phase: StressTestPhase, result: PhaseResult) -> bool:
        """Validate phase results against requirements."""
        # Performance requirements by phase
        requirements = {
            StressTestPhase.BASELINE: {
                'max_latency_ms': 1.0,
                'min_accuracy': 0.95,
                'max_memory_gb': 3.0
            },
            StressTestPhase.LIGHT: {
                'max_latency_ms': 2.0,
                'min_accuracy': 0.93,
                'max_memory_gb': 4.0
            },
            StressTestPhase.MEDIUM: {
                'max_latency_ms': 5.0,
                'min_accuracy': 0.90,
                'max_memory_gb': 6.0
            },
            StressTestPhase.HEAVY: {
                'max_latency_ms': 10.0,
                'min_accuracy': 0.85,
                'max_memory_gb': 8.0
            },
            StressTestPhase.EXTREME: {
                'max_latency_ms': 20.0,
                'min_accuracy': 0.80,
                'max_memory_gb': 10.0
            },
            StressTestPhase.CRITICAL: {
                'max_latency_ms': 50.0,
                'min_accuracy': 0.75,
                'max_memory_gb': 11.0
            },
            StressTestPhase.CHAOS: {
                'max_latency_ms': 100.0,
                'min_accuracy': 0.70,
                'max_memory_gb': 12.0
            }
        }
        
        req = requirements[phase]
        
        # Validate latency
        if 'avg_learning_latency' in result.metrics:
            if result.metrics['avg_learning_latency'] * 1000 > req['max_latency_ms']:
                result.errors.append(f"Latency exceeded: {result.metrics['avg_learning_latency']*1000:.2f}ms > {req['max_latency_ms']}ms")
                return False
        
        # Validate accuracy
        if 'learning_accuracy' in result.metrics:
            if result.metrics['learning_accuracy'] < req['min_accuracy']:
                result.errors.append(f"Accuracy too low: {result.metrics['learning_accuracy']:.2f} < {req['min_accuracy']}")
                return False
        
        # Validate memory
        current_memory_gb = self.memory_monitor.get_current_usage() / (1024**3)
        if current_memory_gb > req['max_memory_gb']:
            result.errors.append(f"Memory exceeded: {current_memory_gb:.2f}GB > {req['max_memory_gb']}GB")
            return False
        
        return True
    
    async def _cooldown_period(self, duration: int = 30):
        """Cool down period between phases."""
        logger.info(f"Cooling down for {duration} seconds")
        await asyncio.sleep(duration)
        
        # Reset metrics
        self.accuracy_tracker.reset()
        self.latency_tracker.reset()
    
    async def _generate_learning_interaction(self) -> Dict[str, Any]:
        """Generate a test learning interaction."""
        return {
            'type': 'pattern',
            'data': {
                'input': f"test_input_{time.time()}",
                'expected': f"test_output_{time.time()}",
                'context': {
                    'domain': 'stress_test',
                    'complexity': np.random.choice(['low', 'medium', 'high'])
                }
            }
        }
    
    async def _continuous_learning_task(self, duration: int):
        """Continuous learning task for concurrent testing."""
        end_time = time.time() + duration
        
        while time.time() < end_time:
            interaction = await self._generate_learning_interaction()
            await self.mcp_cluster.learn(interaction)
            await asyncio.sleep(0.01)  # Small delay
    
    async def _monitor_adaptation(self, duration: int) -> Dict[str, Any]:
        """Monitor learning adaptation over time."""
        samples = []
        end_time = time.time() + duration
        
        while time.time() < end_time:
            accuracy = await self.mcp_cluster.measure_accuracy()
            samples.append(accuracy)
            await asyncio.sleep(1)  # Sample every second
        
        # Calculate adaptation metrics
        if len(samples) > 10:
            # Adaptation rate: improvement over time
            first_quarter = np.mean(samples[:len(samples)//4])
            last_quarter = np.mean(samples[-len(samples)//4:])
            adaptation_rate = (last_quarter - first_quarter) / first_quarter
        else:
            adaptation_rate = 0.0
        
        return {
            'rate': adaptation_rate,
            'accuracy': np.mean(samples) if samples else 0.0,
            'samples': len(samples)
        }
    
    async def _measure_learning_efficiency(self, duration: int, load_level: str) -> Dict[str, Any]:
        """Measure learning efficiency metrics."""
        metrics = {
            'patterns_learned': 0,
            'learning_rate': 0.0,
            'efficiency_score': 0.0
        }
        
        start_time = time.time()
        patterns_learned = 0
        
        while time.time() < start_time + duration:
            # Learn pattern
            pattern = await self._generate_learning_interaction()
            result = await self.mcp_cluster.learn(pattern)
            
            if result.success:
                patterns_learned += 1
            
            # Vary rate based on load
            delay = {'light': 0.01, 'medium': 0.005, 'heavy': 0.001}.get(load_level, 0.01)
            await asyncio.sleep(delay)
        
        elapsed = time.time() - start_time
        metrics['patterns_learned'] = patterns_learned
        metrics['learning_rate'] = patterns_learned / elapsed
        metrics['efficiency_score'] = metrics['learning_rate'] / (1 + self.memory_monitor.get_current_usage() / (1024**3))
        
        return metrics
    
    async def _test_cross_instance_sharing(self, duration: int, rate: int) -> Dict[str, Any]:
        """Test cross-instance knowledge sharing."""
        metrics = {
            'total_shares': 0,
            'successful_shares': 0,
            'avg_share_latency': 0.0,
            'p95_share_latency': 0.0,
            'p99_share_latency': 0.0
        }
        
        latencies = []
        end_time = time.time() + duration
        
        while time.time() < end_time:
            # Share knowledge between instances
            source = np.random.choice(['development', 'devops', 'quality', 'bash_god'])
            target = np.random.choice(['development', 'devops', 'quality', 'bash_god'])
            
            if source != target:
                knowledge = {'pattern': f"shared_{time.time()}", 'confidence': 0.95}
                
                start = time.perf_counter()
                result = await self.mcp_cluster.share_knowledge(source, target, knowledge)
                latency = time.perf_counter() - start
                
                metrics['total_shares'] += 1
                if result.success:
                    metrics['successful_shares'] += 1
                    latencies.append(latency)
                
                # Control rate
                await asyncio.sleep(1.0 / rate)
        
        # Calculate latency percentiles
        if latencies:
            metrics['avg_share_latency'] = np.mean(latencies)
            metrics['p95_share_latency'] = np.percentile(latencies, 95)
            metrics['p99_share_latency'] = np.percentile(latencies, 99)
        
        return metrics
    
    async def _test_resilience_with_failures(self, duration: int, failure_rate: float) -> Dict[str, Any]:
        """Test resilience with injected failures."""
        metrics = {
            'total_operations': 0,
            'failed_operations': 0,
            'recovered_operations': 0,
            'avg_recovery_time': 0.0
        }
        
        recovery_times = []
        end_time = time.time() + duration
        
        while time.time() < end_time:
            # Inject failure randomly
            if np.random.random() < failure_rate:
                # Kill random instance
                instance = np.random.choice(list(self.mcp_cluster.instances.values()))
                
                start_recovery = time.time()
                await instance.kill()
                
                # Attempt operation (should trigger recovery)
                try:
                    await self.mcp_cluster.learn(await self._generate_learning_interaction())
                    recovery_time = time.time() - start_recovery
                    recovery_times.append(recovery_time)
                    metrics['recovered_operations'] += 1
                except Exception:
                    metrics['failed_operations'] += 1
                
                # Restart instance
                await instance.restart()
            else:
                # Normal operation
                await self.mcp_cluster.learn(await self._generate_learning_interaction())
            
            metrics['total_operations'] += 1
            await asyncio.sleep(0.01)
        
        if recovery_times:
            metrics['avg_recovery_time'] = np.mean(recovery_times)
        
        return metrics
    
    async def _test_performance_limits(self, duration: int, target_latency_ms: float) -> Dict[str, Any]:
        """Test performance at system limits."""
        metrics = {
            'operations_within_target': 0,
            'total_operations': 0,
            'min_latency_ms': float('inf'),
            'max_latency_ms': 0.0
        }
        
        end_time = time.time() + duration
        
        while time.time() < end_time:
            # Perform operation
            start = time.perf_counter()
            await self.mcp_cluster.process_pattern_match("test_pattern")
            latency_ms = (time.perf_counter() - start) * 1000
            
            metrics['total_operations'] += 1
            if latency_ms <= target_latency_ms:
                metrics['operations_within_target'] += 1
            
            metrics['min_latency_ms'] = min(metrics['min_latency_ms'], latency_ms)
            metrics['max_latency_ms'] = max(metrics['max_latency_ms'], latency_ms)
            
            # No delay - maximum throughput
        
        metrics['target_achievement_rate'] = metrics['operations_within_target'] / metrics['total_operations']
        
        return metrics
    
    async def _run_chaos_scenarios(self, duration: int) -> Dict[str, Any]:
        """Run chaos engineering scenarios."""
        metrics = {
            'scenarios_run': 0,
            'scenarios_recovered': 0,
            'recovery_times': [],
            'data_integrity_maintained': True
        }
        
        scenarios = [
            self._chaos_network_partition,
            self._chaos_memory_pressure,
            self._chaos_cpu_spike,
            self._chaos_disk_full,
            self._chaos_random_kills
        ]
        
        end_time = time.time() + duration
        
        while time.time() < end_time:
            # Select random scenario
            scenario = np.random.choice(scenarios)
            
            # Run scenario
            start_recovery = time.time()
            try:
                await scenario()
                
                # Verify system recovered
                test_result = await self.mcp_cluster.health_check()
                if test_result.healthy:
                    recovery_time = time.time() - start_recovery
                    metrics['recovery_times'].append(recovery_time)
                    metrics['scenarios_recovered'] += 1
                
            except Exception as e:
                logger.error(f"Chaos scenario failed: {e}")
            
            metrics['scenarios_run'] += 1
            
            # Wait before next scenario
            await asyncio.sleep(10)
        
        # Verify data integrity
        metrics['data_integrity_maintained'] = await self._verify_data_integrity()
        
        return metrics
    
    async def _chaos_network_partition(self):
        """Simulate network partition between instances."""
        # Partition random instances
        instances = list(self.mcp_cluster.instances.values())
        if len(instances) >= 2:
            partition_size = len(instances) // 2
            partitioned = instances[:partition_size]
            
            for instance in partitioned:
                await instance.block_network()
            
            # Wait for detection
            await asyncio.sleep(5)
            
            # Restore network
            for instance in partitioned:
                await instance.restore_network()
    
    async def _chaos_memory_pressure(self):
        """Simulate memory pressure."""
        # Allocate large memory blocks
        allocations = []
        for _ in range(100):
            # Allocate 100MB chunks
            allocation = bytearray(100 * 1024 * 1024)
            allocations.append(allocation)
            await asyncio.sleep(0.1)
        
        # Hold for a bit
        await asyncio.sleep(5)
        
        # Release memory
        allocations.clear()
    
    async def _chaos_cpu_spike(self):
        """Simulate CPU spike."""
        # Create CPU-intensive tasks
        tasks = []
        for _ in range(100):
            task = asyncio.create_task(self._cpu_intensive_task())
            tasks.append(task)
        
        # Run for limited time
        await asyncio.sleep(10)
        
        # Cancel tasks
        for task in tasks:
            task.cancel()
    
    async def _chaos_disk_full(self):
        """Simulate disk full scenario."""
        # This is simulated - actual implementation would write files
        logger.warning("Simulating disk full scenario")
        await asyncio.sleep(5)
    
    async def _chaos_random_kills(self):
        """Randomly kill instances."""
        instances = list(self.mcp_cluster.instances.values())
        num_to_kill = max(1, len(instances) // 3)
        
        to_kill = np.random.choice(instances, num_to_kill, replace=False)
        
        # Kill instances
        for instance in to_kill:
            await instance.kill()
        
        # Wait for recovery
        await asyncio.sleep(10)
        
        # Restart
        for instance in to_kill:
            await instance.restart()
    
    async def _cpu_intensive_task(self):
        """CPU-intensive task for stress testing."""
        result = 0
        for i in range(1000000):
            result += i ** 2
            if i % 10000 == 0:
                await asyncio.sleep(0)  # Yield control
        return result
    
    async def _verify_data_integrity(self) -> bool:
        """Verify data integrity after chaos testing."""
        try:
            # Check each instance
            for name, instance in self.mcp_cluster.instances.items():
                if not await instance.verify_integrity():
                    logger.error(f"Instance {name} failed integrity check")
                    return False
            
            # Check cross-instance consistency
            knowledge_hashes = {}
            for name, instance in self.mcp_cluster.instances.items():
                knowledge_hashes[name] = await instance.get_knowledge_hash()
            
            # All should have consistent shared knowledge
            unique_hashes = set(knowledge_hashes.values())
            if len(unique_hashes) > 1:
                logger.error("Knowledge inconsistency detected across instances")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Integrity verification failed: {e}")
            return False