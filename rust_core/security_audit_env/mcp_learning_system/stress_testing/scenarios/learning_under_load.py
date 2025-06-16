"""
Learning under load stress testing scenario.

Tests learning performance, accuracy, and adaptation under various load conditions.
"""

import asyncio
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
import numpy as np
import logging
from concurrent.futures import ThreadPoolExecutor
import psutil

from mcp_learning_system.core import LearningMCPCluster
from ..monitoring import AccuracyTracker, LatencyTracker, LoadGenerator

logger = logging.getLogger(__name__)


@dataclass
class LoadScenarioResult:
    """Results from a load scenario test."""
    scenario_name: str
    load_level: int
    duration: float
    total_operations: int
    successful_operations: int
    failed_operations: int
    accuracy_metrics: Dict[str, float] = field(default_factory=dict)
    latency_metrics: Dict[str, float] = field(default_factory=dict)
    resource_metrics: Dict[str, float] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    
    @property
    def success_rate(self) -> float:
        """Calculate operation success rate."""
        if self.total_operations == 0:
            return 0.0
        return self.successful_operations / self.total_operations
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'scenario_name': self.scenario_name,
            'load_level': self.load_level,
            'duration': self.duration,
            'total_operations': self.total_operations,
            'successful_operations': self.successful_operations,
            'failed_operations': self.failed_operations,
            'success_rate': self.success_rate,
            'accuracy_metrics': self.accuracy_metrics,
            'latency_metrics': self.latency_metrics,
            'resource_metrics': self.resource_metrics,
            'errors': self.errors
        }


class LearningUnderLoadScenario:
    """Comprehensive learning under load stress testing scenario."""
    
    def __init__(self, mcp_cluster: Optional[LearningMCPCluster] = None):
        """Initialize scenario."""
        self.mcp_cluster = mcp_cluster or LearningMCPCluster()
        self.accuracy_tracker = AccuracyTracker()
        self.latency_tracker = LatencyTracker()
        self.executor = ThreadPoolExecutor(max_workers=psutil.cpu_count() * 2)
        
    async def run_scenario(self, duration: int = 600) -> Dict[str, LoadScenarioResult]:
        """Run complete learning under load scenario."""
        logger.info(f"Starting learning under load scenario for {duration} seconds")
        
        results = {}
        
        try:
            # Initialize cluster
            await self.mcp_cluster.initialize()
            
            # Run different load scenarios
            results['gradual_load'] = await self.test_gradual_load_increase(duration // 4)
            results['sustained_load'] = await self.test_sustained_high_load(duration // 4)
            results['burst_load'] = await self.test_burst_load_patterns(duration // 4)
            results['variable_load'] = await self.test_variable_load(duration // 4)
            
            # Generate summary
            results['summary'] = self._generate_scenario_summary(results)
            
        finally:
            await self.mcp_cluster.shutdown()
            self.executor.shutdown()
            
        return results
    
    async def test_gradual_load_increase(self, duration: int) -> LoadScenarioResult:
        """Test learning under gradually increasing load."""
        logger.info("Testing gradual load increase")
        
        result = LoadScenarioResult(
            scenario_name="gradual_load_increase",
            load_level=0,
            duration=0,
            total_operations=0,
            successful_operations=0,
            failed_operations=0
        )
        
        start_time = time.time()
        load_generator = LoadGenerator()
        
        # Gradually increase load from 100 to 10000 ops/sec
        load_steps = [100, 500, 1000, 2500, 5000, 7500, 10000]
        step_duration = duration // len(load_steps)
        
        for target_rate in load_steps:
            logger.info(f"Increasing load to {target_rate} ops/sec")
            
            # Reset trackers for this step
            self.accuracy_tracker.reset()
            self.latency_tracker.reset()
            
            # Generate load at target rate
            step_result = await self._run_load_step(
                target_rate=target_rate,
                duration=step_duration
            )
            
            # Update cumulative results
            result.total_operations += step_result['total_operations']
            result.successful_operations += step_result['successful_operations']
            result.failed_operations += step_result['failed_operations']
            
            # Track peak load level
            result.load_level = max(result.load_level, target_rate)
            
            # Record metrics at this load level
            result.accuracy_metrics[f'{target_rate}_ops'] = step_result['accuracy']
            result.latency_metrics[f'{target_rate}_ops'] = step_result['avg_latency']
            result.resource_metrics[f'{target_rate}_ops'] = step_result['cpu_usage']
        
        result.duration = time.time() - start_time
        
        # Final metrics
        result.accuracy_metrics['final'] = self.accuracy_tracker.get_current()
        result.latency_metrics['overall_p95'] = self.latency_tracker.get_percentile('learning', 95)
        result.latency_metrics['overall_p99'] = self.latency_tracker.get_percentile('learning', 99)
        
        return result
    
    async def test_sustained_high_load(self, duration: int) -> LoadScenarioResult:
        """Test learning under sustained high load."""
        logger.info("Testing sustained high load")
        
        result = LoadScenarioResult(
            scenario_name="sustained_high_load",
            load_level=10000,  # 10k ops/sec
            duration=0,
            total_operations=0,
            successful_operations=0,
            failed_operations=0
        )
        
        start_time = time.time()
        
        # Run at constant high load
        async with LoadGenerator(rate=10000) as load_gen:
            # Monitor accuracy over time
            accuracy_samples = []
            sample_interval = 10  # seconds
            
            while time.time() - start_time < duration:
                # Reset trackers for sampling
                self.accuracy_tracker.reset()
                self.latency_tracker.reset()
                
                # Run for sample interval
                sample_start = time.time()
                operations = 0
                successes = 0
                failures = 0
                
                while time.time() - sample_start < sample_interval:
                    # Generate learning interaction
                    interaction = await load_gen.generate_interaction()
                    
                    # Attempt learning
                    try:
                        start = time.perf_counter()
                        learning_result = await self.mcp_cluster.learn(interaction)
                        latency = time.perf_counter() - start
                        
                        operations += 1
                        if learning_result.success:
                            successes += 1
                            self.latency_tracker.record('learning', latency)
                            self.accuracy_tracker.record(learning_result.accuracy)
                        else:
                            failures += 1
                            
                    except Exception as e:
                        failures += 1
                        result.errors.append(f"Learning error: {str(e)}")
                    
                    # Small yield to prevent blocking
                    if operations % 100 == 0:
                        await asyncio.sleep(0)
                
                # Update results
                result.total_operations += operations
                result.successful_operations += successes
                result.failed_operations += failures
                
                # Record sample
                current_accuracy = self.accuracy_tracker.get_current()
                accuracy_samples.append(current_accuracy)
                
                # Log progress
                elapsed = time.time() - start_time
                logger.info(
                    f"Sustained load progress: {elapsed:.1f}s, "
                    f"accuracy: {current_accuracy:.3f}, "
                    f"success rate: {successes/operations:.3f}"
                )
        
        result.duration = time.time() - start_time
        
        # Analyze accuracy stability
        if accuracy_samples:
            result.accuracy_metrics['mean'] = np.mean(accuracy_samples)
            result.accuracy_metrics['std'] = np.std(accuracy_samples)
            result.accuracy_metrics['min'] = np.min(accuracy_samples)
            result.accuracy_metrics['max'] = np.max(accuracy_samples)
            
            # Check for degradation
            first_quarter = np.mean(accuracy_samples[:len(accuracy_samples)//4])
            last_quarter = np.mean(accuracy_samples[-len(accuracy_samples)//4:])
            result.accuracy_metrics['degradation'] = first_quarter - last_quarter
        
        # Latency metrics
        result.latency_metrics['mean'] = self.latency_tracker.get_average('learning')
        result.latency_metrics['p95'] = self.latency_tracker.get_percentile('learning', 95)
        result.latency_metrics['p99'] = self.latency_tracker.get_percentile('learning', 99)
        
        return result
    
    async def test_burst_load_patterns(self, duration: int) -> LoadScenarioResult:
        """Test learning under burst load patterns."""
        logger.info("Testing burst load patterns")
        
        result = LoadScenarioResult(
            scenario_name="burst_load_patterns",
            load_level=20000,  # Peak burst rate
            duration=0,
            total_operations=0,
            successful_operations=0,
            failed_operations=0
        )
        
        start_time = time.time()
        
        # Burst configuration
        burst_config = {
            'baseline_rate': 1000,     # ops/sec during normal
            'burst_rate': 20000,       # ops/sec during burst
            'burst_duration': 10,      # seconds
            'quiet_duration': 20,      # seconds between bursts
        }
        
        burst_count = 0
        
        while time.time() - start_time < duration:
            # Quiet period
            quiet_result = await self._run_load_step(
                target_rate=burst_config['baseline_rate'],
                duration=burst_config['quiet_duration']
            )
            
            result.total_operations += quiet_result['total_operations']
            result.successful_operations += quiet_result['successful_operations']
            result.failed_operations += quiet_result['failed_operations']
            
            # Burst period
            logger.info(f"Starting burst #{burst_count + 1}")
            burst_start = time.time()
            
            # Track burst-specific metrics
            self.accuracy_tracker.reset()
            self.latency_tracker.reset()
            
            burst_result = await self._run_load_step(
                target_rate=burst_config['burst_rate'],
                duration=burst_config['burst_duration']
            )
            
            burst_recovery_time = time.time() - burst_start
            
            result.total_operations += burst_result['total_operations']
            result.successful_operations += burst_result['successful_operations']
            result.failed_operations += burst_result['failed_operations']
            
            # Record burst metrics
            burst_count += 1
            result.accuracy_metrics[f'burst_{burst_count}_accuracy'] = burst_result['accuracy']
            result.latency_metrics[f'burst_{burst_count}_p99'] = self.latency_tracker.get_percentile('learning', 99)
            result.resource_metrics[f'burst_{burst_count}_recovery_time'] = burst_recovery_time
            
            # Check if we've exceeded duration
            if time.time() - start_time >= duration:
                break
        
        result.duration = time.time() - start_time
        
        # Summary metrics
        result.accuracy_metrics['burst_count'] = burst_count
        result.resource_metrics['avg_burst_impact'] = np.mean([
            result.accuracy_metrics.get(f'burst_{i}_accuracy', 0)
            for i in range(1, burst_count + 1)
        ])
        
        return result
    
    async def test_variable_load(self, duration: int) -> LoadScenarioResult:
        """Test learning under variable load patterns."""
        logger.info("Testing variable load patterns")
        
        result = LoadScenarioResult(
            scenario_name="variable_load",
            load_level=0,
            duration=0,
            total_operations=0,
            successful_operations=0,
            failed_operations=0
        )
        
        start_time = time.time()
        
        # Generate sinusoidal load pattern
        base_rate = 5000
        amplitude = 4000
        period = 60  # seconds
        
        sample_interval = 1  # second
        load_samples = []
        accuracy_samples = []
        
        while time.time() - start_time < duration:
            # Calculate current load based on sine wave
            elapsed = time.time() - start_time
            current_rate = int(
                base_rate + amplitude * np.sin(2 * np.pi * elapsed / period)
            )
            current_rate = max(100, current_rate)  # Minimum 100 ops/sec
            
            load_samples.append(current_rate)
            result.load_level = max(result.load_level, current_rate)
            
            # Run at current rate for sample interval
            sample_result = await self._run_load_step(
                target_rate=current_rate,
                duration=sample_interval
            )
            
            result.total_operations += sample_result['total_operations']
            result.successful_operations += sample_result['successful_operations']
            result.failed_operations += sample_result['failed_operations']
            
            accuracy_samples.append(sample_result['accuracy'])
            
            # Log current state
            if len(load_samples) % 10 == 0:
                logger.info(
                    f"Variable load: rate={current_rate}, "
                    f"accuracy={sample_result['accuracy']:.3f}"
                )
        
        result.duration = time.time() - start_time
        
        # Analyze correlation between load and accuracy
        if len(load_samples) > 10 and len(accuracy_samples) > 10:
            correlation = np.corrcoef(load_samples, accuracy_samples)[0, 1]
            result.accuracy_metrics['load_accuracy_correlation'] = correlation
            
            # Find optimal load level (best accuracy)
            best_idx = np.argmax(accuracy_samples)
            result.resource_metrics['optimal_load_rate'] = load_samples[best_idx]
            result.accuracy_metrics['optimal_load_accuracy'] = accuracy_samples[best_idx]
        
        # Summary statistics
        result.accuracy_metrics['mean'] = np.mean(accuracy_samples) if accuracy_samples else 0
        result.accuracy_metrics['std'] = np.std(accuracy_samples) if accuracy_samples else 0
        result.resource_metrics['load_variance'] = np.var(load_samples) if load_samples else 0
        
        return result
    
    async def _run_load_step(self, target_rate: int, duration: int) -> Dict[str, Any]:
        """Run a single load step at target rate."""
        load_gen = LoadGenerator(rate=target_rate)
        
        start_time = time.time()
        operations = 0
        successes = 0
        failures = 0
        latencies = []
        accuracies = []
        
        # Start CPU monitoring
        process = psutil.Process()
        cpu_samples = []
        
        async with load_gen:
            while time.time() - start_time < duration:
                # Generate batch of operations
                batch_size = min(100, target_rate // 10)
                batch_tasks = []
                
                for _ in range(batch_size):
                    interaction = await load_gen.generate_interaction()
                    task = asyncio.create_task(self._perform_learning(interaction))
                    batch_tasks.append(task)
                
                # Wait for batch completion
                batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
                
                # Process results
                for result in batch_results:
                    operations += 1
                    
                    if isinstance(result, Exception):
                        failures += 1
                    elif result is not None:
                        if result['success']:
                            successes += 1
                            latencies.append(result['latency'])
                            accuracies.append(result['accuracy'])
                        else:
                            failures += 1
                
                # Sample CPU usage
                cpu_samples.append(process.cpu_percent())
                
                # Adaptive delay based on target rate
                delay = max(0, (batch_size / target_rate) - (time.time() - start_time))
                if delay > 0:
                    await asyncio.sleep(delay)
        
        # Calculate metrics
        actual_rate = operations / (time.time() - start_time)
        
        return {
            'total_operations': operations,
            'successful_operations': successes,
            'failed_operations': failures,
            'actual_rate': actual_rate,
            'accuracy': np.mean(accuracies) if accuracies else 0.0,
            'avg_latency': np.mean(latencies) if latencies else 0.0,
            'p95_latency': np.percentile(latencies, 95) if latencies else 0.0,
            'p99_latency': np.percentile(latencies, 99) if latencies else 0.0,
            'cpu_usage': np.mean(cpu_samples) if cpu_samples else 0.0
        }
    
    async def _perform_learning(self, interaction: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Perform a single learning operation."""
        try:
            start = time.perf_counter()
            result = await self.mcp_cluster.learn(interaction)
            latency = time.perf_counter() - start
            
            return {
                'success': result.success,
                'accuracy': result.accuracy,
                'latency': latency
            }
        except Exception as e:
            logger.error(f"Learning operation failed: {e}")
            return None
    
    def _generate_scenario_summary(self, results: Dict[str, LoadScenarioResult]) -> Dict[str, Any]:
        """Generate summary of all scenario results."""
        summary = {
            'total_operations': sum(r.total_operations for r in results.values() if isinstance(r, LoadScenarioResult)),
            'overall_success_rate': 0.0,
            'best_scenario': None,
            'worst_scenario': None,
            'recommendations': []
        }
        
        # Calculate overall success rate
        total_ops = sum(r.total_operations for r in results.values() if isinstance(r, LoadScenarioResult))
        total_success = sum(r.successful_operations for r in results.values() if isinstance(r, LoadScenarioResult))
        
        if total_ops > 0:
            summary['overall_success_rate'] = total_success / total_ops
        
        # Find best and worst scenarios
        scenario_scores = {}
        for name, result in results.items():
            if isinstance(result, LoadScenarioResult):
                # Score based on success rate and accuracy
                score = result.success_rate * 0.5
                if 'mean' in result.accuracy_metrics:
                    score += result.accuracy_metrics['mean'] * 0.5
                scenario_scores[name] = score
        
        if scenario_scores:
            summary['best_scenario'] = max(scenario_scores, key=scenario_scores.get)
            summary['worst_scenario'] = min(scenario_scores, key=scenario_scores.get)
        
        # Generate recommendations
        if 'gradual_load' in results:
            if results['gradual_load'].accuracy_metrics.get('10000_ops', 0) < 0.8:
                summary['recommendations'].append(
                    "System struggles at 10k ops/sec - consider optimizing learning algorithms"
                )
        
        if 'sustained_load' in results:
            degradation = results['sustained_load'].accuracy_metrics.get('degradation', 0)
            if degradation > 0.1:
                summary['recommendations'].append(
                    f"Significant accuracy degradation ({degradation:.2f}) under sustained load - "
                    "implement adaptive learning rate or memory management"
                )
        
        if 'burst_load' in results:
            burst_impact = results['burst_load'].resource_metrics.get('avg_burst_impact', 0)
            if burst_impact < 0.7:
                summary['recommendations'].append(
                    "Poor burst handling - implement request queuing or rate limiting"
                )
        
        if 'variable_load' in results:
            optimal_rate = results['variable_load'].resource_metrics.get('optimal_load_rate', 0)
            if optimal_rate > 0:
                summary['recommendations'].append(
                    f"Optimal performance at {optimal_rate} ops/sec - "
                    "consider auto-scaling around this threshold"
                )
        
        return summary