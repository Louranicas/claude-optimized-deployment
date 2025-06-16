"""
Cross-instance stress testing scenario.

Tests communication, coordination, and knowledge sharing under stress.
"""

import asyncio
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
import numpy as np
import logging
from collections import defaultdict
import json

from mcp_learning_system.core import LearningMCPCluster
from ..monitoring import LatencyTracker, LoadGenerator

logger = logging.getLogger(__name__)


@dataclass
class CrossInstanceScenarioResult:
    """Results from a cross-instance stress scenario."""
    scenario_name: str
    duration: float
    instances_tested: List[str]
    total_messages: int
    successful_messages: int
    failed_messages: int
    communication_metrics: Dict[str, Any] = field(default_factory=dict)
    coordination_metrics: Dict[str, Any] = field(default_factory=dict)
    failure_recovery_metrics: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    
    @property
    def message_success_rate(self) -> float:
        """Calculate message success rate."""
        if self.total_messages == 0:
            return 0.0
        return self.successful_messages / self.total_messages
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'scenario_name': self.scenario_name,
            'duration': self.duration,
            'instances_tested': self.instances_tested,
            'total_messages': self.total_messages,
            'successful_messages': self.successful_messages,
            'failed_messages': self.failed_messages,
            'message_success_rate': self.message_success_rate,
            'communication_metrics': self.communication_metrics,
            'coordination_metrics': self.coordination_metrics,
            'failure_recovery_metrics': self.failure_recovery_metrics,
            'errors': self.errors
        }


class CrossInstanceStressScenario:
    """Cross-instance stress testing scenarios."""
    
    def __init__(self, mcp_cluster: Optional[LearningMCPCluster] = None):
        """Initialize scenario."""
        self.mcp_cluster = mcp_cluster or LearningMCPCluster()
        self.latency_tracker = LatencyTracker()
        
        # Instance configurations
        self.instance_names = ['development', 'devops', 'quality', 'bash_god']
        
        # Performance targets
        self.targets = {
            'max_latency_ms': 50,      # Max cross-instance latency
            'min_throughput_mbps': 10,  # Min throughput
            'max_recovery_time_s': 5,   # Max failure recovery time
            'min_consensus_rate': 0.95, # Min consensus success rate
        }
        
    async def run_scenario(self, duration: int = 600) -> Dict[str, CrossInstanceScenarioResult]:
        """Run complete cross-instance stress scenario."""
        logger.info(f"Starting cross-instance stress scenario for {duration} seconds")
        
        results = {}
        
        try:
            # Initialize cluster
            await self.mcp_cluster.initialize()
            
            # Verify all instances are operational
            await self._verify_cluster_health()
            
            # Run different stress scenarios
            results['high_frequency_sharing'] = await self.test_high_frequency_sharing(duration // 5)
            results['broadcast_stress'] = await self.test_broadcast_stress(duration // 5)
            results['consensus_under_load'] = await self.test_consensus_under_load(duration // 5)
            results['failure_recovery'] = await self.test_failure_recovery(duration // 5)
            results['network_partition'] = await self.test_network_partition(duration // 5)
            
            # Generate summary
            results['summary'] = self._generate_cross_instance_summary(results)
            
        finally:
            await self.mcp_cluster.shutdown()
            
        return results
    
    async def test_high_frequency_sharing(self, duration: int) -> CrossInstanceScenarioResult:
        """Test high-frequency knowledge sharing between instances."""
        logger.info("Testing high-frequency knowledge sharing")
        
        result = CrossInstanceScenarioResult(
            scenario_name="high_frequency_sharing",
            duration=0,
            instances_tested=self.instance_names,
            total_messages=0,
            successful_messages=0,
            failed_messages=0
        )
        
        start_time = time.time()
        
        # Target sharing rate: 1000 messages/second
        target_rate = 1000
        load_generator = LoadGenerator(rate=target_rate)
        
        # Track latencies per instance pair
        latencies = defaultdict(list)
        throughput_samples = []
        
        async with load_generator:
            while time.time() - start_time < duration:
                # Generate batch of sharing operations
                batch_size = 100
                batch_tasks = []
                
                for _ in range(batch_size):
                    # Random source and target
                    source = np.random.choice(self.instance_names)
                    target = np.random.choice([i for i in self.instance_names if i != source])
                    
                    # Generate knowledge payload
                    knowledge = self._create_knowledge_payload('medium')
                    
                    # Create sharing task
                    task = asyncio.create_task(
                        self._measure_sharing_operation(source, target, knowledge)
                    )
                    batch_tasks.append((task, source, target))
                
                # Wait for batch completion
                batch_start = time.time()
                completed_tasks = await asyncio.gather(
                    *[task for task, _, _ in batch_tasks],
                    return_exceptions=True
                )
                batch_duration = time.time() - batch_start
                
                # Process results
                successful_in_batch = 0
                for i, task_result in enumerate(completed_tasks):
                    result.total_messages += 1
                    
                    if isinstance(task_result, Exception):
                        result.failed_messages += 1
                        result.errors.append(f"Sharing error: {str(task_result)}")
                    elif task_result is not None:
                        if task_result['success']:
                            result.successful_messages += 1
                            successful_in_batch += 1
                            
                            source, target = batch_tasks[i][1], batch_tasks[i][2]
                            pair_key = f"{source}->{target}"
                            latencies[pair_key].append(task_result['latency'])
                            
                            self.latency_tracker.record('cross_instance', task_result['latency'])
                        else:
                            result.failed_messages += 1
                
                # Calculate throughput for this batch
                if batch_duration > 0:
                    batch_throughput = successful_in_batch / batch_duration
                    throughput_samples.append(batch_throughput)
                
                # Control rate
                expected_batch_time = batch_size / target_rate
                actual_batch_time = time.time() - batch_start
                sleep_time = max(0, expected_batch_time - actual_batch_time)
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)
        
        result.duration = time.time() - start_time
        
        # Analyze communication patterns
        result.communication_metrics = {
            'avg_latency_ms': self.latency_tracker.get_average('cross_instance') * 1000,
            'p95_latency_ms': self.latency_tracker.get_percentile('cross_instance', 95) * 1000,
            'p99_latency_ms': self.latency_tracker.get_percentile('cross_instance', 99) * 1000,
            'actual_rate_msg_per_sec': result.total_messages / result.duration,
            'avg_throughput_msg_per_sec': np.mean(throughput_samples) if throughput_samples else 0,
            'peak_throughput_msg_per_sec': np.max(throughput_samples) if throughput_samples else 0
        }
        
        # Per-pair analysis
        pair_metrics = {}
        for pair, pair_latencies in latencies.items():
            if pair_latencies:
                pair_metrics[pair] = {
                    'message_count': len(pair_latencies),
                    'avg_latency_ms': np.mean(pair_latencies) * 1000,
                    'max_latency_ms': np.max(pair_latencies) * 1000,
                    'p95_latency_ms': np.percentile(pair_latencies, 95) * 1000
                }
        
        result.communication_metrics['instance_pairs'] = pair_metrics
        
        # Check performance targets
        if result.communication_metrics['p99_latency_ms'] > self.targets['max_latency_ms']:
            result.errors.append(
                f"P99 latency ({result.communication_metrics['p99_latency_ms']:.1f}ms) "
                f"exceeds target ({self.targets['max_latency_ms']}ms)"
            )
        
        return result
    
    async def test_broadcast_stress(self, duration: int) -> CrossInstanceScenarioResult:
        """Test broadcast communication under stress."""
        logger.info("Testing broadcast stress")
        
        result = CrossInstanceScenarioResult(
            scenario_name="broadcast_stress",
            duration=0,
            instances_tested=self.instance_names,
            total_messages=0,
            successful_messages=0,
            failed_messages=0
        )
        
        start_time = time.time()
        
        # Test different broadcast patterns
        broadcast_patterns = [
            {'name': 'small_frequent', 'size': 'small', 'interval': 0.1},
            {'name': 'medium_regular', 'size': 'medium', 'interval': 1.0},
            {'name': 'large_occasional', 'size': 'large', 'interval': 5.0}
        ]
        
        pattern_results = {}
        
        for pattern in broadcast_patterns:
            if time.time() - start_time >= duration:
                break
                
            logger.info(f"Testing broadcast pattern: {pattern['name']}")
            
            pattern_start = time.time()
            pattern_duration = min(duration // len(broadcast_patterns), 
                                 duration - (time.time() - start_time))
            
            pattern_metrics = {
                'broadcasts_sent': 0,
                'total_deliveries': 0,
                'successful_deliveries': 0,
                'failed_deliveries': 0,
                'latencies': []
            }
            
            while time.time() - pattern_start < pattern_duration:
                # Create broadcast payload
                payload = self._create_knowledge_payload(pattern['size'])
                
                # Select random broadcaster
                broadcaster = np.random.choice(self.instance_names)
                targets = [i for i in self.instance_names if i != broadcaster]
                
                # Perform broadcast
                broadcast_start = time.perf_counter()
                
                try:
                    broadcast_result = await self.mcp_cluster.broadcast(
                        broadcaster, payload, targets
                    )
                    
                    broadcast_latency = time.perf_counter() - broadcast_start
                    pattern_metrics['latencies'].append(broadcast_latency)
                    pattern_metrics['broadcasts_sent'] += 1
                    
                    # Count deliveries
                    for delivery in broadcast_result.deliveries:
                        pattern_metrics['total_deliveries'] += 1
                        if delivery.success:
                            pattern_metrics['successful_deliveries'] += 1
                        else:
                            pattern_metrics['failed_deliveries'] += 1
                    
                    result.total_messages += len(targets)
                    result.successful_messages += pattern_metrics['successful_deliveries']
                    result.failed_messages += pattern_metrics['failed_deliveries']
                    
                except Exception as e:
                    result.errors.append(f"Broadcast error: {str(e)}")
                    pattern_metrics['broadcasts_sent'] += 1
                    pattern_metrics['failed_deliveries'] += len(targets)
                    result.total_messages += len(targets)
                    result.failed_messages += len(targets)
                
                # Wait for next broadcast
                await asyncio.sleep(pattern['interval'])
            
            # Calculate pattern metrics
            if pattern_metrics['total_deliveries'] > 0:
                pattern_metrics['delivery_success_rate'] = (
                    pattern_metrics['successful_deliveries'] / 
                    pattern_metrics['total_deliveries']
                )
            
            if pattern_metrics['latencies']:
                pattern_metrics['avg_broadcast_time_ms'] = np.mean(pattern_metrics['latencies']) * 1000
                pattern_metrics['p95_broadcast_time_ms'] = np.percentile(pattern_metrics['latencies'], 95) * 1000
            
            pattern_results[pattern['name']] = pattern_metrics
        
        result.duration = time.time() - start_time
        result.communication_metrics['broadcast_patterns'] = pattern_results
        
        # Overall broadcast metrics
        all_latencies = []
        total_broadcasts = 0
        total_delivery_rate = 0
        
        for pattern_name, metrics in pattern_results.items():
            all_latencies.extend(metrics.get('latencies', []))
            total_broadcasts += metrics.get('broadcasts_sent', 0)
            total_delivery_rate += metrics.get('delivery_success_rate', 0)
        
        if all_latencies:
            result.communication_metrics['overall_broadcast_time_ms'] = np.mean(all_latencies) * 1000
            result.communication_metrics['p99_broadcast_time_ms'] = np.percentile(all_latencies, 99) * 1000
        
        if len(pattern_results) > 0:
            result.communication_metrics['avg_delivery_success_rate'] = total_delivery_rate / len(pattern_results)
        
        return result
    
    async def test_consensus_under_load(self, duration: int) -> CrossInstanceScenarioResult:
        """Test consensus mechanisms under load."""
        logger.info("Testing consensus under load")
        
        result = CrossInstanceScenarioResult(
            scenario_name="consensus_under_load",
            duration=0,
            instances_tested=self.instance_names,
            total_messages=0,
            successful_messages=0,
            failed_messages=0
        )
        
        start_time = time.time()
        
        # Test different consensus scenarios
        consensus_scenarios = [
            {'name': 'simple_majority', 'complexity': 'low'},
            {'name': 'byzantine_tolerant', 'complexity': 'high'},
            {'name': 'raft_consensus', 'complexity': 'medium'}
        ]
        
        consensus_results = {}
        
        for scenario in consensus_scenarios:
            if time.time() - start_time >= duration:
                break
                
            logger.info(f"Testing consensus: {scenario['name']}")
            
            scenario_start = time.time()
            scenario_duration = min(duration // len(consensus_scenarios),
                                  duration - (time.time() - start_time))
            
            consensus_attempts = 0
            consensus_successes = 0
            consensus_failures = 0
            consensus_times = []
            
            while time.time() - scenario_start < scenario_duration:
                # Create consensus proposal
                proposal = {
                    'id': f"proposal_{consensus_attempts}",
                    'data': self._create_knowledge_payload('small'),
                    'complexity': scenario['complexity'],
                    'timestamp': time.time()
                }
                
                # Attempt consensus
                consensus_start = time.perf_counter()
                
                try:
                    if scenario['name'] == 'simple_majority':
                        consensus_result = await self.mcp_cluster.simple_majority_consensus(
                            proposal, participants=self.instance_names, timeout=5.0
                        )
                    elif scenario['name'] == 'byzantine_tolerant':
                        consensus_result = await self.mcp_cluster.byzantine_consensus(
                            proposal, participants=self.instance_names, timeout=10.0
                        )
                    elif scenario['name'] == 'raft_consensus':
                        consensus_result = await self.mcp_cluster.raft_consensus(
                            proposal, participants=self.instance_names, timeout=7.0
                        )
                    
                    consensus_time = time.perf_counter() - consensus_start
                    consensus_times.append(consensus_time)
                    consensus_attempts += 1
                    
                    if consensus_result.success:
                        consensus_successes += 1
                        result.successful_messages += 1
                    else:
                        consensus_failures += 1
                        result.failed_messages += 1
                    
                    result.total_messages += 1
                    
                except Exception as e:
                    result.errors.append(f"Consensus error ({scenario['name']}): {str(e)}")
                    consensus_failures += 1
                    result.failed_messages += 1
                    result.total_messages += 1
                
                # Adaptive delay based on consensus complexity
                delay = {'low': 0.5, 'medium': 1.0, 'high': 2.0}[scenario['complexity']]
                await asyncio.sleep(delay)
            
            # Calculate scenario metrics
            scenario_metrics = {
                'attempts': consensus_attempts,
                'successes': consensus_successes,
                'failures': consensus_failures,
                'success_rate': consensus_successes / consensus_attempts if consensus_attempts > 0 else 0
            }
            
            if consensus_times:
                scenario_metrics['avg_consensus_time_ms'] = np.mean(consensus_times) * 1000
                scenario_metrics['p95_consensus_time_ms'] = np.percentile(consensus_times, 95) * 1000
                scenario_metrics['p99_consensus_time_ms'] = np.percentile(consensus_times, 99) * 1000
            
            consensus_results[scenario['name']] = scenario_metrics
        
        result.duration = time.time() - start_time
        result.coordination_metrics['consensus_scenarios'] = consensus_results
        
        # Overall consensus metrics
        total_attempts = sum(s.get('attempts', 0) for s in consensus_results.values())
        total_successes = sum(s.get('successes', 0) for s in consensus_results.values())
        
        if total_attempts > 0:
            result.coordination_metrics['overall_consensus_success_rate'] = total_successes / total_attempts
        
        # Check consensus performance target
        if result.coordination_metrics.get('overall_consensus_success_rate', 0) < self.targets['min_consensus_rate']:
            result.errors.append(
                f"Consensus success rate ({result.coordination_metrics['overall_consensus_success_rate']:.2f}) "
                f"below target ({self.targets['min_consensus_rate']})"
            )
        
        return result
    
    async def test_failure_recovery(self, duration: int) -> CrossInstanceScenarioResult:
        """Test failure recovery mechanisms."""
        logger.info("Testing failure recovery")
        
        result = CrossInstanceScenarioResult(
            scenario_name="failure_recovery",
            duration=0,
            instances_tested=self.instance_names,
            total_messages=0,
            successful_messages=0,
            failed_messages=0
        )
        
        start_time = time.time()
        
        # Test different failure scenarios
        failure_scenarios = [
            {'type': 'single_instance', 'count': 1},
            {'type': 'multiple_instance', 'count': 2},
            {'type': 'cascading_failure', 'count': 1}  # Starts with 1, may cascade
        ]
        
        recovery_results = {}
        
        for scenario in failure_scenarios:
            if time.time() - start_time >= duration:
                break
                
            logger.info(f"Testing failure scenario: {scenario['type']}")
            
            scenario_start = time.time()
            
            # Select instances to fail
            if scenario['type'] == 'cascading_failure':
                # Start with one instance
                failed_instances = [np.random.choice(self.instance_names)]
            else:
                failed_instances = np.random.choice(
                    self.instance_names, 
                    scenario['count'], 
                    replace=False
                ).tolist()
            
            # Store test data before failure
            test_data = self._create_knowledge_payload('large')
            await self.mcp_cluster.store_replicated_data(test_data, replication_factor=3)
            
            # Simulate failures
            recovery_start = time.perf_counter()
            
            for instance in failed_instances:
                await self.mcp_cluster.simulate_instance_failure(instance)
                result.total_messages += 1  # Count as communication attempt
            
            # For cascading failure, simulate additional failures
            if scenario['type'] == 'cascading_failure':
                # Wait and see if failure cascades
                await asyncio.sleep(2)
                
                # Check if other instances are affected
                health_status = await self.mcp_cluster.check_cluster_health()
                
                for instance_name, health in health_status.items():
                    if instance_name not in failed_instances and not health.healthy:
                        failed_instances.append(instance_name)
                        logger.warning(f"Cascading failure detected: {instance_name}")
            
            # Test cluster operations during failure
            operations_during_failure = await self._test_operations_during_failure(
                failed_instances, duration=30
            )
            
            # Wait for recovery detection and initiation
            recovery_detected = await self.mcp_cluster.wait_for_recovery_detection(timeout=10.0)
            
            if recovery_detected:
                # Wait for recovery completion
                recovery_completed = await self.mcp_cluster.wait_for_recovery_completion(timeout=30.0)
                recovery_time = time.perf_counter() - recovery_start
                
                # Test data integrity after recovery
                data_integrity = await self._verify_data_integrity_after_recovery(test_data)
                
                scenario_metrics = {
                    'failed_instances': failed_instances,
                    'failure_count': len(failed_instances),
                    'recovery_time_s': recovery_time,
                    'recovery_successful': recovery_completed,
                    'data_integrity_maintained': data_integrity,
                    'operations_during_failure': operations_during_failure
                }
                
                if recovery_completed:
                    result.successful_messages += len(failed_instances)
                else:
                    result.failed_messages += len(failed_instances)
                    result.errors.append(f"Recovery failed for {scenario['type']}")
                
                # Check recovery time target
                if recovery_time > self.targets['max_recovery_time_s']:
                    result.errors.append(
                        f"Recovery time ({recovery_time:.1f}s) exceeds target "
                        f"({self.targets['max_recovery_time_s']}s)"
                    )
                
            else:
                scenario_metrics = {
                    'failed_instances': failed_instances,
                    'failure_count': len(failed_instances),
                    'recovery_time_s': float('inf'),
                    'recovery_successful': False,
                    'data_integrity_maintained': False,
                    'operations_during_failure': operations_during_failure
                }
                
                result.failed_messages += len(failed_instances)
                result.errors.append(f"Recovery not detected for {scenario['type']}")
            
            recovery_results[scenario['type']] = scenario_metrics
            
            # Restore failed instances
            for instance in failed_instances:
                await self.mcp_cluster.restore_instance(instance)
            
            # Wait for stabilization
            await asyncio.sleep(5)
        
        result.duration = time.time() - start_time
        result.failure_recovery_metrics = recovery_results
        
        return result
    
    async def test_network_partition(self, duration: int) -> CrossInstanceScenarioResult:
        """Test network partition handling."""
        logger.info("Testing network partition handling")
        
        result = CrossInstanceScenarioResult(
            scenario_name="network_partition",
            duration=0,
            instances_tested=self.instance_names,
            total_messages=0,
            successful_messages=0,
            failed_messages=0
        )
        
        start_time = time.time()
        
        # Test partition scenarios
        partition_scenarios = [
            {'name': 'split_brain', 'partitions': 2},
            {'name': 'isolated_minority', 'partitions': 'asymmetric'},
            {'name': 'multiple_partitions', 'partitions': 3}
        ]
        
        partition_results = {}
        
        for scenario in partition_scenarios:
            if time.time() - start_time >= duration:
                break
                
            logger.info(f"Testing partition scenario: {scenario['name']}")
            
            # Create partitions
            if scenario['name'] == 'split_brain':
                mid = len(self.instance_names) // 2
                partition_a = self.instance_names[:mid]
                partition_b = self.instance_names[mid:]
                partitions = [partition_a, partition_b]
                
            elif scenario['name'] == 'isolated_minority':
                # Isolate one instance
                isolated = [self.instance_names[0]]
                majority = self.instance_names[1:]
                partitions = [isolated, majority]
                
            elif scenario['name'] == 'multiple_partitions':
                # Create 3 small partitions
                size = len(self.instance_names) // 3
                partitions = [
                    self.instance_names[:size],
                    self.instance_names[size:2*size],
                    self.instance_names[2*size:]
                ]
            
            # Store test data before partition
            test_data = self._create_knowledge_payload('medium')
            await self.mcp_cluster.store_replicated_data(test_data, replication_factor=4)
            
            # Create network partition
            partition_start = time.perf_counter()
            await self.mcp_cluster.create_network_partition(partitions)
            
            # Test operations within partitions
            partition_operations = []
            
            for i, partition in enumerate(partitions):
                if len(partition) > 1:
                    # Test intra-partition communication
                    ops = await self._test_intra_partition_operations(
                        partition, duration=20
                    )
                    partition_operations.append({
                        'partition_id': i,
                        'instances': partition,
                        'operations': ops
                    })
            
            # Heal partition
            await self.mcp_cluster.heal_network_partition()
            
            # Wait for reconciliation
            reconciliation_start = time.perf_counter()
            reconciled = await self.mcp_cluster.wait_for_reconciliation(timeout=60.0)
            total_partition_time = time.perf_counter() - partition_start
            
            # Verify data consistency
            consistency_check = await self._verify_cross_partition_consistency(test_data)
            
            scenario_metrics = {
                'partitions_created': len(partitions),
                'partition_details': [{'instances': p} for p in partitions],
                'total_partition_time_s': total_partition_time,
                'reconciliation_successful': reconciled,
                'data_consistency_maintained': consistency_check,
                'partition_operations': partition_operations
            }
            
            # Count messages (estimate based on operations)
            total_ops = sum(ops['total_operations'] for ops in 
                          [po['operations'] for po in partition_operations])
            successful_ops = sum(ops['successful_operations'] for ops in 
                               [po['operations'] for po in partition_operations])
            
            result.total_messages += total_ops
            result.successful_messages += successful_ops
            result.failed_messages += (total_ops - successful_ops)
            
            if not reconciled:
                result.errors.append(f"Reconciliation failed for {scenario['name']}")
            
            if not consistency_check:
                result.errors.append(f"Data consistency lost in {scenario['name']}")
            
            partition_results[scenario['name']] = scenario_metrics
            
            # Recovery time
            await asyncio.sleep(10)
        
        result.duration = time.time() - start_time
        result.coordination_metrics['partition_scenarios'] = partition_results
        
        return result
    
    async def _measure_sharing_operation(
        self, 
        source: str, 
        target: str, 
        knowledge: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Measure a single knowledge sharing operation."""
        try:
            start = time.perf_counter()
            sharing_result = await self.mcp_cluster.share_knowledge(source, target, knowledge)
            latency = time.perf_counter() - start
            
            return {
                'success': sharing_result.success,
                'latency': latency,
                'bytes_transferred': len(json.dumps(knowledge).encode())
            }
        except Exception as e:
            logger.error(f"Sharing operation failed: {e}")
            return None
    
    async def _test_operations_during_failure(
        self, 
        failed_instances: List[str], 
        duration: int
    ) -> Dict[str, Any]:
        """Test operations during instance failures."""
        operation_results = {
            'pattern_matching': {'attempts': 0, 'successes': 0},
            'learning_updates': {'attempts': 0, 'successes': 0},
            'knowledge_sharing': {'attempts': 0, 'successes': 0}
        }
        
        available_instances = [i for i in self.instance_names if i not in failed_instances]
        
        if len(available_instances) < 2:
            return operation_results  # Need at least 2 instances for testing
        
        end_time = time.time() + duration
        
        while time.time() < end_time:
            # Test pattern matching
            try:
                pattern = self._create_knowledge_payload('small')
                await self.mcp_cluster.match_pattern_on_instance(
                    available_instances[0], pattern
                )
                operation_results['pattern_matching']['successes'] += 1
            except Exception:
                pass
            operation_results['pattern_matching']['attempts'] += 1
            
            # Test learning updates
            try:
                interaction = {'data': 'test_learning'}
                await self.mcp_cluster.update_learning_on_instance(
                    available_instances[0], interaction
                )
                operation_results['learning_updates']['successes'] += 1
            except Exception:
                pass
            operation_results['learning_updates']['attempts'] += 1
            
            # Test knowledge sharing between available instances
            if len(available_instances) >= 2:
                try:
                    knowledge = self._create_knowledge_payload('small')
                    await self.mcp_cluster.share_knowledge(
                        available_instances[0], available_instances[1], knowledge
                    )
                    operation_results['knowledge_sharing']['successes'] += 1
                except Exception:
                    pass
                operation_results['knowledge_sharing']['attempts'] += 1
            
            await asyncio.sleep(0.5)
        
        # Calculate success rates
        for op_type, results in operation_results.items():
            if results['attempts'] > 0:
                results['success_rate'] = results['successes'] / results['attempts']
            else:
                results['success_rate'] = 0.0
        
        return operation_results
    
    async def _verify_data_integrity_after_recovery(
        self, 
        test_data: Dict[str, Any]
    ) -> bool:
        """Verify data integrity after failure recovery."""
        try:
            # Retrieve test data from all available instances
            retrieved_data = {}
            
            for instance in self.instance_names:
                try:
                    data = await self.mcp_cluster.retrieve_data_from_instance(
                        instance, test_data['id']
                    )
                    retrieved_data[instance] = data
                except Exception as e:
                    logger.warning(f"Could not retrieve data from {instance}: {e}")
            
            # Check consistency
            if not retrieved_data:
                return False
            
            # Compare all retrieved versions
            reference_data = next(iter(retrieved_data.values()))
            
            for instance, data in retrieved_data.items():
                if data != reference_data:
                    logger.error(f"Data inconsistency detected on {instance}")
                    return False
            
            # Verify against original
            if reference_data != test_data:
                logger.error("Retrieved data doesn't match original")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Data integrity verification failed: {e}")
            return False
    
    async def _test_intra_partition_operations(
        self, 
        partition_instances: List[str], 
        duration: int
    ) -> Dict[str, Any]:
        """Test operations within a network partition."""
        if len(partition_instances) < 2:
            return {
                'total_operations': 0,
                'successful_operations': 0,
                'success_rate': 0.0
            }
        
        operations = 0
        successes = 0
        end_time = time.time() + duration
        
        while time.time() < end_time:
            # Test communication within partition
            source = np.random.choice(partition_instances)
            target = np.random.choice([i for i in partition_instances if i != source])
            
            try:
                knowledge = self._create_knowledge_payload('small')
                result = await self.mcp_cluster.share_knowledge(source, target, knowledge)
                
                operations += 1
                if result.success:
                    successes += 1
                    
            except Exception:
                operations += 1
            
            await asyncio.sleep(0.1)
        
        return {
            'total_operations': operations,
            'successful_operations': successes,
            'success_rate': successes / operations if operations > 0 else 0.0
        }
    
    async def _verify_cross_partition_consistency(
        self, 
        test_data: Dict[str, Any]
    ) -> bool:
        """Verify data consistency after partition healing."""
        try:
            # Wait for stabilization
            await asyncio.sleep(5)
            
            # Check that all instances have consistent view
            return await self._verify_data_integrity_after_recovery(test_data)
            
        except Exception as e:
            logger.error(f"Cross-partition consistency check failed: {e}")
            return False
    
    async def _verify_cluster_health(self):
        """Verify all instances in cluster are healthy."""
        for instance in self.instance_names:
            health = await self.mcp_cluster.check_instance_health(instance)
            if not health.healthy:
                raise RuntimeError(f"Instance {instance} is not healthy before test")
    
    def _create_knowledge_payload(self, size: str) -> Dict[str, Any]:
        """Create knowledge payload of specified size."""
        sizes = {
            'small': 100,    # ~1KB
            'medium': 1000,  # ~10KB
            'large': 10000   # ~100KB
        }
        
        data_size = sizes.get(size, 100)
        
        return {
            'id': f"knowledge_{time.time()}_{np.random.randint(1000000)}",
            'type': 'stress_test_data',
            'features': np.random.rand(data_size).tolist(),
            'metadata': {
                'size': size,
                'timestamp': time.time(),
                'source': 'cross_instance_stress_test'
            }
        }
    
    def _generate_cross_instance_summary(
        self, 
        results: Dict[str, CrossInstanceScenarioResult]
    ) -> Dict[str, Any]:
        """Generate summary of cross-instance stress test results."""
        summary = {
            'total_scenarios': len([r for r in results.values() if isinstance(r, CrossInstanceScenarioResult)]),
            'overall_message_success_rate': 0.0,
            'performance_targets_met': 0,
            'critical_issues': [],
            'recommendations': []
        }
        
        # Aggregate metrics
        total_messages = 0
        total_successful = 0
        
        for name, result in results.items():
            if isinstance(result, CrossInstanceScenarioResult):
                total_messages += result.total_messages
                total_successful += result.successful_messages
        
        if total_messages > 0:
            summary['overall_message_success_rate'] = total_successful / total_messages
        
        # Check performance targets
        targets_met = 0
        total_targets = len(self.targets)
        
        # Check latency targets
        if 'high_frequency_sharing' in results:
            hfs_result = results['high_frequency_sharing']
            if hfs_result.communication_metrics.get('p99_latency_ms', float('inf')) <= self.targets['max_latency_ms']:
                targets_met += 1
        
        # Check consensus targets
        if 'consensus_under_load' in results:
            consensus_result = results['consensus_under_load']
            if consensus_result.coordination_metrics.get('overall_consensus_success_rate', 0) >= self.targets['min_consensus_rate']:
                targets_met += 1
        
        # Check recovery targets
        if 'failure_recovery' in results:
            recovery_result = results['failure_recovery']
            recovery_times = [
                metrics.get('recovery_time_s', float('inf'))
                for metrics in recovery_result.failure_recovery_metrics.values()
                if metrics.get('recovery_successful', False)
            ]
            if recovery_times and max(recovery_times) <= self.targets['max_recovery_time_s']:
                targets_met += 1
        
        summary['performance_targets_met'] = targets_met
        summary['target_achievement_rate'] = targets_met / total_targets if total_targets > 0 else 0
        
        # Identify critical issues
        for name, result in results.items():
            if isinstance(result, CrossInstanceScenarioResult):
                if result.message_success_rate < 0.9:
                    summary['critical_issues'].append(
                        f"{name}: Low success rate ({result.message_success_rate:.2f})"
                    )
                
                if len(result.errors) > 0:
                    summary['critical_issues'].extend([
                        f"{name}: {error}" for error in result.errors[:3]  # Limit to 3 errors
                    ])
        
        # Generate recommendations
        if summary['overall_message_success_rate'] < 0.95:
            summary['recommendations'].append(
                "Overall message success rate is low - investigate network reliability"
            )
        
        if summary['target_achievement_rate'] < 0.8:
            summary['recommendations'].append(
                "Performance targets not met - consider system optimization"
            )
        
        if 'failure_recovery' in results:
            recovery_result = results['failure_recovery']
            failed_recoveries = [
                scenario for scenario, metrics in recovery_result.failure_recovery_metrics.items()
                if not metrics.get('recovery_successful', False)
            ]
            if failed_recoveries:
                summary['recommendations'].append(
                    f"Recovery failures in scenarios: {', '.join(failed_recoveries)} - "
                    "implement more robust recovery mechanisms"
                )
        
        return summary