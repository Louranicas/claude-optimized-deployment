"""
Cross-instance communication benchmarks for MCP Learning System.

Tests knowledge sharing, synchronization, and coordination between instances.
"""

import asyncio
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
import numpy as np
import logging
from collections import defaultdict
import hashlib
import json

from mcp_learning_system.core import LearningMCPCluster

logger = logging.getLogger(__name__)


@dataclass
class CommunicationMetrics:
    """Metrics for cross-instance communication."""
    total_messages: int = 0
    successful_messages: int = 0
    failed_messages: int = 0
    total_bytes: int = 0
    latencies: List[float] = field(default_factory=list)
    
    @property
    def success_rate(self) -> float:
        """Calculate message success rate."""
        if self.total_messages == 0:
            return 0.0
        return self.successful_messages / self.total_messages
    
    @property
    def avg_latency(self) -> float:
        """Calculate average latency."""
        if not self.latencies:
            return 0.0
        return np.mean(self.latencies)
    
    @property
    def p95_latency(self) -> float:
        """Calculate 95th percentile latency."""
        if not self.latencies:
            return 0.0
        return np.percentile(self.latencies, 95)
    
    @property
    def p99_latency(self) -> float:
        """Calculate 99th percentile latency."""
        if not self.latencies:
            return 0.0
        return np.percentile(self.latencies, 99)
    
    @property
    def throughput_mbps(self) -> float:
        """Calculate throughput in Mbps."""
        if not self.latencies:
            return 0.0
        total_time = sum(self.latencies)
        if total_time == 0:
            return 0.0
        return (self.total_bytes * 8) / (total_time * 1_000_000)  # Convert to Mbps


class CrossInstanceBenchmark:
    """Benchmarks for cross-instance communication and coordination."""
    
    def __init__(self, mcp_cluster: Optional[LearningMCPCluster] = None):
        """Initialize cross-instance benchmark suite."""
        self.mcp_cluster = mcp_cluster or LearningMCPCluster()
        
        # Instance configurations
        self.instance_names = ['development', 'devops', 'quality', 'bash_god']
        
    async def run_cross_instance_benchmarks(self) -> Dict[str, Any]:
        """Run complete cross-instance benchmark suite."""
        logger.info("Starting cross-instance benchmarks")
        
        results = {}
        
        try:
            # Initialize cluster
            await self.mcp_cluster.initialize()
            
            # Basic connectivity test
            results['connectivity'] = await self.benchmark_connectivity()
            
            # Knowledge sharing benchmarks
            results['knowledge_sharing'] = await self.benchmark_knowledge_sharing()
            
            # Synchronization benchmarks
            results['synchronization'] = await self.benchmark_synchronization()
            
            # Broadcast performance
            results['broadcast'] = await self.benchmark_broadcast()
            
            # Consensus benchmarks
            results['consensus'] = await self.benchmark_consensus()
            
            # Failure recovery
            results['failure_recovery'] = await self.benchmark_failure_recovery()
            
            # Network partition handling
            results['partition_handling'] = await self.benchmark_partition_handling()
            
            # Generate summary
            results['summary'] = self._generate_summary(results)
            
        finally:
            await self.mcp_cluster.shutdown()
            
        return results
    
    async def benchmark_connectivity(self) -> Dict[str, Any]:
        """Test basic connectivity between all instances."""
        logger.info("Benchmarking instance connectivity")
        
        results = {
            'connectivity_matrix': {},
            'avg_ping_latency': {},
            'total_tests': 0,
            'successful_connections': 0
        }
        
        # Test connectivity between all pairs
        for source in self.instance_names:
            results['connectivity_matrix'][source] = {}
            
            for target in self.instance_names:
                if source == target:
                    continue
                
                # Ping test
                latencies = []
                success_count = 0
                
                for _ in range(100):  # 100 pings
                    start = time.perf_counter()
                    success = await self.mcp_cluster.ping(source, target)
                    latency = time.perf_counter() - start
                    
                    if success:
                        latencies.append(latency)
                        success_count += 1
                    
                    results['total_tests'] += 1
                
                # Record results
                results['connectivity_matrix'][source][target] = {
                    'success_rate': success_count / 100,
                    'avg_latency_ms': np.mean(latencies) * 1000 if latencies else None,
                    'min_latency_ms': np.min(latencies) * 1000 if latencies else None,
                    'max_latency_ms': np.max(latencies) * 1000 if latencies else None
                }
                
                results['successful_connections'] += success_count
        
        # Calculate average ping latency
        all_latencies = []
        for source_data in results['connectivity_matrix'].values():
            for target_data in source_data.values():
                if target_data['avg_latency_ms'] is not None:
                    all_latencies.append(target_data['avg_latency_ms'])
        
        if all_latencies:
            results['avg_ping_latency'] = {
                'mean_ms': np.mean(all_latencies),
                'median_ms': np.median(all_latencies),
                'p95_ms': np.percentile(all_latencies, 95),
                'p99_ms': np.percentile(all_latencies, 99)
            }
        
        return results
    
    async def benchmark_knowledge_sharing(self) -> Dict[str, Any]:
        """Benchmark knowledge sharing between instances."""
        logger.info("Benchmarking knowledge sharing")
        
        results = {
            'point_to_point': await self._benchmark_point_to_point_sharing(),
            'many_to_one': await self._benchmark_many_to_one_sharing(),
            'one_to_many': await self._benchmark_one_to_many_sharing(),
            'all_to_all': await self._benchmark_all_to_all_sharing()
        }
        
        return results
    
    async def _benchmark_point_to_point_sharing(self) -> Dict[str, Any]:
        """Benchmark point-to-point knowledge sharing."""
        metrics = CommunicationMetrics()
        test_duration = 60  # seconds
        
        start_time = time.time()
        
        while time.time() - start_time < test_duration:
            # Random source and target
            source = np.random.choice(self.instance_names)
            target = np.random.choice([i for i in self.instance_names if i != source])
            
            # Create knowledge payload
            knowledge = self._create_knowledge_payload(size='medium')
            payload_size = len(json.dumps(knowledge).encode())
            
            # Share knowledge
            start = time.perf_counter()
            try:
                result = await self.mcp_cluster.share_knowledge(source, target, knowledge)
                latency = time.perf_counter() - start
                
                metrics.total_messages += 1
                metrics.total_bytes += payload_size
                
                if result.success:
                    metrics.successful_messages += 1
                    metrics.latencies.append(latency)
                else:
                    metrics.failed_messages += 1
                    
            except Exception as e:
                logger.error(f"Sharing failed: {e}")
                metrics.failed_messages += 1
                metrics.total_messages += 1
        
        return {
            'duration': time.time() - start_time,
            'total_messages': metrics.total_messages,
            'success_rate': metrics.success_rate,
            'avg_latency_ms': metrics.avg_latency * 1000,
            'p95_latency_ms': metrics.p95_latency * 1000,
            'p99_latency_ms': metrics.p99_latency * 1000,
            'throughput_mbps': metrics.throughput_mbps,
            'messages_per_second': metrics.total_messages / (time.time() - start_time)
        }
    
    async def _benchmark_many_to_one_sharing(self) -> Dict[str, Any]:
        """Benchmark many instances sharing to one."""
        target = 'development'  # Central collector
        sources = [i for i in self.instance_names if i != target]
        
        metrics = CommunicationMetrics()
        test_duration = 60  # seconds
        
        async def source_worker(source: str):
            """Worker that continuously shares from source."""
            while time.time() - start_time < test_duration:
                knowledge = self._create_knowledge_payload(size='small')
                payload_size = len(json.dumps(knowledge).encode())
                
                start = time.perf_counter()
                try:
                    result = await self.mcp_cluster.share_knowledge(source, target, knowledge)
                    latency = time.perf_counter() - start
                    
                    if result.success:
                        metrics.successful_messages += 1
                        metrics.latencies.append(latency)
                    else:
                        metrics.failed_messages += 1
                    
                    metrics.total_messages += 1
                    metrics.total_bytes += payload_size
                    
                except Exception as e:
                    logger.error(f"Many-to-one sharing failed: {e}")
                    metrics.failed_messages += 1
                    metrics.total_messages += 1
                
                await asyncio.sleep(0.01)  # Small delay
        
        start_time = time.time()
        
        # Run concurrent sources
        tasks = [asyncio.create_task(source_worker(source)) for source in sources]
        await asyncio.gather(*tasks)
        
        duration = time.time() - start_time
        
        return {
            'target': target,
            'sources': sources,
            'duration': duration,
            'total_messages': metrics.total_messages,
            'success_rate': metrics.success_rate,
            'avg_latency_ms': metrics.avg_latency * 1000,
            'p95_latency_ms': metrics.p95_latency * 1000,
            'p99_latency_ms': metrics.p99_latency * 1000,
            'throughput_mbps': metrics.throughput_mbps,
            'messages_per_second': metrics.total_messages / duration
        }
    
    async def _benchmark_one_to_many_sharing(self) -> Dict[str, Any]:
        """Benchmark one instance broadcasting to many."""
        source = 'bash_god'  # Master broadcaster
        targets = [i for i in self.instance_names if i != source]
        
        metrics = CommunicationMetrics()
        test_duration = 60  # seconds
        
        start_time = time.time()
        
        while time.time() - start_time < test_duration:
            knowledge = self._create_knowledge_payload(size='medium')
            payload_size = len(json.dumps(knowledge).encode())
            
            # Broadcast to all targets
            start = time.perf_counter()
            
            tasks = []
            for target in targets:
                task = asyncio.create_task(
                    self.mcp_cluster.share_knowledge(source, target, knowledge)
                )
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            latency = time.perf_counter() - start
            
            # Count successes
            successful = sum(1 for r in results if not isinstance(r, Exception) and r.success)
            
            metrics.total_messages += len(targets)
            metrics.successful_messages += successful
            metrics.failed_messages += len(targets) - successful
            metrics.total_bytes += payload_size * len(targets)
            metrics.latencies.append(latency)  # Total broadcast time
            
            await asyncio.sleep(0.1)  # Rate limiting
        
        duration = time.time() - start_time
        
        return {
            'source': source,
            'targets': targets,
            'duration': duration,
            'total_broadcasts': len(metrics.latencies),
            'total_messages': metrics.total_messages,
            'success_rate': metrics.success_rate,
            'avg_broadcast_time_ms': metrics.avg_latency * 1000,
            'p95_broadcast_time_ms': metrics.p95_latency * 1000,
            'p99_broadcast_time_ms': metrics.p99_latency * 1000,
            'effective_throughput_mbps': metrics.throughput_mbps,
            'broadcasts_per_second': len(metrics.latencies) / duration
        }
    
    async def _benchmark_all_to_all_sharing(self) -> Dict[str, Any]:
        """Benchmark all instances sharing with all others."""
        metrics = CommunicationMetrics()
        test_duration = 30  # Shorter duration due to high load
        
        async def instance_worker(instance: str):
            """Worker for each instance."""
            while time.time() - start_time < test_duration:
                # Share with all other instances
                targets = [i for i in self.instance_names if i != instance]
                knowledge = self._create_knowledge_payload(size='small')
                payload_size = len(json.dumps(knowledge).encode())
                
                for target in targets:
                    start = time.perf_counter()
                    try:
                        result = await self.mcp_cluster.share_knowledge(
                            instance, target, knowledge
                        )
                        latency = time.perf_counter() - start
                        
                        if result.success:
                            metrics.successful_messages += 1
                            metrics.latencies.append(latency)
                        else:
                            metrics.failed_messages += 1
                        
                        metrics.total_messages += 1
                        metrics.total_bytes += payload_size
                        
                    except Exception as e:
                        logger.error(f"All-to-all sharing failed: {e}")
                        metrics.failed_messages += 1
                        metrics.total_messages += 1
                
                await asyncio.sleep(0.1)  # Rate limiting
        
        start_time = time.time()
        
        # Run all instances concurrently
        tasks = [
            asyncio.create_task(instance_worker(instance))
            for instance in self.instance_names
        ]
        await asyncio.gather(*tasks)
        
        duration = time.time() - start_time
        
        return {
            'instances': self.instance_names,
            'duration': duration,
            'total_messages': metrics.total_messages,
            'success_rate': metrics.success_rate,
            'avg_latency_ms': metrics.avg_latency * 1000,
            'p95_latency_ms': metrics.p95_latency * 1000,
            'p99_latency_ms': metrics.p99_latency * 1000,
            'aggregate_throughput_mbps': metrics.throughput_mbps,
            'messages_per_second': metrics.total_messages / duration
        }
    
    async def benchmark_synchronization(self) -> Dict[str, Any]:
        """Benchmark synchronization mechanisms."""
        logger.info("Benchmarking synchronization")
        
        results = {
            'barrier_sync': await self._benchmark_barrier_sync(),
            'distributed_lock': await self._benchmark_distributed_lock(),
            'consensus_sync': await self._benchmark_consensus_sync()
        }
        
        return results
    
    async def _benchmark_barrier_sync(self) -> Dict[str, Any]:
        """Benchmark barrier synchronization."""
        iterations = 100
        sync_times = []
        
        for i in range(iterations):
            start = time.perf_counter()
            
            # All instances must reach barrier
            await self.mcp_cluster.barrier_sync('test_barrier', self.instance_names)
            
            sync_time = time.perf_counter() - start
            sync_times.append(sync_time)
        
        return {
            'iterations': iterations,
            'avg_sync_time_ms': np.mean(sync_times) * 1000,
            'min_sync_time_ms': np.min(sync_times) * 1000,
            'max_sync_time_ms': np.max(sync_times) * 1000,
            'p95_sync_time_ms': np.percentile(sync_times, 95) * 1000,
            'p99_sync_time_ms': np.percentile(sync_times, 99) * 1000
        }
    
    async def _benchmark_distributed_lock(self) -> Dict[str, Any]:
        """Benchmark distributed lock performance."""
        lock_name = 'benchmark_lock'
        iterations_per_instance = 25
        
        lock_acquisition_times = []
        lock_hold_times = []
        contentions = 0
        
        async def lock_worker(instance: str):
            nonlocal contentions
            
            for _ in range(iterations_per_instance):
                # Try to acquire lock
                start_acquire = time.perf_counter()
                
                acquired = False
                retries = 0
                while not acquired and retries < 10:
                    acquired = await self.mcp_cluster.acquire_lock(
                        lock_name, instance, timeout=1.0
                    )
                    if not acquired:
                        contentions += 1
                        await asyncio.sleep(0.01)
                    retries += 1
                
                if acquired:
                    acquire_time = time.perf_counter() - start_acquire
                    lock_acquisition_times.append(acquire_time)
                    
                    # Hold lock briefly
                    hold_start = time.perf_counter()
                    await asyncio.sleep(0.01)  # Simulate work
                    hold_time = time.perf_counter() - hold_start
                    lock_hold_times.append(hold_time)
                    
                    # Release lock
                    await self.mcp_cluster.release_lock(lock_name, instance)
        
        # Run concurrent lock workers
        start_time = time.time()
        tasks = [
            asyncio.create_task(lock_worker(instance))
            for instance in self.instance_names
        ]
        await asyncio.gather(*tasks)
        duration = time.time() - start_time
        
        total_acquisitions = len(lock_acquisition_times)
        
        return {
            'duration': duration,
            'total_acquisitions': total_acquisitions,
            'contentions': contentions,
            'contention_rate': contentions / (total_acquisitions + contentions),
            'avg_acquisition_time_ms': np.mean(lock_acquisition_times) * 1000,
            'max_acquisition_time_ms': np.max(lock_acquisition_times) * 1000,
            'avg_hold_time_ms': np.mean(lock_hold_times) * 1000,
            'throughput_ops_per_sec': total_acquisitions / duration
        }
    
    async def _benchmark_consensus_sync(self) -> Dict[str, Any]:
        """Benchmark consensus synchronization."""
        iterations = 50
        consensus_times = []
        consensus_sizes = []
        
        for i in range(iterations):
            # Create proposal
            proposal = {
                'id': f'proposal_{i}',
                'value': np.random.rand(100).tolist(),
                'timestamp': time.time()
            }
            
            start = time.perf_counter()
            
            # Reach consensus
            result = await self.mcp_cluster.reach_consensus(
                proposal, 
                participants=self.instance_names,
                timeout=5.0
            )
            
            consensus_time = time.perf_counter() - start
            
            if result.success:
                consensus_times.append(consensus_time)
                consensus_sizes.append(len(result.participants))
        
        success_rate = len(consensus_times) / iterations
        
        return {
            'iterations': iterations,
            'success_rate': success_rate,
            'avg_consensus_time_ms': np.mean(consensus_times) * 1000 if consensus_times else 0,
            'max_consensus_time_ms': np.max(consensus_times) * 1000 if consensus_times else 0,
            'p95_consensus_time_ms': np.percentile(consensus_times, 95) * 1000 if consensus_times else 0,
            'p99_consensus_time_ms': np.percentile(consensus_times, 99) * 1000 if consensus_times else 0,
            'avg_consensus_size': np.mean(consensus_sizes) if consensus_sizes else 0
        }
    
    async def benchmark_broadcast(self) -> Dict[str, Any]:
        """Benchmark broadcast communication patterns."""
        logger.info("Benchmarking broadcast performance")
        
        results = {
            'small_payload': await self._benchmark_broadcast_size('small'),
            'medium_payload': await self._benchmark_broadcast_size('medium'),
            'large_payload': await self._benchmark_broadcast_size('large')
        }
        
        return results
    
    async def _benchmark_broadcast_size(self, size: str) -> Dict[str, Any]:
        """Benchmark broadcast with specific payload size."""
        iterations = 100
        broadcast_times = []
        delivery_rates = []
        
        for _ in range(iterations):
            # Create payload
            payload = self._create_knowledge_payload(size)
            
            start = time.perf_counter()
            
            # Broadcast from random source
            source = np.random.choice(self.instance_names)
            result = await self.mcp_cluster.broadcast(source, payload)
            
            broadcast_time = time.perf_counter() - start
            broadcast_times.append(broadcast_time)
            
            # Calculate delivery rate
            successful_deliveries = sum(1 for r in result.deliveries if r.success)
            total_targets = len(self.instance_names) - 1  # Exclude source
            delivery_rate = successful_deliveries / total_targets if total_targets > 0 else 0
            delivery_rates.append(delivery_rate)
        
        payload_size = len(json.dumps(self._create_knowledge_payload(size)).encode())
        
        return {
            'payload_size_bytes': payload_size,
            'iterations': iterations,
            'avg_broadcast_time_ms': np.mean(broadcast_times) * 1000,
            'p95_broadcast_time_ms': np.percentile(broadcast_times, 95) * 1000,
            'p99_broadcast_time_ms': np.percentile(broadcast_times, 99) * 1000,
            'avg_delivery_rate': np.mean(delivery_rates),
            'min_delivery_rate': np.min(delivery_rates),
            'throughput_mbps': (payload_size * 8 * iterations) / (sum(broadcast_times) * 1_000_000)
        }
    
    async def benchmark_consensus(self) -> Dict[str, Any]:
        """Benchmark consensus algorithms."""
        logger.info("Benchmarking consensus mechanisms")
        
        results = {
            'simple_majority': await self._benchmark_simple_majority(),
            'byzantine_fault_tolerant': await self._benchmark_bft(),
            'raft_consensus': await self._benchmark_raft()
        }
        
        return results
    
    async def _benchmark_simple_majority(self) -> Dict[str, Any]:
        """Benchmark simple majority consensus."""
        iterations = 100
        consensus_times = []
        success_count = 0
        
        for i in range(iterations):
            # Create decision
            decision = {
                'id': f'decision_{i}',
                'options': ['A', 'B', 'C'],
                'deadline': time.time() + 5.0
            }
            
            start = time.perf_counter()
            
            # Get consensus
            result = await self.mcp_cluster.simple_majority_vote(
                decision,
                voters=self.instance_names
            )
            
            consensus_time = time.perf_counter() - start
            
            if result.consensus_reached:
                consensus_times.append(consensus_time)
                success_count += 1
        
        return {
            'iterations': iterations,
            'success_rate': success_count / iterations,
            'avg_consensus_time_ms': np.mean(consensus_times) * 1000 if consensus_times else 0,
            'p95_consensus_time_ms': np.percentile(consensus_times, 95) * 1000 if consensus_times else 0,
            'p99_consensus_time_ms': np.percentile(consensus_times, 99) * 1000 if consensus_times else 0
        }
    
    async def _benchmark_bft(self) -> Dict[str, Any]:
        """Benchmark Byzantine Fault Tolerant consensus."""
        iterations = 50  # Fewer due to complexity
        consensus_times = []
        success_count = 0
        
        # Simulate Byzantine node
        byzantine_node = np.random.choice(self.instance_names)
        
        for i in range(iterations):
            # Create transaction
            transaction = {
                'id': f'tx_{i}',
                'data': self._create_knowledge_payload('small'),
                'timestamp': time.time()
            }
            
            start = time.perf_counter()
            
            # Run BFT consensus
            result = await self.mcp_cluster.bft_consensus(
                transaction,
                participants=self.instance_names,
                byzantine_nodes=[byzantine_node],
                timeout=10.0
            )
            
            consensus_time = time.perf_counter() - start
            
            if result.success:
                consensus_times.append(consensus_time)
                success_count += 1
        
        return {
            'iterations': iterations,
            'success_rate': success_count / iterations,
            'byzantine_nodes': 1,
            'total_nodes': len(self.instance_names),
            'avg_consensus_time_ms': np.mean(consensus_times) * 1000 if consensus_times else 0,
            'max_consensus_time_ms': np.max(consensus_times) * 1000 if consensus_times else 0,
            'fault_tolerance': (len(self.instance_names) - 1) // 3  # BFT tolerance
        }
    
    async def _benchmark_raft(self) -> Dict[str, Any]:
        """Benchmark Raft consensus algorithm."""
        iterations = 100
        
        # Leader election
        election_times = []
        for _ in range(10):  # 10 elections
            start = time.perf_counter()
            leader = await self.mcp_cluster.elect_leader(self.instance_names)
            election_time = time.perf_counter() - start
            election_times.append(election_time)
        
        # Log replication
        replication_times = []
        success_count = 0
        
        for i in range(iterations):
            # Create log entry
            entry = {
                'index': i,
                'term': 1,
                'command': f'command_{i}',
                'data': self._create_knowledge_payload('small')
            }
            
            start = time.perf_counter()
            
            # Replicate entry
            result = await self.mcp_cluster.replicate_log_entry(entry)
            
            replication_time = time.perf_counter() - start
            
            if result.success:
                replication_times.append(replication_time)
                success_count += 1
        
        return {
            'leader_elections': len(election_times),
            'avg_election_time_ms': np.mean(election_times) * 1000,
            'log_replications': iterations,
            'replication_success_rate': success_count / iterations,
            'avg_replication_time_ms': np.mean(replication_times) * 1000 if replication_times else 0,
            'p95_replication_time_ms': np.percentile(replication_times, 95) * 1000 if replication_times else 0,
            'p99_replication_time_ms': np.percentile(replication_times, 99) * 1000 if replication_times else 0
        }
    
    async def benchmark_failure_recovery(self) -> Dict[str, Any]:
        """Benchmark failure recovery mechanisms."""
        logger.info("Benchmarking failure recovery")
        
        results = {
            'single_instance_failure': await self._benchmark_single_failure(),
            'multiple_instance_failure': await self._benchmark_multiple_failure(),
            'cascading_failure': await self._benchmark_cascading_failure()
        }
        
        return results
    
    async def _benchmark_single_failure(self) -> Dict[str, Any]:
        """Benchmark recovery from single instance failure."""
        iterations = 20
        recovery_times = []
        data_loss = []
        
        for _ in range(iterations):
            # Select random instance to fail
            failed_instance = np.random.choice(self.instance_names)
            
            # Store test data
            test_data = self._create_knowledge_payload('medium')
            await self.mcp_cluster.store_replicated(test_data, replication_factor=3)
            
            # Simulate failure
            start = time.perf_counter()
            await self.mcp_cluster.simulate_instance_failure(failed_instance)
            
            # Wait for detection and recovery
            recovered = await self.mcp_cluster.wait_for_recovery(timeout=30.0)
            recovery_time = time.perf_counter() - start
            
            if recovered:
                recovery_times.append(recovery_time)
                
                # Check data integrity
                retrieved = await self.mcp_cluster.retrieve_replicated(test_data['id'])
                if retrieved != test_data:
                    data_loss.append(1)
                else:
                    data_loss.append(0)
            
            # Restore instance
            await self.mcp_cluster.restore_instance(failed_instance)
            await asyncio.sleep(2)  # Stabilization time
        
        return {
            'iterations': iterations,
            'success_rate': len(recovery_times) / iterations,
            'avg_recovery_time_ms': np.mean(recovery_times) * 1000 if recovery_times else 0,
            'max_recovery_time_ms': np.max(recovery_times) * 1000 if recovery_times else 0,
            'data_loss_rate': np.mean(data_loss) if data_loss else 0
        }
    
    async def _benchmark_multiple_failure(self) -> Dict[str, Any]:
        """Benchmark recovery from multiple simultaneous failures."""
        iterations = 10
        recovery_times = []
        partial_recovery = []
        
        for _ in range(iterations):
            # Fail 2 instances simultaneously
            num_failures = 2
            failed_instances = np.random.choice(
                self.instance_names, 
                num_failures, 
                replace=False
            ).tolist()
            
            # Store test data with higher replication
            test_data = self._create_knowledge_payload('medium')
            await self.mcp_cluster.store_replicated(test_data, replication_factor=4)
            
            # Simulate failures
            start = time.perf_counter()
            
            for instance in failed_instances:
                await self.mcp_cluster.simulate_instance_failure(instance)
            
            # Wait for recovery
            recovered = await self.mcp_cluster.wait_for_recovery(timeout=60.0)
            recovery_time = time.perf_counter() - start
            
            if recovered:
                recovery_times.append(recovery_time)
                
                # Check cluster health
                health = await self.mcp_cluster.check_health()
                if health.available_instances < len(self.instance_names):
                    partial_recovery.append(1)
                else:
                    partial_recovery.append(0)
            
            # Restore instances
            for instance in failed_instances:
                await self.mcp_cluster.restore_instance(instance)
            await asyncio.sleep(5)  # Longer stabilization
        
        return {
            'iterations': iterations,
            'failures_per_iteration': num_failures,
            'success_rate': len(recovery_times) / iterations,
            'avg_recovery_time_ms': np.mean(recovery_times) * 1000 if recovery_times else 0,
            'max_recovery_time_ms': np.max(recovery_times) * 1000 if recovery_times else 0,
            'partial_recovery_rate': np.mean(partial_recovery) if partial_recovery else 0
        }
    
    async def _benchmark_cascading_failure(self) -> Dict[str, Any]:
        """Benchmark recovery from cascading failures."""
        iterations = 5  # Fewer due to complexity
        recovery_times = []
        cascade_depths = []
        
        for _ in range(iterations):
            # Start with one failure
            initial_failure = np.random.choice(self.instance_names)
            cascade_depth = 1
            
            start = time.perf_counter()
            
            # Initial failure
            await self.mcp_cluster.simulate_instance_failure(initial_failure)
            failed_instances = [initial_failure]
            
            # Simulate cascade
            while cascade_depth < 3 and len(failed_instances) < len(self.instance_names) - 1:
                # Failure causes another failure
                remaining = [i for i in self.instance_names if i not in failed_instances]
                if remaining:
                    next_failure = np.random.choice(remaining)
                    await asyncio.sleep(1)  # Cascade delay
                    await self.mcp_cluster.simulate_instance_failure(next_failure)
                    failed_instances.append(next_failure)
                    cascade_depth += 1
            
            cascade_depths.append(cascade_depth)
            
            # Wait for recovery
            recovered = await self.mcp_cluster.wait_for_recovery(timeout=90.0)
            recovery_time = time.perf_counter() - start
            
            if recovered:
                recovery_times.append(recovery_time)
            
            # Restore all instances
            for instance in failed_instances:
                await self.mcp_cluster.restore_instance(instance)
            await asyncio.sleep(10)  # Extended stabilization
        
        return {
            'iterations': iterations,
            'avg_cascade_depth': np.mean(cascade_depths),
            'max_cascade_depth': np.max(cascade_depths),
            'success_rate': len(recovery_times) / iterations,
            'avg_recovery_time_ms': np.mean(recovery_times) * 1000 if recovery_times else 0,
            'max_recovery_time_ms': np.max(recovery_times) * 1000 if recovery_times else 0
        }
    
    async def benchmark_partition_handling(self) -> Dict[str, Any]:
        """Benchmark network partition handling."""
        logger.info("Benchmarking partition handling")
        
        results = {
            'split_brain': await self._benchmark_split_brain(),
            'asymmetric_partition': await self._benchmark_asymmetric_partition(),
            'healing_partition': await self._benchmark_partition_healing()
        }
        
        return results
    
    async def _benchmark_split_brain(self) -> Dict[str, Any]:
        """Benchmark split-brain scenario handling."""
        iterations = 10
        resolution_times = []
        data_consistency = []
        
        for _ in range(iterations):
            # Create two partitions
            partition_size = len(self.instance_names) // 2
            partition_a = self.instance_names[:partition_size]
            partition_b = self.instance_names[partition_size:]
            
            # Store test data before partition
            test_data = self._create_knowledge_payload('medium')
            await self.mcp_cluster.store_replicated(test_data, replication_factor=4)
            
            # Create partition
            start = time.perf_counter()
            await self.mcp_cluster.create_network_partition(partition_a, partition_b)
            
            # Both partitions try to update
            update_a = {'partition': 'A', 'timestamp': time.time()}
            update_b = {'partition': 'B', 'timestamp': time.time()}
            
            await asyncio.gather(
                self.mcp_cluster.update_in_partition(test_data['id'], update_a, partition_a),
                self.mcp_cluster.update_in_partition(test_data['id'], update_b, partition_b),
                return_exceptions=True
            )
            
            # Heal partition
            await self.mcp_cluster.heal_network_partition()
            
            # Wait for resolution
            resolved = await self.mcp_cluster.wait_for_consistency(timeout=30.0)
            resolution_time = time.perf_counter() - start
            
            if resolved:
                resolution_times.append(resolution_time)
                
                # Check final state
                final_data = await self.mcp_cluster.retrieve_replicated(test_data['id'])
                
                # Verify consistency
                is_consistent = await self.mcp_cluster.verify_consistency(test_data['id'])
                data_consistency.append(1 if is_consistent else 0)
        
        return {
            'iterations': iterations,
            'partitions_per_test': 2,
            'resolution_success_rate': len(resolution_times) / iterations,
            'avg_resolution_time_ms': np.mean(resolution_times) * 1000 if resolution_times else 0,
            'max_resolution_time_ms': np.max(resolution_times) * 1000 if resolution_times else 0,
            'data_consistency_rate': np.mean(data_consistency) if data_consistency else 0
        }
    
    async def _benchmark_asymmetric_partition(self) -> Dict[str, Any]:
        """Benchmark asymmetric network partition."""
        iterations = 10
        handling_times = []
        
        for _ in range(iterations):
            # Create asymmetric partition (one instance isolated)
            isolated = np.random.choice(self.instance_names)
            others = [i for i in self.instance_names if i != isolated]
            
            start = time.perf_counter()
            
            # Isolate instance
            await self.mcp_cluster.isolate_instance(isolated)
            
            # Continue operations in main partition
            for _ in range(10):
                knowledge = self._create_knowledge_payload('small')
                await self.mcp_cluster.share_knowledge(
                    others[0], others[1], knowledge
                )
            
            # Detect and handle isolation
            handled = await self.mcp_cluster.handle_isolation(timeout=20.0)
            handling_time = time.perf_counter() - start
            
            if handled:
                handling_times.append(handling_time)
            
            # Restore connectivity
            await self.mcp_cluster.restore_instance_connectivity(isolated)
            await asyncio.sleep(2)
        
        return {
            'iterations': iterations,
            'isolation_type': 'single_instance',
            'handling_success_rate': len(handling_times) / iterations,
            'avg_handling_time_ms': np.mean(handling_times) * 1000 if handling_times else 0,
            'max_handling_time_ms': np.max(handling_times) * 1000 if handling_times else 0
        }
    
    async def _benchmark_partition_healing(self) -> Dict[str, Any]:
        """Benchmark partition healing and reconciliation."""
        iterations = 10
        healing_times = []
        reconciliation_items = []
        
        for _ in range(iterations):
            # Create partition
            mid = len(self.instance_names) // 2
            partition_a = self.instance_names[:mid]
            partition_b = self.instance_names[mid:]
            
            await self.mcp_cluster.create_network_partition(partition_a, partition_b)
            
            # Generate divergent state
            divergent_items = 0
            for i in range(20):
                # Different data in each partition
                data_a = self._create_knowledge_payload('small')
                data_b = self._create_knowledge_payload('small')
                
                await asyncio.gather(
                    self.mcp_cluster.store_in_partition(data_a, partition_a),
                    self.mcp_cluster.store_in_partition(data_b, partition_b),
                    return_exceptions=True
                )
                divergent_items += 2
            
            # Heal partition
            start = time.perf_counter()
            await self.mcp_cluster.heal_network_partition()
            
            # Wait for reconciliation
            reconciled = await self.mcp_cluster.reconcile_state(timeout=60.0)
            healing_time = time.perf_counter() - start
            
            if reconciled:
                healing_times.append(healing_time)
                reconciliation_items.append(divergent_items)
        
        return {
            'iterations': iterations,
            'healing_success_rate': len(healing_times) / iterations,
            'avg_healing_time_ms': np.mean(healing_times) * 1000 if healing_times else 0,
            'max_healing_time_ms': np.max(healing_times) * 1000 if healing_times else 0,
            'avg_reconciliation_items': np.mean(reconciliation_items) if reconciliation_items else 0,
            'reconciliation_rate_items_per_sec': (
                sum(reconciliation_items) / sum(healing_times) 
                if healing_times else 0
            )
        }
    
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
            'type': 'benchmark_data',
            'features': np.random.rand(data_size).tolist(),
            'metadata': {
                'size': size,
                'timestamp': time.time(),
                'source': 'benchmark'
            }
        }
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of cross-instance benchmarks."""
        summary = {
            'connectivity': {
                'avg_ping_latency_ms': results['connectivity']['avg_ping_latency']['mean_ms'],
                'connectivity_success_rate': (
                    results['connectivity']['successful_connections'] / 
                    results['connectivity']['total_tests']
                )
            },
            'knowledge_sharing': {
                'point_to_point_latency_ms': results['knowledge_sharing']['point_to_point']['avg_latency_ms'],
                'broadcast_latency_ms': results['broadcast']['medium_payload']['avg_broadcast_time_ms'],
                'throughput_mbps': results['knowledge_sharing']['point_to_point']['throughput_mbps']
            },
            'consensus': {
                'simple_majority_time_ms': results['consensus']['simple_majority']['avg_consensus_time_ms'],
                'bft_success_rate': results['consensus']['byzantine_fault_tolerant']['success_rate'],
                'raft_replication_time_ms': results['consensus']['raft_consensus']['avg_replication_time_ms']
            },
            'reliability': {
                'single_failure_recovery_ms': results['failure_recovery']['single_instance_failure']['avg_recovery_time_ms'],
                'partition_resolution_ms': results['partition_handling']['split_brain']['avg_resolution_time_ms'],
                'data_consistency_rate': results['partition_handling']['split_brain']['data_consistency_rate']
            }
        }
        
        return summary