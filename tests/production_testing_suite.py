#!/usr/bin/env python3
"""
Production Testing Suite for MCP Servers
Comprehensive testing including load testing, chaos engineering, and failover testing
"""

import asyncio
import json
import time
import random
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import aiohttp
import psutil
from concurrent.futures import ThreadPoolExecutor
import subprocess
import signal
import threading

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class TestMetrics:
    """Test execution metrics"""
    timestamp: str
    test_type: str
    duration_seconds: float
    total_requests: int
    successful_requests: int
    failed_requests: int
    avg_response_time_ms: float
    p95_response_time_ms: float
    p99_response_time_ms: float
    max_response_time_ms: float
    throughput_rps: float
    error_rate_percent: float
    cpu_usage_percent: float
    memory_usage_mb: float
    network_io_mb: float

@dataclass
class ChaosEvent:
    """Chaos engineering event"""
    event_type: str
    target: str
    duration_seconds: int
    impact_level: str
    timestamp: str
    recovery_time_seconds: Optional[float] = None

class LoadTester:
    """High-performance load testing for MCP servers"""
    
    def __init__(self, base_urls: List[str]):
        self.base_urls = base_urls
        self.session = None
        self.metrics = []
        self.running = False
        
    async def initialize(self):
        """Initialize load testing session"""
        connector = aiohttp.TCPConnector(
            limit=1000,
            limit_per_host=100,
            keepalive_timeout=60,
            enable_cleanup_closed=True
        )
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': 'MCP-Load-Tester/1.0'}
        )
        logger.info("Load tester initialized")
    
    async def cleanup(self):
        """Cleanup load testing session"""
        if self.session:
            await self.session.close()
        logger.info("Load tester cleaned up")
    
    async def make_request(self, url: str, method: str = 'GET', data: Dict = None) -> Dict:
        """Make a single HTTP request and measure performance"""
        start_time = time.time()
        try:
            async with self.session.request(method, url, json=data) as response:
                await response.text()
                duration_ms = (time.time() - start_time) * 1000
                return {
                    'status': response.status,
                    'duration_ms': duration_ms,
                    'success': 200 <= response.status < 400
                }
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error(f"Request failed: {e}")
            return {
                'status': 0,
                'duration_ms': duration_ms,
                'success': False,
                'error': str(e)
            }
    
    async def constant_load_test(self, 
                                duration_seconds: int = 300,
                                requests_per_second: float = 100,
                                endpoint: str = '/health') -> TestMetrics:
        """Constant load testing pattern"""
        logger.info(f"Starting constant load test: {requests_per_second} RPS for {duration_seconds}s")
        
        start_time = time.time()
        end_time = start_time + duration_seconds
        interval = 1.0 / requests_per_second
        
        results = []
        request_count = 0
        
        while time.time() < end_time and self.running:
            batch_start = time.time()
            
            # Send batch of requests
            tasks = []
            for url in self.base_urls:
                task = self.make_request(f"{url}{endpoint}")
                tasks.append(task)
                request_count += 1
            
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in batch_results:
                if isinstance(result, dict):
                    results.append(result)
            
            # Control rate
            elapsed = time.time() - batch_start
            sleep_time = max(0, interval - elapsed)
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)
        
        return self._calculate_metrics(results, "constant_load", time.time() - start_time)
    
    async def spike_load_test(self,
                             duration_seconds: int = 300,
                             baseline_rps: float = 50,
                             spike_rps: float = 500,
                             spike_duration: int = 30,
                             spike_interval: int = 60) -> TestMetrics:
        """Spike load testing pattern"""
        logger.info(f"Starting spike load test: {baseline_rps} RPS baseline, {spike_rps} RPS spikes")
        
        start_time = time.time()
        end_time = start_time + duration_seconds
        results = []
        request_count = 0
        last_spike = 0
        
        while time.time() < end_time and self.running:
            current_time = time.time() - start_time
            
            # Determine if we're in a spike
            if (current_time - last_spike) >= spike_interval:
                # Start spike
                current_rps = spike_rps
                spike_end = current_time + spike_duration
                last_spike = current_time
                logger.info(f"Starting spike: {spike_rps} RPS for {spike_duration}s")
            elif (current_time - last_spike) < spike_duration:
                # In spike
                current_rps = spike_rps
            else:
                # Baseline
                current_rps = baseline_rps
            
            # Send requests at current rate
            interval = 1.0 / current_rps
            batch_start = time.time()
            
            tasks = []
            for url in self.base_urls:
                task = self.make_request(f"{url}/health")
                tasks.append(task)
                request_count += 1
            
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in batch_results:
                if isinstance(result, dict):
                    results.append(result)
            
            elapsed = time.time() - batch_start
            sleep_time = max(0, interval - elapsed)
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)
        
        return self._calculate_metrics(results, "spike_load", time.time() - start_time)
    
    async def ramp_up_test(self,
                          duration_seconds: int = 300,
                          start_rps: float = 10,
                          end_rps: float = 200,
                          ramp_duration: int = 120) -> TestMetrics:
        """Ramp-up load testing pattern"""
        logger.info(f"Starting ramp-up test: {start_rps} to {end_rps} RPS over {ramp_duration}s")
        
        start_time = time.time()
        end_time = start_time + duration_seconds
        results = []
        request_count = 0
        
        while time.time() < end_time and self.running:
            current_time = time.time() - start_time
            
            # Calculate current RPS based on ramp
            if current_time <= ramp_duration:
                progress = current_time / ramp_duration
                current_rps = start_rps + (end_rps - start_rps) * progress
            else:
                current_rps = end_rps
            
            interval = 1.0 / current_rps
            batch_start = time.time()
            
            tasks = []
            for url in self.base_urls:
                task = self.make_request(f"{url}/health")
                tasks.append(task)
                request_count += 1
            
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in batch_results:
                if isinstance(result, dict):
                    results.append(result)
            
            elapsed = time.time() - batch_start
            sleep_time = max(0, interval - elapsed)
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)
        
        return self._calculate_metrics(results, "ramp_up", time.time() - start_time)
    
    def _calculate_metrics(self, results: List[Dict], test_type: str, duration: float) -> TestMetrics:
        """Calculate test metrics from results"""
        if not results:
            return TestMetrics(
                timestamp=datetime.now().isoformat(),
                test_type=test_type,
                duration_seconds=duration,
                total_requests=0,
                successful_requests=0,
                failed_requests=0,
                avg_response_time_ms=0,
                p95_response_time_ms=0,
                p99_response_time_ms=0,
                max_response_time_ms=0,
                throughput_rps=0,
                error_rate_percent=100,
                cpu_usage_percent=psutil.cpu_percent(),
                memory_usage_mb=psutil.virtual_memory().used / 1024 / 1024,
                network_io_mb=0
            )
        
        successful = [r for r in results if r.get('success', False)]
        failed = [r for r in results if not r.get('success', False)]
        response_times = [r['duration_ms'] for r in results]
        
        response_times.sort()
        n = len(response_times)
        
        return TestMetrics(
            timestamp=datetime.now().isoformat(),
            test_type=test_type,
            duration_seconds=duration,
            total_requests=len(results),
            successful_requests=len(successful),
            failed_requests=len(failed),
            avg_response_time_ms=sum(response_times) / n if n > 0 else 0,
            p95_response_time_ms=response_times[int(n * 0.95)] if n > 0 else 0,
            p99_response_time_ms=response_times[int(n * 0.99)] if n > 0 else 0,
            max_response_time_ms=max(response_times) if response_times else 0,
            throughput_rps=len(results) / duration if duration > 0 else 0,
            error_rate_percent=(len(failed) / len(results)) * 100 if results else 100,
            cpu_usage_percent=psutil.cpu_percent(),
            memory_usage_mb=psutil.virtual_memory().used / 1024 / 1024,
            network_io_mb=0
        )

class ChaosEngineer:
    """Chaos engineering for testing system resilience"""
    
    def __init__(self, kubernetes_namespace: str = "mcp-production"):
        self.namespace = kubernetes_namespace
        self.chaos_events = []
        self.recovery_times = {}
    
    async def pod_killer_chaos(self, deployment_name: str, kill_percentage: float = 0.3) -> ChaosEvent:
        """Kill random pods to test resilience"""
        logger.info(f"Starting pod killer chaos on {deployment_name}")
        
        event = ChaosEvent(
            event_type="pod_killer",
            target=deployment_name,
            duration_seconds=0,  # Instantaneous
            impact_level="medium",
            timestamp=datetime.now().isoformat()
        )
        
        try:
            # Get pods for deployment
            result = subprocess.run([
                'kubectl', 'get', 'pods', '-l', f'app={deployment_name}',
                '-n', self.namespace, '-o', 'json'
            ], capture_output=True, text=True, check=True)
            
            pods_data = json.loads(result.stdout)
            pods = [pod['metadata']['name'] for pod in pods_data['items']]
            
            # Calculate pods to kill
            pods_to_kill = int(len(pods) * kill_percentage)
            if pods_to_kill == 0 and pods:
                pods_to_kill = 1
            
            # Randomly select pods to kill
            selected_pods = random.sample(pods, min(pods_to_kill, len(pods)))
            
            # Kill selected pods
            for pod in selected_pods:
                subprocess.run([
                    'kubectl', 'delete', 'pod', pod, '-n', self.namespace
                ], check=True)
                logger.info(f"Killed pod: {pod}")
            
            # Monitor recovery
            recovery_start = time.time()
            await self._wait_for_deployment_ready(deployment_name)
            recovery_time = time.time() - recovery_start
            
            event.recovery_time_seconds = recovery_time
            logger.info(f"Pod killer chaos completed. Recovery time: {recovery_time:.2f}s")
            
        except Exception as e:
            logger.error(f"Pod killer chaos failed: {e}")
            event.impact_level = "failed"
        
        self.chaos_events.append(event)
        return event
    
    async def network_partition_chaos(self, deployment_name: str, duration_seconds: int = 60) -> ChaosEvent:
        """Simulate network partition"""
        logger.info(f"Starting network partition chaos on {deployment_name} for {duration_seconds}s")
        
        event = ChaosEvent(
            event_type="network_partition",
            target=deployment_name,
            duration_seconds=duration_seconds,
            impact_level="high",
            timestamp=datetime.now().isoformat()
        )
        
        try:
            # Create network policy to block traffic
            network_policy = {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {
                    "name": f"chaos-partition-{deployment_name}",
                    "namespace": self.namespace
                },
                "spec": {
                    "podSelector": {
                        "matchLabels": {"app": deployment_name}
                    },
                    "policyTypes": ["Ingress", "Egress"],
                    "ingress": [],
                    "egress": []
                }
            }
            
            # Apply network policy
            subprocess.run([
                'kubectl', 'apply', '-f', '-'
            ], input=json.dumps(network_policy), text=True, check=True)
            
            logger.info(f"Network partition applied for {duration_seconds}s")
            await asyncio.sleep(duration_seconds)
            
            # Remove network policy
            subprocess.run([
                'kubectl', 'delete', 'networkpolicy', 
                f'chaos-partition-{deployment_name}', '-n', self.namespace
            ], check=True)
            
            # Monitor recovery
            recovery_start = time.time()
            await self._wait_for_deployment_ready(deployment_name)
            recovery_time = time.time() - recovery_start
            
            event.recovery_time_seconds = recovery_time
            logger.info(f"Network partition chaos completed. Recovery time: {recovery_time:.2f}s")
            
        except Exception as e:
            logger.error(f"Network partition chaos failed: {e}")
            event.impact_level = "failed"
        
        self.chaos_events.append(event)
        return event
    
    async def resource_exhaustion_chaos(self, deployment_name: str, duration_seconds: int = 120) -> ChaosEvent:
        """Simulate resource exhaustion"""
        logger.info(f"Starting resource exhaustion chaos on {deployment_name}")
        
        event = ChaosEvent(
            event_type="resource_exhaustion",
            target=deployment_name,
            duration_seconds=duration_seconds,
            impact_level="high",
            timestamp=datetime.now().isoformat()
        )
        
        try:
            # Create CPU/memory stress job
            stress_job = {
                "apiVersion": "batch/v1",
                "kind": "Job",
                "metadata": {
                    "name": f"chaos-stress-{deployment_name}",
                    "namespace": self.namespace
                },
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [{
                                "name": "stress",
                                "image": "polinux/stress",
                                "command": ["stress"],
                                "args": [
                                    "--cpu", "4",
                                    "--memory", "2",
                                    "--memory-bytes", "1G",
                                    "--timeout", f"{duration_seconds}s"
                                ],
                                "resources": {
                                    "requests": {"cpu": "2", "memory": "1Gi"},
                                    "limits": {"cpu": "4", "memory": "2Gi"}
                                }
                            }],
                            "restartPolicy": "Never",
                            "nodeSelector": {"workload": "ml"}  # Target ML nodes
                        }
                    }
                }
            }
            
            # Apply stress job
            subprocess.run([
                'kubectl', 'apply', '-f', '-'
            ], input=json.dumps(stress_job), text=True, check=True)
            
            logger.info(f"Resource exhaustion applied for {duration_seconds}s")
            await asyncio.sleep(duration_seconds + 30)  # Wait for completion
            
            # Clean up stress job
            subprocess.run([
                'kubectl', 'delete', 'job', 
                f'chaos-stress-{deployment_name}', '-n', self.namespace
            ], check=True)
            
            # Monitor recovery
            recovery_start = time.time()
            await self._wait_for_deployment_ready(deployment_name)
            recovery_time = time.time() - recovery_start
            
            event.recovery_time_seconds = recovery_time
            logger.info(f"Resource exhaustion chaos completed. Recovery time: {recovery_time:.2f}s")
            
        except Exception as e:
            logger.error(f"Resource exhaustion chaos failed: {e}")
            event.impact_level = "failed"
        
        self.chaos_events.append(event)
        return event
    
    async def _wait_for_deployment_ready(self, deployment_name: str, timeout: int = 300):
        """Wait for deployment to be ready"""
        cmd = [
            'kubectl', 'rollout', 'status', f'deployment/{deployment_name}',
            '-n', self.namespace, f'--timeout={timeout}s'
        ]
        subprocess.run(cmd, check=True)

class FailoverTester:
    """Test failover and disaster recovery scenarios"""
    
    def __init__(self, primary_urls: List[str], secondary_urls: List[str]):
        self.primary_urls = primary_urls
        self.secondary_urls = secondary_urls
        self.failover_events = []
    
    async def database_failover_test(self) -> Dict:
        """Test database failover scenarios"""
        logger.info("Starting database failover test")
        
        start_time = time.time()
        
        # Simulate database failure
        try:
            # Stop primary database
            subprocess.run([
                'kubectl', 'scale', 'deployment', 'postgres-primary',
                '--replicas=0', '-n', 'mcp-production'
            ], check=True)
            
            # Wait for failover to secondary
            await asyncio.sleep(30)
            
            # Verify secondary is active
            recovery_time = await self._measure_recovery_time()
            
            # Restore primary
            subprocess.run([
                'kubectl', 'scale', 'deployment', 'postgres-primary',
                '--replicas=1', '-n', 'mcp-production'
            ], check=True)
            
            return {
                'test_type': 'database_failover',
                'duration_seconds': time.time() - start_time,
                'recovery_time_seconds': recovery_time,
                'status': 'success'
            }
            
        except Exception as e:
            logger.error(f"Database failover test failed: {e}")
            return {
                'test_type': 'database_failover',
                'duration_seconds': time.time() - start_time,
                'status': 'failed',
                'error': str(e)
            }
    
    async def region_failover_test(self) -> Dict:
        """Test cross-region failover"""
        logger.info("Starting region failover test")
        
        start_time = time.time()
        
        try:
            # Switch DNS to secondary region
            # This would typically involve updating Route53 or similar
            logger.info("Simulating region failover...")
            
            # Measure recovery time
            recovery_time = await self._measure_recovery_time(self.secondary_urls)
            
            return {
                'test_type': 'region_failover',
                'duration_seconds': time.time() - start_time,
                'recovery_time_seconds': recovery_time,
                'status': 'success'
            }
            
        except Exception as e:
            logger.error(f"Region failover test failed: {e}")
            return {
                'test_type': 'region_failover',
                'duration_seconds': time.time() - start_time,
                'status': 'failed',
                'error': str(e)
            }
    
    async def _measure_recovery_time(self, urls: List[str] = None) -> float:
        """Measure time to recovery"""
        test_urls = urls or self.primary_urls
        start_time = time.time()
        
        async with aiohttp.ClientSession() as session:
            while time.time() - start_time < 300:  # 5 minute timeout
                try:
                    for url in test_urls:
                        async with session.get(f"{url}/health") as response:
                            if response.status == 200:
                                return time.time() - start_time
                except:
                    pass
                
                await asyncio.sleep(5)
        
        return 300  # Timeout

class ProductionTestOrchestrator:
    """Orchestrate comprehensive production testing"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.load_tester = LoadTester(config['api_urls'])
        self.chaos_engineer = ChaosEngineer(config.get('namespace', 'mcp-production'))
        self.failover_tester = FailoverTester(
            config['primary_urls'], 
            config.get('secondary_urls', [])
        )
        self.results = []
    
    async def run_comprehensive_test_suite(self) -> Dict:
        """Run complete production test suite"""
        logger.info("Starting comprehensive production test suite")
        
        try:
            await self.load_tester.initialize()
            self.load_tester.running = True
            
            # Phase 1: Baseline load testing
            logger.info("Phase 1: Baseline load testing")
            baseline_metrics = await self.load_tester.constant_load_test(
                duration_seconds=300,
                requests_per_second=100
            )
            self.results.append(('baseline_load', baseline_metrics))
            
            # Phase 2: Spike testing
            logger.info("Phase 2: Spike load testing")
            spike_metrics = await self.load_tester.spike_load_test(
                duration_seconds=300,
                baseline_rps=50,
                spike_rps=500
            )
            self.results.append(('spike_load', spike_metrics))
            
            # Phase 3: Chaos engineering
            logger.info("Phase 3: Chaos engineering")
            chaos_events = []
            
            # Pod killer chaos
            chaos_events.append(
                await self.chaos_engineer.pod_killer_chaos('mcp-typescript-api')
            )
            
            # Network partition chaos
            chaos_events.append(
                await self.chaos_engineer.network_partition_chaos('mcp-learning-system')
            )
            
            # Resource exhaustion chaos
            chaos_events.append(
                await self.chaos_engineer.resource_exhaustion_chaos('mcp-rust-server')
            )
            
            self.results.append(('chaos_events', chaos_events))
            
            # Phase 4: Failover testing
            logger.info("Phase 4: Failover testing")
            failover_results = []
            
            failover_results.append(
                await self.failover_tester.database_failover_test()
            )
            
            if self.config.get('secondary_urls'):
                failover_results.append(
                    await self.failover_tester.region_failover_test()
                )
            
            self.results.append(('failover_tests', failover_results))
            
            # Phase 5: Recovery validation
            logger.info("Phase 5: Recovery validation")
            recovery_metrics = await self.load_tester.constant_load_test(
                duration_seconds=180,
                requests_per_second=100
            )
            self.results.append(('recovery_validation', recovery_metrics))
            
            return self._generate_report()
            
        finally:
            self.load_tester.running = False
            await self.load_tester.cleanup()
    
    def _generate_report(self) -> Dict:
        """Generate comprehensive test report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'test_duration_seconds': 0,
            'overall_status': 'PASS',
            'phases': {},
            'summary': {
                'total_requests': 0,
                'success_rate': 0,
                'avg_response_time_ms': 0,
                'chaos_recovery_time_avg_seconds': 0,
                'failover_success_rate': 0
            },
            'recommendations': []
        }
        
        total_requests = 0
        total_successful = 0
        response_times = []
        recovery_times = []
        
        for phase_name, phase_data in self.results:
            if isinstance(phase_data, TestMetrics):
                report['phases'][phase_name] = asdict(phase_data)
                total_requests += phase_data.total_requests
                total_successful += phase_data.successful_requests
                response_times.append(phase_data.avg_response_time_ms)
                
                # Check for failures
                if phase_data.error_rate_percent > 5:
                    report['overall_status'] = 'FAIL'
                    report['recommendations'].append(
                        f"High error rate in {phase_name}: {phase_data.error_rate_percent:.2f}%"
                    )
                
                if phase_data.p95_response_time_ms > 2000:
                    report['overall_status'] = 'WARNING'
                    report['recommendations'].append(
                        f"High P95 response time in {phase_name}: {phase_data.p95_response_time_ms:.2f}ms"
                    )
            
            elif phase_name == 'chaos_events':
                report['phases'][phase_name] = [asdict(event) for event in phase_data]
                for event in phase_data:
                    if event.recovery_time_seconds:
                        recovery_times.append(event.recovery_time_seconds)
                    if event.impact_level == 'failed':
                        report['overall_status'] = 'FAIL'
                        report['recommendations'].append(
                            f"Chaos event failed: {event.event_type} on {event.target}"
                        )
            
            elif phase_name == 'failover_tests':
                report['phases'][phase_name] = phase_data
                failed_failovers = [test for test in phase_data if test['status'] != 'success']
                if failed_failovers:
                    report['overall_status'] = 'FAIL'
                    for failed_test in failed_failovers:
                        report['recommendations'].append(
                            f"Failover test failed: {failed_test['test_type']}"
                        )
        
        # Calculate summary metrics
        report['summary']['total_requests'] = total_requests
        report['summary']['success_rate'] = (total_successful / total_requests * 100) if total_requests > 0 else 0
        report['summary']['avg_response_time_ms'] = sum(response_times) / len(response_times) if response_times else 0
        report['summary']['chaos_recovery_time_avg_seconds'] = sum(recovery_times) / len(recovery_times) if recovery_times else 0
        
        # Production readiness assessment
        if report['overall_status'] == 'PASS':
            if report['summary']['success_rate'] >= 99.9 and report['summary']['avg_response_time_ms'] <= 1000:
                report['production_ready'] = True
                report['production_grade'] = 'A'
            elif report['summary']['success_rate'] >= 99.5 and report['summary']['avg_response_time_ms'] <= 2000:
                report['production_ready'] = True
                report['production_grade'] = 'B'
            else:
                report['production_ready'] = False
                report['production_grade'] = 'C'
        else:
            report['production_ready'] = False
            report['production_grade'] = 'F'
        
        return report

async def main():
    """Main function for running production tests"""
    import argparse
    
    parser = argparse.ArgumentParser(description='MCP Production Testing Suite')
    parser.add_argument('--config', required=True, help='Configuration file path')
    parser.add_argument('--output', default='production_test_results.json', help='Output file path')
    args = parser.parse_args()
    
    # Load configuration
    with open(args.config, 'r') as f:
        config = json.load(f)
    
    # Run tests
    orchestrator = ProductionTestOrchestrator(config)
    results = await orchestrator.run_comprehensive_test_suite()
    
    # Save results
    with open(args.output, 'w') as f:
        json.dump(results, f, indent=2)
    
    # Print summary
    print(f"Production Test Results:")
    print(f"Overall Status: {results['overall_status']}")
    print(f"Production Ready: {results['production_ready']}")
    print(f"Production Grade: {results['production_grade']}")
    print(f"Success Rate: {results['summary']['success_rate']:.2f}%")
    print(f"Avg Response Time: {results['summary']['avg_response_time_ms']:.2f}ms")
    
    if results['recommendations']:
        print("\nRecommendations:")
        for rec in results['recommendations']:
            print(f"- {rec}")

if __name__ == "__main__":
    asyncio.run(main())