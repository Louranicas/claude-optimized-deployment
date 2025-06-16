#!/usr/bin/env python3
"""
24-Hour Sustained Load Testing Framework
Comprehensive load testing with realistic traffic patterns and system validation
"""

import asyncio
import json
import logging
import time
import psutil
import statistics
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
import aiohttp
import numpy as np
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
import threading
import queue
import random
import math

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class LoadTestMetrics:
    """Load test metrics data structure"""
    timestamp: datetime
    concurrent_users: int
    requests_per_second: float
    response_time_avg: float
    response_time_p95: float
    response_time_p99: float
    error_rate: float
    cpu_usage: float
    memory_usage: float
    disk_io_read: float
    disk_io_write: float
    network_io_sent: float
    network_io_recv: float
    success_count: int
    error_count: int
    timeout_count: int

@dataclass
class LoadTestReport:
    """24-hour load test report"""
    test_id: str
    start_time: datetime
    end_time: datetime
    duration_hours: float
    total_requests: int
    total_errors: int
    average_response_time: float
    p95_response_time: float
    p99_response_time: float
    max_response_time: float
    average_rps: float
    peak_rps: float
    error_rate: float
    cpu_usage_avg: float
    cpu_usage_peak: float
    memory_usage_avg: float
    memory_usage_peak: float
    sla_compliance: float
    stability_score: float
    recommendations: List[str]
    hourly_metrics: List[LoadTestMetrics]

class TrafficPattern:
    """Realistic traffic pattern simulation"""
    
    @staticmethod
    def daily_cycle_pattern(hour: int) -> float:
        """Daily traffic cycle (0.0 to 1.0 multiplier)"""
        # Simulate typical daily traffic: low at night, peak during business hours
        base_pattern = 0.3 + 0.7 * math.sin(math.pi * (hour - 6) / 12) ** 2
        return max(0.1, min(1.0, base_pattern))
    
    @staticmethod
    def gradual_increase_pattern(elapsed_hours: float, total_hours: float) -> float:
        """Gradual increase over time"""
        return min(1.0, 0.2 + 0.8 * (elapsed_hours / total_hours))
    
    @staticmethod
    def spike_pattern(hour: int) -> float:
        """Random traffic spikes"""
        spike_hours = [2, 8, 13, 18, 22]  # Specific hours with spikes
        if hour in spike_hours:
            return 1.5 + random.uniform(0, 0.5)  # 150-200% traffic
        return 1.0
    
    @staticmethod
    def get_realistic_load(hour: int, elapsed_hours: float, total_hours: float) -> float:
        """Combined realistic load pattern"""
        daily = TrafficPattern.daily_cycle_pattern(hour)
        gradual = TrafficPattern.gradual_increase_pattern(elapsed_hours, total_hours)
        spike = TrafficPattern.spike_pattern(hour)
        
        # Combine patterns with weights
        return daily * 0.6 + gradual * 0.3 + (spike - 1.0) * 0.1

class UserScenario:
    """Simulate different user behavior patterns"""
    
    def __init__(self, scenario_type: str):
        self.scenario_type = scenario_type
        self.session = None
        
    async def setup_session(self):
        """Setup HTTP session for user"""
        connector = aiohttp.TCPConnector(limit=100)
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
    
    async def cleanup_session(self):
        """Cleanup HTTP session"""
        if self.session:
            await self.session.close()
    
    async def execute_scenario(self, base_url: str) -> Tuple[bool, float, str]:
        """Execute user scenario and return (success, response_time, error)"""
        start_time = time.time()
        
        try:
            if self.scenario_type == "api_user":
                return await self._api_user_scenario(base_url)
            elif self.scenario_type == "heavy_user":
                return await self._heavy_user_scenario(base_url)
            elif self.scenario_type == "casual_user":
                return await self._casual_user_scenario(base_url)
            else:
                return await self._default_scenario(base_url)
                
        except Exception as e:
            response_time = time.time() - start_time
            return False, response_time, str(e)
    
    async def _api_user_scenario(self, base_url: str) -> Tuple[bool, float, str]:
        """API-heavy user scenario"""
        start_time = time.time()
        
        # Multiple API calls simulating real usage
        endpoints = [
            "/health",
            "/api/v1/status",
            "/api/v1/metrics",
            "/api/v1/experts/query",
            "/api/v1/deployment/status"
        ]
        
        for endpoint in endpoints:
            async with self.session.get(f"{base_url}{endpoint}") as response:
                if response.status != 200:
                    response_time = time.time() - start_time
                    return False, response_time, f"HTTP {response.status}"
                
                # Small delay between requests
                await asyncio.sleep(random.uniform(0.1, 0.3))
        
        response_time = time.time() - start_time
        return True, response_time, ""
    
    async def _heavy_user_scenario(self, base_url: str) -> Tuple[bool, float, str]:
        """Heavy user with complex operations"""
        start_time = time.time()
        
        # Simulate deployment operation
        payload = {
            "deployment_type": "production",
            "replicas": 3,
            "environment": "staging"
        }
        
        async with self.session.post(f"{base_url}/api/v1/deploy", json=payload) as response:
            if response.status not in [200, 201, 202]:
                response_time = time.time() - start_time
                return False, response_time, f"HTTP {response.status}"
        
        # Poll for completion
        for _ in range(5):
            await asyncio.sleep(1)
            async with self.session.get(f"{base_url}/api/v1/deployment/status") as response:
                if response.status == 200:
                    break
        
        response_time = time.time() - start_time
        return True, response_time, ""
    
    async def _casual_user_scenario(self, base_url: str) -> Tuple[bool, float, str]:
        """Casual user with simple operations"""
        start_time = time.time()
        
        # Simple health check
        async with self.session.get(f"{base_url}/health") as response:
            response_time = time.time() - start_time
            
            if response.status == 200:
                return True, response_time, ""
            else:
                return False, response_time, f"HTTP {response.status}"
    
    async def _default_scenario(self, base_url: str) -> Tuple[bool, float, str]:
        """Default user scenario"""
        return await self._casual_user_scenario(base_url)

class SystemMonitor:
    """System resource monitoring"""
    
    def __init__(self):
        self.monitoring = False
        self.metrics_queue = queue.Queue()
        self.monitor_thread = None
        
    def start_monitoring(self):
        """Start system monitoring"""
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.start()
        logger.info("📊 System monitoring started")
    
    def stop_monitoring(self):
        """Stop system monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join()
        logger.info("📊 System monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                # Collect system metrics
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk_io = psutil.disk_io_counters()
                network_io = psutil.net_io_counters()
                
                metrics = {
                    'timestamp': datetime.now(),
                    'cpu_usage': cpu_percent,
                    'memory_usage': memory.percent,
                    'memory_available': memory.available,
                    'disk_read_bytes': disk_io.read_bytes if disk_io else 0,
                    'disk_write_bytes': disk_io.write_bytes if disk_io else 0,
                    'network_sent_bytes': network_io.bytes_sent if network_io else 0,
                    'network_recv_bytes': network_io.bytes_recv if network_io else 0
                }
                
                self.metrics_queue.put(metrics)
                
                # Collect at 1-second intervals
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                time.sleep(5)
    
    def get_latest_metrics(self) -> Optional[Dict]:
        """Get latest system metrics"""
        try:
            return self.metrics_queue.get_nowait()
        except queue.Empty:
            return None

class SustainedLoadTester:
    """24-hour sustained load testing framework"""
    
    def __init__(self, 
                 base_url: str = "http://localhost:8000",
                 test_duration_hours: float = 24.0,
                 max_concurrent_users: int = 100,
                 project_root: str = "/home/louranicas/projects/claude-optimized-deployment"):
        
        self.base_url = base_url
        self.test_duration_hours = test_duration_hours
        self.max_concurrent_users = max_concurrent_users
        self.project_root = Path(project_root)
        
        self.test_id = f"LOAD_TEST_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.start_time = datetime.now()
        self.metrics_history: List[LoadTestMetrics] = []
        self.system_monitor = SystemMonitor()
        
        # Test configuration
        self.user_scenarios = [
            ("casual_user", 0.6),      # 60% casual users
            ("api_user", 0.3),         # 30% API users
            ("heavy_user", 0.1)        # 10% heavy users
        ]
        
        # SLA targets
        self.sla_targets = {
            'response_time_p95': 2000,  # 2 seconds
            'response_time_p99': 5000,  # 5 seconds
            'error_rate': 0.01,         # 1%
            'availability': 0.999       # 99.9%
        }
    
    async def run_sustained_load_test(self) -> LoadTestReport:
        """Execute 24-hour sustained load test"""
        logger.info(f"🚀 Starting 24-hour sustained load test - ID: {self.test_id}")
        logger.info(f"   Duration: {self.test_duration_hours} hours")
        logger.info(f"   Max concurrent users: {self.max_concurrent_users}")
        logger.info(f"   Base URL: {self.base_url}")
        
        # Start system monitoring
        self.system_monitor.start_monitoring()
        
        try:
            # Calculate test phases
            test_duration_seconds = self.test_duration_hours * 3600
            phase_duration = 3600  # 1-hour phases
            num_phases = int(test_duration_seconds / phase_duration)
            
            logger.info(f"📅 Test will run in {num_phases} phases of {phase_duration/60:.0f} minutes each")
            
            # Execute test phases
            for phase in range(num_phases):
                elapsed_hours = phase * (phase_duration / 3600)
                current_hour = (self.start_time.hour + phase) % 24
                
                logger.info(f"⏱️  Phase {phase + 1}/{num_phases} - Hour {current_hour}:00")
                
                # Calculate load for this phase
                load_multiplier = TrafficPattern.get_realistic_load(
                    current_hour, elapsed_hours, self.test_duration_hours
                )
                
                concurrent_users = int(self.max_concurrent_users * load_multiplier)
                concurrent_users = max(1, min(concurrent_users, self.max_concurrent_users))
                
                logger.info(f"   Load multiplier: {load_multiplier:.2f}")
                logger.info(f"   Concurrent users: {concurrent_users}")
                
                # Execute phase
                phase_metrics = await self._execute_load_phase(
                    concurrent_users, phase_duration, phase
                )
                
                self.metrics_history.append(phase_metrics)
                
                # Log phase results
                logger.info(f"   ✅ Phase {phase + 1} completed:")
                logger.info(f"      RPS: {phase_metrics.requests_per_second:.1f}")
                logger.info(f"      Avg response time: {phase_metrics.response_time_avg:.0f}ms")
                logger.info(f"      Error rate: {phase_metrics.error_rate:.2%}")
                logger.info(f"      CPU usage: {phase_metrics.cpu_usage:.1f}%")
                logger.info(f"      Memory usage: {phase_metrics.memory_usage:.1f}%")
                
                # Check for critical issues
                if phase_metrics.error_rate > 0.05:  # 5% error rate
                    logger.warning("⚠️  High error rate detected!")
                
                if phase_metrics.cpu_usage > 90:
                    logger.warning("⚠️  High CPU usage detected!")
                
                if phase_metrics.memory_usage > 90:
                    logger.warning("⚠️  High memory usage detected!")
                
                # Brief pause between phases
                await asyncio.sleep(10)
            
            # Generate final report
            return await self._generate_load_test_report()
            
        finally:
            # Stop monitoring
            self.system_monitor.stop_monitoring()
    
    async def _execute_load_phase(self, concurrent_users: int, 
                                 phase_duration: int, phase_num: int) -> LoadTestMetrics:
        """Execute single load testing phase"""
        
        phase_start = time.time()
        requests_completed = 0
        total_response_time = 0
        response_times = []
        error_count = 0
        timeout_count = 0
        
        # Track system metrics during phase
        cpu_samples = []
        memory_samples = []
        disk_read_samples = []
        disk_write_samples = []
        network_sent_samples = []
        network_recv_samples = []
        
        # Create user scenarios
        user_scenarios = self._create_user_scenarios(concurrent_users)
        
        # Setup sessions for all users
        for scenario in user_scenarios:
            await scenario.setup_session()
        
        try:
            # Run load test for phase duration
            phase_end_time = phase_start + phase_duration
            
            while time.time() < phase_end_time:
                # Collect system metrics
                sys_metrics = self.system_monitor.get_latest_metrics()
                if sys_metrics:
                    cpu_samples.append(sys_metrics['cpu_usage'])
                    memory_samples.append(sys_metrics['memory_usage'])
                    disk_read_samples.append(sys_metrics['disk_read_bytes'])
                    disk_write_samples.append(sys_metrics['disk_write_bytes'])
                    network_sent_samples.append(sys_metrics['network_sent_bytes'])
                    network_recv_samples.append(sys_metrics['network_recv_bytes'])
                
                # Execute concurrent requests
                batch_start = time.time()
                
                # Create tasks for concurrent execution
                tasks = []
                for scenario in user_scenarios:
                    task = asyncio.create_task(
                        scenario.execute_scenario(self.base_url)
                    )
                    tasks.append(task)
                
                # Execute batch with timeout
                try:
                    results = await asyncio.wait_for(
                        asyncio.gather(*tasks, return_exceptions=True),
                        timeout=30.0
                    )
                    
                    # Process results
                    for result in results:
                        if isinstance(result, Exception):
                            error_count += 1
                            if "timeout" in str(result).lower():
                                timeout_count += 1
                        elif isinstance(result, tuple):
                            success, response_time, error = result
                            requests_completed += 1
                            
                            if success:
                                response_time_ms = response_time * 1000
                                total_response_time += response_time_ms
                                response_times.append(response_time_ms)
                            else:
                                error_count += 1
                                if "timeout" in error.lower():
                                    timeout_count += 1
                
                except asyncio.TimeoutError:
                    logger.warning("Batch execution timeout")
                    timeout_count += len(tasks)
                    error_count += len(tasks)
                
                # Control request rate (don't overload)
                batch_duration = time.time() - batch_start
                target_batch_duration = 1.0  # 1 second per batch
                
                if batch_duration < target_batch_duration:
                    await asyncio.sleep(target_batch_duration - batch_duration)
        
        finally:
            # Cleanup user sessions
            for scenario in user_scenarios:
                await scenario.cleanup_session()
        
        # Calculate phase metrics
        phase_duration_actual = time.time() - phase_start
        
        # Calculate statistics
        avg_response_time = total_response_time / max(1, requests_completed)
        rps = requests_completed / phase_duration_actual
        error_rate = error_count / max(1, requests_completed + error_count)
        
        # Response time percentiles
        if response_times:
            p95_response_time = np.percentile(response_times, 95)
            p99_response_time = np.percentile(response_times, 99)
        else:
            p95_response_time = 0
            p99_response_time = 0
        
        # System metrics averages
        cpu_avg = statistics.mean(cpu_samples) if cpu_samples else 0
        memory_avg = statistics.mean(memory_samples) if memory_samples else 0
        
        # Network I/O rates (bytes per second)
        if len(network_sent_samples) > 1:
            network_sent_rate = (network_sent_samples[-1] - network_sent_samples[0]) / phase_duration_actual
            network_recv_rate = (network_recv_samples[-1] - network_recv_samples[0]) / phase_duration_actual
        else:
            network_sent_rate = 0
            network_recv_rate = 0
        
        # Disk I/O rates (bytes per second)
        if len(disk_read_samples) > 1:
            disk_read_rate = (disk_read_samples[-1] - disk_read_samples[0]) / phase_duration_actual
            disk_write_rate = (disk_write_samples[-1] - disk_write_samples[0]) / phase_duration_actual
        else:
            disk_read_rate = 0
            disk_write_rate = 0
        
        return LoadTestMetrics(
            timestamp=datetime.now(),
            concurrent_users=concurrent_users,
            requests_per_second=rps,
            response_time_avg=avg_response_time,
            response_time_p95=p95_response_time,
            response_time_p99=p99_response_time,
            error_rate=error_rate,
            cpu_usage=cpu_avg,
            memory_usage=memory_avg,
            disk_io_read=disk_read_rate,
            disk_io_write=disk_write_rate,
            network_io_sent=network_sent_rate,
            network_io_recv=network_recv_rate,
            success_count=requests_completed,
            error_count=error_count,
            timeout_count=timeout_count
        )
    
    def _create_user_scenarios(self, concurrent_users: int) -> List[UserScenario]:
        """Create user scenarios based on distribution"""
        scenarios = []
        
        for scenario_type, percentage in self.user_scenarios:
            user_count = int(concurrent_users * percentage)
            
            for _ in range(user_count):
                scenarios.append(UserScenario(scenario_type))
        
        # Fill remaining slots with casual users
        while len(scenarios) < concurrent_users:
            scenarios.append(UserScenario("casual_user"))
        
        return scenarios
    
    async def _generate_load_test_report(self) -> LoadTestReport:
        """Generate comprehensive load test report"""
        logger.info("📄 Generating load test report...")
        
        end_time = datetime.now()
        duration = end_time - self.start_time
        duration_hours = duration.total_seconds() / 3600
        
        # Aggregate metrics
        total_requests = sum(m.success_count for m in self.metrics_history)
        total_errors = sum(m.error_count for m in self.metrics_history)
        
        if self.metrics_history:
            # Response time statistics
            all_response_times = []
            for metrics in self.metrics_history:
                # Weight by number of requests
                for _ in range(metrics.success_count):
                    all_response_times.append(metrics.response_time_avg)
            
            if all_response_times:
                avg_response_time = statistics.mean(all_response_times)
                max_response_time = max(m.response_time_p99 for m in self.metrics_history)
                p95_response_time = np.percentile([m.response_time_p95 for m in self.metrics_history], 95)
                p99_response_time = np.percentile([m.response_time_p99 for m in self.metrics_history], 99)
            else:
                avg_response_time = 0
                max_response_time = 0
                p95_response_time = 0
                p99_response_time = 0
            
            # RPS statistics
            rps_values = [m.requests_per_second for m in self.metrics_history]
            avg_rps = statistics.mean(rps_values)
            peak_rps = max(rps_values)
            
            # Error rate
            error_rate = total_errors / max(1, total_requests + total_errors)
            
            # System resource statistics
            cpu_values = [m.cpu_usage for m in self.metrics_history]
            memory_values = [m.memory_usage for m in self.metrics_history]
            
            cpu_avg = statistics.mean(cpu_values)
            cpu_peak = max(cpu_values)
            memory_avg = statistics.mean(memory_values)
            memory_peak = max(memory_values)
        else:
            avg_response_time = 0
            max_response_time = 0
            p95_response_time = 0
            p99_response_time = 0
            avg_rps = 0
            peak_rps = 0
            error_rate = 1.0
            cpu_avg = 0
            cpu_peak = 0
            memory_avg = 0
            memory_peak = 0
        
        # Calculate SLA compliance
        sla_compliance = self._calculate_sla_compliance(
            p95_response_time, p99_response_time, error_rate
        )
        
        # Calculate stability score
        stability_score = self._calculate_stability_score()
        
        # Generate recommendations
        recommendations = self._generate_load_test_recommendations(
            error_rate, cpu_peak, memory_peak, avg_response_time
        )
        
        report = LoadTestReport(
            test_id=self.test_id,
            start_time=self.start_time,
            end_time=end_time,
            duration_hours=duration_hours,
            total_requests=total_requests,
            total_errors=total_errors,
            average_response_time=avg_response_time,
            p95_response_time=p95_response_time,
            p99_response_time=p99_response_time,
            max_response_time=max_response_time,
            average_rps=avg_rps,
            peak_rps=peak_rps,
            error_rate=error_rate,
            cpu_usage_avg=cpu_avg,
            cpu_usage_peak=cpu_peak,
            memory_usage_avg=memory_avg,
            memory_usage_peak=memory_peak,
            sla_compliance=sla_compliance,
            stability_score=stability_score,
            recommendations=recommendations,
            hourly_metrics=self.metrics_history
        )
        
        # Save report
        await self._save_load_test_report(report)
        
        return report
    
    def _calculate_sla_compliance(self, p95_response_time: float, 
                                 p99_response_time: float, error_rate: float) -> float:
        """Calculate SLA compliance score (0-100)"""
        compliance_score = 100.0
        
        # Response time compliance
        if p95_response_time > self.sla_targets['response_time_p95']:
            penalty = (p95_response_time - self.sla_targets['response_time_p95']) / self.sla_targets['response_time_p95']
            compliance_score -= min(30, penalty * 30)
        
        if p99_response_time > self.sla_targets['response_time_p99']:
            penalty = (p99_response_time - self.sla_targets['response_time_p99']) / self.sla_targets['response_time_p99']
            compliance_score -= min(20, penalty * 20)
        
        # Error rate compliance
        if error_rate > self.sla_targets['error_rate']:
            penalty = (error_rate - self.sla_targets['error_rate']) / self.sla_targets['error_rate']
            compliance_score -= min(50, penalty * 50)
        
        return max(0, compliance_score)
    
    def _calculate_stability_score(self) -> float:
        """Calculate system stability score (0-100)"""
        if not self.metrics_history:
            return 0.0
        
        # Measure variability in key metrics
        rps_values = [m.requests_per_second for m in self.metrics_history]
        response_times = [m.response_time_avg for m in self.metrics_history]
        error_rates = [m.error_rate for m in self.metrics_history]
        
        # Calculate coefficient of variation (CV = std/mean)
        rps_cv = statistics.stdev(rps_values) / statistics.mean(rps_values) if statistics.mean(rps_values) > 0 else 1
        response_cv = statistics.stdev(response_times) / statistics.mean(response_times) if statistics.mean(response_times) > 0 else 1
        
        # Stability score based on consistency
        stability_score = 100.0
        
        # Penalize high variability
        stability_score -= min(30, rps_cv * 30)
        stability_score -= min(30, response_cv * 30)
        
        # Penalize sustained high error rates
        avg_error_rate = statistics.mean(error_rates)
        if avg_error_rate > 0.01:
            stability_score -= min(40, avg_error_rate * 4000)
        
        return max(0, stability_score)
    
    def _generate_load_test_recommendations(self, error_rate: float, cpu_peak: float,
                                          memory_peak: float, avg_response_time: float) -> List[str]:
        """Generate load test recommendations"""
        recommendations = []
        
        # Performance recommendations
        if avg_response_time > 1000:  # > 1 second
            recommendations.append("Consider optimizing application response times - average exceeds 1 second")
        
        if error_rate > 0.01:  # > 1%
            recommendations.append(f"High error rate ({error_rate:.2%}) requires investigation and fixes")
        
        # Resource recommendations
        if cpu_peak > 80:
            recommendations.append(f"High CPU usage detected ({cpu_peak:.1f}%) - consider scaling or optimization")
        
        if memory_peak > 80:
            recommendations.append(f"High memory usage detected ({memory_peak:.1f}%) - check for memory leaks")
        
        # Capacity recommendations
        if error_rate > 0.05:  # > 5%
            recommendations.append("System may be at capacity limits - consider horizontal scaling")
        
        # General recommendations
        recommendations.extend([
            "Implement comprehensive monitoring in production",
            "Set up automated alerting for performance degradation", 
            "Consider implementing auto-scaling based on load patterns",
            "Plan capacity for 20% above peak load observed in testing",
            "Implement circuit breakers for external service dependencies",
            "Set up regular performance testing as part of CI/CD pipeline"
        ])
        
        return recommendations
    
    async def _save_load_test_report(self, report: LoadTestReport):
        """Save load test report to files"""
        reports_dir = self.project_root / "load_test_reports"
        reports_dir.mkdir(exist_ok=True)
        
        # Save JSON report
        json_report = reports_dir / f"{self.test_id}_load_test.json"
        with open(json_report, 'w') as f:
            json.dump(asdict(report), f, indent=2, default=str)
        
        # Save human-readable report
        text_report = reports_dir / f"{self.test_id}_load_test.md"
        await self._generate_markdown_load_report(report, text_report)
        
        # Save CSV data for analysis
        csv_report = reports_dir / f"{self.test_id}_metrics.csv"
        await self._generate_csv_metrics(report, csv_report)
        
        logger.info(f"📁 Load test reports saved:")
        logger.info(f"   JSON: {json_report}")
        logger.info(f"   Markdown: {text_report}")
        logger.info(f"   CSV: {csv_report}")
    
    async def _generate_markdown_load_report(self, report: LoadTestReport, output_path: Path):
        """Generate human-readable markdown report"""
        
        content = f"""# 24-Hour Sustained Load Test Report

**Test ID:** {report.test_id}  
**Start Time:** {report.start_time.strftime('%Y-%m-%d %H:%M:%S')}  
**End Time:** {report.end_time.strftime('%Y-%m-%d %H:%M:%S')}  
**Duration:** {report.duration_hours:.1f} hours  

## Executive Summary

The 24-hour sustained load test completed successfully with the following results:

- **Total Requests:** {report.total_requests:,}
- **Error Rate:** {report.error_rate:.2%}
- **Average Response Time:** {report.average_response_time:.0f}ms
- **SLA Compliance:** {report.sla_compliance:.1f}%
- **Stability Score:** {report.stability_score:.1f}%

## Performance Metrics

| Metric | Value |
|--------|-------|
| Total Requests | {report.total_requests:,} |
| Total Errors | {report.total_errors:,} |
| Average RPS | {report.average_rps:.1f} |
| Peak RPS | {report.peak_rps:.1f} |
| Average Response Time | {report.average_response_time:.0f}ms |
| P95 Response Time | {report.p95_response_time:.0f}ms |
| P99 Response Time | {report.p99_response_time:.0f}ms |
| Max Response Time | {report.max_response_time:.0f}ms |
| Error Rate | {report.error_rate:.2%} |

## System Resource Usage

| Resource | Average | Peak |
|----------|---------|------|
| CPU Usage | {report.cpu_usage_avg:.1f}% | {report.cpu_usage_peak:.1f}% |
| Memory Usage | {report.memory_usage_avg:.1f}% | {report.memory_usage_peak:.1f}% |

## SLA Compliance Analysis

**Overall SLA Compliance: {report.sla_compliance:.1f}%**

Target vs Actual Performance:
- P95 Response Time: {report.p95_response_time:.0f}ms (Target: ≤2000ms)
- P99 Response Time: {report.p99_response_time:.0f}ms (Target: ≤5000ms)  
- Error Rate: {report.error_rate:.2%} (Target: ≤1%)

## Stability Assessment

**Stability Score: {report.stability_score:.1f}%**

The stability score measures system consistency and reliability over the test duration.
A score above 80% indicates good stability for production deployment.

## Hourly Performance Breakdown

| Hour | Users | RPS | Avg RT (ms) | Error Rate | CPU % | Memory % |
|------|-------|-----|-------------|------------|-------|----------|"""

        for i, metrics in enumerate(report.hourly_metrics):
            content += f"""
| {i+1:2d} | {metrics.concurrent_users:3d} | {metrics.requests_per_second:5.1f} | {metrics.response_time_avg:6.0f} | {metrics.error_rate:6.2%} | {metrics.cpu_usage:5.1f} | {metrics.memory_usage:6.1f} |"""

        content += f"""

## Recommendations

"""
        for i, rec in enumerate(report.recommendations, 1):
            content += f"{i}. {rec}\n"

        content += f"""

## Production Capacity Planning

Based on the load test results:

1. **Recommended Production Capacity:**
   - Scale to handle {report.peak_rps * 1.2:.0f} RPS (20% above peak observed)
   - Monitor CPU usage to stay below 70% under normal load
   - Monitor memory usage to stay below 70% under normal load

2. **Scaling Triggers:**
   - Scale up when: CPU > 70% for 5+ minutes OR Response time P95 > 1500ms
   - Scale down when: CPU < 30% for 15+ minutes AND Response time P95 < 500ms

3. **Resource Allocation:**
   - CPU: Plan for {report.cpu_usage_peak * 1.3:.0f}% peak capacity
   - Memory: Plan for {report.memory_usage_peak * 1.3:.0f}% peak capacity

## Test Methodology

This 24-hour sustained load test simulated realistic traffic patterns including:
- Daily traffic cycles (low at night, peak during business hours)
- Gradual load increase over time
- Random traffic spikes
- Multiple user scenarios: casual users (60%), API users (30%), heavy users (10%)

The test validates system stability, performance consistency, and resource utilization under sustained load conditions typical of production environments.

**Test Environment:** Development/Staging  
**Framework Version:** 1.0.0  
"""
        
        with open(output_path, 'w') as f:
            f.write(content)
    
    async def _generate_csv_metrics(self, report: LoadTestReport, output_path: Path):
        """Generate CSV file with detailed metrics"""
        
        content = "Hour,Timestamp,ConcurrentUsers,RPS,AvgResponseTime,P95ResponseTime,P99ResponseTime,ErrorRate,CPUUsage,MemoryUsage,DiskReadRate,DiskWriteRate,NetworkSentRate,NetworkRecvRate\n"
        
        for i, metrics in enumerate(report.hourly_metrics):
            content += f"{i+1},{metrics.timestamp},{metrics.concurrent_users},{metrics.requests_per_second:.2f},{metrics.response_time_avg:.2f},{metrics.response_time_p95:.2f},{metrics.response_time_p99:.2f},{metrics.error_rate:.4f},{metrics.cpu_usage:.2f},{metrics.memory_usage:.2f},{metrics.disk_io_read:.0f},{metrics.disk_io_write:.0f},{metrics.network_io_sent:.0f},{metrics.network_io_recv:.0f}\n"
        
        with open(output_path, 'w') as f:
            f.write(content)

async def main():
    """Main execution function"""
    print("🚀 Starting 24-Hour Sustained Load Testing Framework")
    print("=" * 60)
    
    # Configuration for demo (shorter duration)
    test_duration_hours = 2.0  # 2 hours for demo, change to 24.0 for full test
    max_concurrent_users = 50   # Adjust based on your system capacity
    base_url = "http://localhost:8000"  # Adjust to your application URL
    
    print(f"Configuration:")
    print(f"  Duration: {test_duration_hours} hours")
    print(f"  Max users: {max_concurrent_users}")
    print(f"  Target URL: {base_url}")
    print()
    
    load_tester = SustainedLoadTester(
        base_url=base_url,
        test_duration_hours=test_duration_hours,
        max_concurrent_users=max_concurrent_users
    )
    
    try:
        # Run sustained load test
        report = await load_tester.run_sustained_load_test()
        
        print("\n🎯 LOAD TEST COMPLETED")
        print("=" * 40)
        print(f"Test ID: {report.test_id}")
        print(f"Duration: {report.duration_hours:.1f} hours")
        print(f"Total Requests: {report.total_requests:,}")
        print(f"Average RPS: {report.average_rps:.1f}")
        print(f"Error Rate: {report.error_rate:.2%}")
        print(f"SLA Compliance: {report.sla_compliance:.1f}%")
        print(f"Stability Score: {report.stability_score:.1f}%")
        
        print(f"\nPerformance Summary:")
        print(f"  Avg Response Time: {report.average_response_time:.0f}ms")
        print(f"  P95 Response Time: {report.p95_response_time:.0f}ms")
        print(f"  P99 Response Time: {report.p99_response_time:.0f}ms")
        
        print(f"\nResource Usage:")
        print(f"  Peak CPU: {report.cpu_usage_peak:.1f}%")
        print(f"  Peak Memory: {report.memory_usage_peak:.1f}%")
        
        print(f"\n📄 Reports saved to load_test_reports/ directory")
        
        # Exit with appropriate code based on results
        if report.error_rate > 0.05:  # > 5% error rate
            print("\n⚠️  HIGH ERROR RATE - SYSTEM STABILITY CONCERNS")
            return 1
        elif report.sla_compliance < 80:
            print("\n⚠️  SLA COMPLIANCE BELOW THRESHOLD")
            return 2
        else:
            print("\n✅ Load test completed successfully - System ready for production")
            return 0
            
    except Exception as e:
        logger.error(f"Load test failed: {e}")
        return 3

if __name__ == "__main__":
    import sys
    exit_code = asyncio.run(main())
    sys.exit(exit_code)