#!/usr/bin/env python3
"""
Comprehensive Chaos Engineering Framework
Validates system resilience and recovery capabilities through controlled failure injection
"""

import asyncio
import json
import logging
import random
import time
import subprocess
import psutil
import signal
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import aiohttp
import docker
import yaml

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class FailureType(Enum):
    """Types of chaos experiments"""
    SERVICE_FAILURE = "service_failure"
    NETWORK_PARTITION = "network_partition"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    DATABASE_FAILURE = "database_failure"
    NETWORK_LATENCY = "network_latency"
    PACKET_LOSS = "packet_loss"
    DISK_FAILURE = "disk_failure"
    CPU_STRESS = "cpu_stress"
    MEMORY_STRESS = "memory_stress"
    INFRASTRUCTURE_FAILURE = "infrastructure_failure"

class ExperimentStatus(Enum):
    """Chaos experiment status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"

@dataclass
class ChaosExperiment:
    """Chaos experiment definition"""
    id: str
    name: str
    description: str
    failure_type: FailureType
    target: str
    duration_seconds: int
    intensity: float  # 0.0 to 1.0
    parameters: Dict[str, Any]
    steady_state_checks: List[str]
    rollback_strategy: str
    blast_radius: str  # "small", "medium", "large"
    
@dataclass
class ExperimentResult:
    """Results of chaos experiment execution"""
    experiment_id: str
    status: ExperimentStatus
    start_time: datetime
    end_time: Optional[datetime]
    duration_seconds: float
    hypothesis_validated: bool
    steady_state_maintained: bool
    system_recovered: bool
    recovery_time_seconds: float
    observations: List[str]
    metrics_before: Dict[str, Any]
    metrics_during: Dict[str, Any]
    metrics_after: Dict[str, Any]
    incident_created: bool
    lessons_learned: List[str]

@dataclass
class ResilienceReport:
    """Comprehensive resilience assessment report"""
    test_id: str
    timestamp: datetime
    total_experiments: int
    successful_experiments: int
    failed_experiments: int
    system_resilience_score: float
    recovery_time_avg: float
    steady_state_violations: int
    critical_findings: List[str]
    recommendations: List[str]
    experiment_results: List[ExperimentResult]

class SystemMonitor:
    """Monitor system health during chaos experiments"""
    
    def __init__(self):
        self.monitoring = False
        self.metrics_history = []
        self.alert_thresholds = {
            'cpu_usage': 90.0,
            'memory_usage': 90.0,
            'error_rate': 0.05,
            'response_time': 5000  # ms
        }
    
    async def start_monitoring(self):
        """Start continuous system monitoring"""
        self.monitoring = True
        asyncio.create_task(self._monitoring_loop())
        logger.info("📊 System monitoring started")
    
    async def stop_monitoring(self):
        """Stop system monitoring"""
        self.monitoring = False
        logger.info("📊 System monitoring stopped")
    
    async def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                metrics = await self._collect_metrics()
                self.metrics_history.append(metrics)
                
                # Check for critical conditions
                await self._check_alert_conditions(metrics)
                
                await asyncio.sleep(5)  # Collect every 5 seconds
                
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                await asyncio.sleep(10)
    
    async def _collect_metrics(self) -> Dict[str, Any]:
        """Collect comprehensive system metrics"""
        # System resources
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Network stats
        network = psutil.net_io_counters()
        
        # Process count
        process_count = len(psutil.pids())
        
        # Application-specific metrics (simulate)
        app_metrics = await self._collect_application_metrics()
        
        return {
            'timestamp': datetime.now(),
            'cpu_usage': cpu_percent,
            'memory_usage': memory.percent,
            'memory_available': memory.available,
            'disk_usage': (disk.total - disk.free) / disk.total * 100,
            'disk_free': disk.free,
            'network_bytes_sent': network.bytes_sent,
            'network_bytes_recv': network.bytes_recv,
            'process_count': process_count,
            **app_metrics
        }
    
    async def _collect_application_metrics(self) -> Dict[str, Any]:
        """Collect application-specific metrics"""
        try:
            # Try to get metrics from application health endpoint
            async with aiohttp.ClientSession() as session:
                async with session.get('http://localhost:8000/health', timeout=5) as response:
                    if response.status == 200:
                        return {
                            'app_health': 'healthy',
                            'response_time': response.headers.get('X-Response-Time', 0),
                            'app_available': True
                        }
                    else:
                        return {
                            'app_health': 'unhealthy',
                            'response_time': 0,
                            'app_available': False
                        }
        except Exception:
            return {
                'app_health': 'unknown',
                'response_time': 0,
                'app_available': False
            }
    
    async def _check_alert_conditions(self, metrics: Dict[str, Any]):
        """Check for critical alert conditions"""
        alerts = []
        
        if metrics['cpu_usage'] > self.alert_thresholds['cpu_usage']:
            alerts.append(f"High CPU usage: {metrics['cpu_usage']:.1f}%")
        
        if metrics['memory_usage'] > self.alert_thresholds['memory_usage']:
            alerts.append(f"High memory usage: {metrics['memory_usage']:.1f}%")
        
        if not metrics.get('app_available', True):
            alerts.append("Application not available")
        
        if alerts:
            logger.warning(f"🚨 System alerts: {'; '.join(alerts)}")
    
    def get_metrics_snapshot(self) -> Dict[str, Any]:
        """Get current metrics snapshot"""
        if self.metrics_history:
            return self.metrics_history[-1]
        return {}
    
    def get_metrics_average(self, duration_seconds: int = 60) -> Dict[str, Any]:
        """Get average metrics over specified duration"""
        cutoff_time = datetime.now() - timedelta(seconds=duration_seconds)
        recent_metrics = [m for m in self.metrics_history if m['timestamp'] > cutoff_time]
        
        if not recent_metrics:
            return {}
        
        # Calculate averages for numeric metrics
        numeric_keys = ['cpu_usage', 'memory_usage', 'disk_usage', 'process_count']
        averages = {}
        
        for key in numeric_keys:
            values = [m.get(key, 0) for m in recent_metrics if isinstance(m.get(key), (int, float))]
            if values:
                averages[key] = sum(values) / len(values)
        
        return averages

class FailureInjector:
    """Inject various types of failures for chaos testing"""
    
    def __init__(self):
        self.active_failures = {}
        self.docker_client = None
        
        try:
            self.docker_client = docker.from_env()
        except Exception:
            logger.warning("Docker client not available - container experiments disabled")
    
    async def inject_service_failure(self, target: str, duration: int, intensity: float) -> str:
        """Inject service failure by stopping/killing processes"""
        failure_id = f"service_failure_{int(time.time())}"
        
        try:
            # Find target process
            target_processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if target.lower() in proc.info['name'].lower() or \
                       any(target.lower() in arg.lower() for arg in proc.info['cmdline'] if arg):
                        target_processes.append(proc)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            if not target_processes:
                logger.warning(f"No processes found matching target: {target}")
                return failure_id
            
            # Store process info for rollback
            self.active_failures[failure_id] = {
                'type': 'service_failure',
                'target': target,
                'processes': [{'pid': p.pid, 'name': p.info['name']} for p in target_processes],
                'start_time': time.time()
            }
            
            # Kill processes based on intensity
            processes_to_kill = int(len(target_processes) * intensity)
            for proc in random.sample(target_processes, min(processes_to_kill, len(target_processes))):
                try:
                    proc.terminate()
                    logger.info(f"Terminated process {proc.pid} ({proc.info['name']})")
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    logger.warning(f"Could not terminate process {proc.pid}: {e}")
            
            # Schedule automatic rollback
            asyncio.create_task(self._auto_rollback(failure_id, duration))
            
        except Exception as e:
            logger.error(f"Service failure injection failed: {e}")
        
        return failure_id
    
    async def inject_network_latency(self, target: str, duration: int, latency_ms: int) -> str:
        """Inject network latency using traffic control"""
        failure_id = f"network_latency_{int(time.time())}"
        
        try:
            # Use tc (traffic control) to add latency
            cmd = f"tc qdisc add dev eth0 root netem delay {latency_ms}ms"
            
            # Store rollback command
            self.active_failures[failure_id] = {
                'type': 'network_latency',
                'target': target,
                'rollback_cmd': "tc qdisc del dev eth0 root",
                'start_time': time.time()
            }
            
            # Execute with sudo (may require passwordless sudo)
            result = subprocess.run(f"sudo {cmd}", shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Applied network latency: {latency_ms}ms")
            else:
                logger.warning(f"Network latency injection failed: {result.stderr}")
            
            # Schedule automatic rollback
            asyncio.create_task(self._auto_rollback(failure_id, duration))
            
        except Exception as e:
            logger.error(f"Network latency injection failed: {e}")
        
        return failure_id
    
    async def inject_packet_loss(self, target: str, duration: int, loss_percentage: float) -> str:
        """Inject packet loss using traffic control"""
        failure_id = f"packet_loss_{int(time.time())}"
        
        try:
            # Use tc to add packet loss
            cmd = f"tc qdisc add dev eth0 root netem loss {loss_percentage}%"
            
            self.active_failures[failure_id] = {
                'type': 'packet_loss',
                'target': target,
                'rollback_cmd': "tc qdisc del dev eth0 root",
                'start_time': time.time()
            }
            
            result = subprocess.run(f"sudo {cmd}", shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Applied packet loss: {loss_percentage}%")
            else:
                logger.warning(f"Packet loss injection failed: {result.stderr}")
            
            asyncio.create_task(self._auto_rollback(failure_id, duration))
            
        except Exception as e:
            logger.error(f"Packet loss injection failed: {e}")
        
        return failure_id
    
    async def inject_cpu_stress(self, target: str, duration: int, intensity: float) -> str:
        """Inject CPU stress using stress-ng or custom CPU load"""
        failure_id = f"cpu_stress_{int(time.time())}"
        
        try:
            # Calculate number of CPU cores to stress
            cpu_count = psutil.cpu_count()
            cores_to_stress = max(1, int(cpu_count * intensity))
            
            # Try to use stress-ng first, fallback to custom implementation
            stress_cmd = f"stress-ng --cpu {cores_to_stress} --timeout {duration}s"
            
            # Start stress process
            process = subprocess.Popen(stress_cmd, shell=True)
            
            self.active_failures[failure_id] = {
                'type': 'cpu_stress',
                'target': target,
                'process': process,
                'start_time': time.time()
            }
            
            logger.info(f"Started CPU stress: {cores_to_stress} cores for {duration}s")
            
            # Schedule automatic cleanup
            asyncio.create_task(self._auto_rollback(failure_id, duration))
            
        except Exception as e:
            logger.error(f"CPU stress injection failed: {e}")
            # Fallback to Python-based CPU stress
            asyncio.create_task(self._python_cpu_stress(failure_id, duration, intensity))
        
        return failure_id
    
    async def inject_memory_stress(self, target: str, duration: int, memory_mb: int) -> str:
        """Inject memory stress by allocating large amounts of memory"""
        failure_id = f"memory_stress_{int(time.time())}"
        
        try:
            # Start memory stress in separate task
            asyncio.create_task(self._memory_stress_task(failure_id, duration, memory_mb))
            
            self.active_failures[failure_id] = {
                'type': 'memory_stress',
                'target': target,
                'memory_mb': memory_mb,
                'start_time': time.time()
            }
            
            logger.info(f"Started memory stress: {memory_mb}MB for {duration}s")
            
        except Exception as e:
            logger.error(f"Memory stress injection failed: {e}")
        
        return failure_id
    
    async def inject_disk_failure(self, target: str, duration: int, intensity: float) -> str:
        """Inject disk I/O stress or fill disk space"""
        failure_id = f"disk_failure_{int(time.time())}"
        
        try:
            # Create large files to fill disk space
            fill_size_gb = max(1, int(10 * intensity))  # Up to 10GB based on intensity
            
            # Start disk stress task
            asyncio.create_task(self._disk_stress_task(failure_id, duration, fill_size_gb))
            
            self.active_failures[failure_id] = {
                'type': 'disk_failure',
                'target': target,
                'fill_size_gb': fill_size_gb,
                'start_time': time.time()
            }
            
            logger.info(f"Started disk stress: {fill_size_gb}GB fill for {duration}s")
            
        except Exception as e:
            logger.error(f"Disk failure injection failed: {e}")
        
        return failure_id
    
    async def inject_container_failure(self, container_name: str, duration: int) -> str:
        """Inject container failure by stopping Docker containers"""
        failure_id = f"container_failure_{int(time.time())}"
        
        if not self.docker_client:
            logger.warning("Docker client not available")
            return failure_id
        
        try:
            # Find and stop containers
            containers = self.docker_client.containers.list(filters={'name': container_name})
            
            stopped_containers = []
            for container in containers:
                container.stop()
                stopped_containers.append({
                    'id': container.id,
                    'name': container.name
                })
                logger.info(f"Stopped container: {container.name}")
            
            self.active_failures[failure_id] = {
                'type': 'container_failure',
                'target': container_name,
                'containers': stopped_containers,
                'start_time': time.time()
            }
            
            # Schedule automatic restart
            asyncio.create_task(self._auto_rollback(failure_id, duration))
            
        except Exception as e:
            logger.error(f"Container failure injection failed: {e}")
        
        return failure_id
    
    async def rollback_failure(self, failure_id: str) -> bool:
        """Rollback a specific failure"""
        if failure_id not in self.active_failures:
            logger.warning(f"No active failure found with ID: {failure_id}")
            return False
        
        failure = self.active_failures[failure_id]
        failure_type = failure['type']
        
        try:
            if failure_type == 'service_failure':
                # Services will typically auto-restart (depends on system)
                logger.info(f"Service failure rollback for {failure_id} - services should auto-restart")
            
            elif failure_type in ['network_latency', 'packet_loss']:
                # Remove traffic control rules
                rollback_cmd = failure.get('rollback_cmd')
                if rollback_cmd:
                    result = subprocess.run(f"sudo {rollback_cmd}", shell=True, capture_output=True, text=True)
                    if result.returncode == 0:
                        logger.info(f"Network failure rolled back: {failure_id}")
                    else:
                        logger.warning(f"Network rollback failed: {result.stderr}")
            
            elif failure_type == 'cpu_stress':
                # Kill stress process
                process = failure.get('process')
                if process and process.poll() is None:
                    process.terminate()
                    logger.info(f"CPU stress process terminated: {failure_id}")
            
            elif failure_type == 'container_failure':
                # Restart stopped containers
                if self.docker_client:
                    for container_info in failure.get('containers', []):
                        try:
                            container = self.docker_client.containers.get(container_info['id'])
                            container.start()
                            logger.info(f"Restarted container: {container_info['name']}")
                        except Exception as e:
                            logger.error(f"Failed to restart container {container_info['name']}: {e}")
            
            # Remove from active failures
            del self.active_failures[failure_id]
            return True
            
        except Exception as e:
            logger.error(f"Rollback failed for {failure_id}: {e}")
            return False
    
    async def rollback_all_failures(self):
        """Rollback all active failures"""
        logger.info("Rolling back all active failures...")
        
        failure_ids = list(self.active_failures.keys())
        for failure_id in failure_ids:
            await self.rollback_failure(failure_id)
    
    async def _auto_rollback(self, failure_id: str, duration: int):
        """Automatically rollback failure after duration"""
        await asyncio.sleep(duration)
        await self.rollback_failure(failure_id)
    
    async def _python_cpu_stress(self, failure_id: str, duration: int, intensity: float):
        """Python-based CPU stress as fallback"""
        def cpu_stress():
            end_time = time.time() + duration
            while time.time() < end_time:
                # Busy loop to consume CPU
                for _ in range(10000):
                    pass
        
        # Start CPU stress threads
        threads = []
        num_threads = max(1, int(psutil.cpu_count() * intensity))
        
        for _ in range(num_threads):
            thread = threading.Thread(target=cpu_stress)
            thread.start()
            threads.append(thread)
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Clean up
        if failure_id in self.active_failures:
            del self.active_failures[failure_id]
    
    async def _memory_stress_task(self, failure_id: str, duration: int, memory_mb: int):
        """Memory stress task"""
        try:
            # Allocate memory in chunks
            chunk_size = 1024 * 1024  # 1MB chunks
            chunks = []
            
            for _ in range(memory_mb):
                chunk = bytearray(chunk_size)
                chunks.append(chunk)
                await asyncio.sleep(0.01)  # Small delay to avoid blocking
            
            # Hold memory for duration
            await asyncio.sleep(duration)
            
            # Release memory
            chunks.clear()
            
        except Exception as e:
            logger.error(f"Memory stress task failed: {e}")
        finally:
            # Clean up
            if failure_id in self.active_failures:
                del self.active_failures[failure_id]
    
    async def _disk_stress_task(self, failure_id: str, duration: int, fill_size_gb: int):
        """Disk stress task"""
        temp_files = []
        
        try:
            # Create temporary directory for stress files
            stress_dir = Path("/tmp/chaos_disk_stress")
            stress_dir.mkdir(exist_ok=True)
            
            # Create large files
            chunk_size = 1024 * 1024  # 1MB chunks
            chunks_per_gb = 1024
            
            for gb in range(fill_size_gb):
                file_path = stress_dir / f"stress_file_{gb}.tmp"
                temp_files.append(file_path)
                
                with open(file_path, 'wb') as f:
                    for chunk in range(chunks_per_gb):
                        f.write(b'0' * chunk_size)
                        
                        # Small delay to avoid blocking
                        if chunk % 100 == 0:
                            await asyncio.sleep(0.01)
            
            # Hold files for duration
            await asyncio.sleep(duration)
            
        except Exception as e:
            logger.error(f"Disk stress task failed: {e}")
        finally:
            # Clean up files
            for file_path in temp_files:
                try:
                    file_path.unlink(missing_ok=True)
                except Exception as e:
                    logger.error(f"Failed to remove stress file {file_path}: {e}")
            
            # Clean up
            if failure_id in self.active_failures:
                del self.active_failures[failure_id]

class ChaosEngineeringFramework:
    """Main chaos engineering framework"""
    
    def __init__(self, project_root: str = "/home/louranicas/projects/claude-optimized-deployment"):
        self.project_root = Path(project_root)
        self.test_id = f"CHAOS_TEST_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        self.monitor = SystemMonitor()
        self.injector = FailureInjector()
        self.experiment_results: List[ExperimentResult] = []
        
        # Load experiment definitions
        self.experiments = self._load_experiment_definitions()
    
    def _load_experiment_definitions(self) -> List[ChaosExperiment]:
        """Load predefined chaos experiments"""
        experiments = [
            ChaosExperiment(
                id="exp_001",
                name="API Service Failure",
                description="Test system resilience when main API service fails",
                failure_type=FailureType.SERVICE_FAILURE,
                target="python",
                duration_seconds=60,
                intensity=0.5,
                parameters={},
                steady_state_checks=["http://localhost:8000/health"],
                rollback_strategy="auto_restart",
                blast_radius="medium"
            ),
            ChaosExperiment(
                id="exp_002", 
                name="Network Latency Injection",
                description="Test system behavior under high network latency",
                failure_type=FailureType.NETWORK_LATENCY,
                target="eth0",
                duration_seconds=120,
                intensity=0.7,
                parameters={"latency_ms": 500},
                steady_state_checks=["http://localhost:8000/health"],
                rollback_strategy="remove_tc_rules",
                blast_radius="large"
            ),
            ChaosExperiment(
                id="exp_003",
                name="High CPU Load",
                description="Test system under high CPU utilization",
                failure_type=FailureType.CPU_STRESS,
                target="system",
                duration_seconds=180,
                intensity=0.8,
                parameters={},
                steady_state_checks=["http://localhost:8000/health"],
                rollback_strategy="kill_stress_processes",
                blast_radius="medium"
            ),
            ChaosExperiment(
                id="exp_004",
                name="Memory Pressure",
                description="Test system under memory pressure",
                failure_type=FailureType.MEMORY_STRESS,
                target="system",
                duration_seconds=120,
                intensity=0.6,
                parameters={"memory_mb": 1024},
                steady_state_checks=["http://localhost:8000/health"],
                rollback_strategy="release_memory",
                blast_radius="medium"
            ),
            ChaosExperiment(
                id="exp_005",
                name="Disk Space Exhaustion",
                description="Test system behavior when disk space is low",
                failure_type=FailureType.DISK_FAILURE,
                target="/tmp",
                duration_seconds=90,
                intensity=0.5,
                parameters={"fill_size_gb": 2},
                steady_state_checks=["http://localhost:8000/health"],
                rollback_strategy="remove_temp_files",
                blast_radius="small"
            ),
            ChaosExperiment(
                id="exp_006",
                name="Packet Loss Injection",
                description="Test system resilience to packet loss",
                failure_type=FailureType.PACKET_LOSS,
                target="eth0", 
                duration_seconds=90,
                intensity=0.3,
                parameters={"loss_percentage": 5.0},
                steady_state_checks=["http://localhost:8000/health"],
                rollback_strategy="remove_tc_rules",
                blast_radius="large"
            )
        ]
        
        return experiments
    
    async def run_chaos_engineering_validation(self) -> ResilienceReport:
        """Run comprehensive chaos engineering validation"""
        logger.info(f"🎯 Starting Chaos Engineering Validation - ID: {self.test_id}")
        logger.info(f"   Experiments: {len(self.experiments)}")
        
        # Start system monitoring
        await self.monitor.start_monitoring()
        
        try:
            # Run experiments in sequence
            for experiment in self.experiments:
                logger.info(f"\n🧪 Executing experiment: {experiment.name}")
                
                result = await self._execute_experiment(experiment)
                self.experiment_results.append(result)
                
                # Log experiment result
                status_emoji = "✅" if result.status == ExperimentStatus.COMPLETED else "❌"
                logger.info(f"   {status_emoji} Experiment {experiment.id} - {result.status.value}")
                logger.info(f"      Hypothesis validated: {result.hypothesis_validated}")
                logger.info(f"      System recovered: {result.system_recovered}")
                logger.info(f"      Recovery time: {result.recovery_time_seconds:.1f}s")
                
                # Wait between experiments
                logger.info("⏱️  Waiting for system stabilization...")
                await asyncio.sleep(30)
            
            # Generate resilience report
            return await self._generate_resilience_report()
            
        finally:
            # Ensure all failures are rolled back
            await self.injector.rollback_all_failures()
            await self.monitor.stop_monitoring()
    
    async def _execute_experiment(self, experiment: ChaosExperiment) -> ExperimentResult:
        """Execute single chaos experiment"""
        
        result = ExperimentResult(
            experiment_id=experiment.id,
            status=ExperimentStatus.PENDING,
            start_time=datetime.now(),
            end_time=None,
            duration_seconds=0,
            hypothesis_validated=False,
            steady_state_maintained=False,
            system_recovered=False,
            recovery_time_seconds=0,
            observations=[],
            metrics_before={},
            metrics_during={},
            metrics_after={},
            incident_created=False,
            lessons_learned=[]
        )
        
        try:
            # Phase 1: Establish steady state
            logger.info("   📊 Phase 1: Establishing steady state...")
            result.status = ExperimentStatus.RUNNING
            
            steady_state_ok = await self._verify_steady_state(experiment.steady_state_checks)
            if not steady_state_ok:
                result.observations.append("System not in steady state before experiment")
                result.status = ExperimentStatus.FAILED
                return result
            
            result.metrics_before = self.monitor.get_metrics_snapshot()
            
            # Phase 2: Inject failure
            logger.info(f"   💥 Phase 2: Injecting failure ({experiment.failure_type.value})...")
            
            failure_id = await self._inject_failure(experiment)
            
            if not failure_id:
                result.observations.append("Failed to inject failure")
                result.status = ExperimentStatus.FAILED
                return result
            
            # Phase 3: Monitor during failure
            logger.info("   👀 Phase 3: Monitoring system behavior...")
            
            monitoring_task = asyncio.create_task(
                self._monitor_during_failure(experiment.duration_seconds, result)
            )
            
            # Wait for experiment duration
            await asyncio.sleep(experiment.duration_seconds)
            
            # Get metrics during failure
            result.metrics_during = self.monitor.get_metrics_average(experiment.duration_seconds)
            
            # Phase 4: Rollback and recovery
            logger.info("   🔄 Phase 4: Rolling back failure...")
            
            rollback_start = time.time()
            rollback_success = await self.injector.rollback_failure(failure_id)
            
            if not rollback_success:
                result.observations.append("Rollback failed")
            
            # Wait for system recovery
            recovery_start = time.time()
            recovery_timeout = 300  # 5 minutes max
            
            while time.time() - recovery_start < recovery_timeout:
                if await self._verify_steady_state(experiment.steady_state_checks):
                    result.system_recovered = True
                    result.recovery_time_seconds = time.time() - recovery_start
                    break
                await asyncio.sleep(10)
            
            # Final metrics
            result.metrics_after = self.monitor.get_metrics_snapshot()
            
            # Phase 5: Evaluate results
            result.hypothesis_validated = await self._evaluate_hypothesis(experiment, result)
            result.steady_state_maintained = result.system_recovered
            
            if result.system_recovered and result.hypothesis_validated:
                result.status = ExperimentStatus.COMPLETED
            else:
                result.status = ExperimentStatus.FAILED
            
            # Generate lessons learned
            result.lessons_learned = self._generate_lessons_learned(experiment, result)
            
        except Exception as e:
            logger.error(f"Experiment execution failed: {e}")
            result.status = ExperimentStatus.FAILED
            result.observations.append(f"Experiment failed with error: {str(e)}")
        
        finally:
            result.end_time = datetime.now()
            result.duration_seconds = (result.end_time - result.start_time).total_seconds()
        
        return result
    
    async def _verify_steady_state(self, checks: List[str]) -> bool:
        """Verify system is in steady state"""
        for check in checks:
            try:
                if check.startswith('http'):
                    # HTTP health check
                    async with aiohttp.ClientSession() as session:
                        async with session.get(check, timeout=10) as response:
                            if response.status != 200:
                                return False
                else:
                    # Custom check (could be extended)
                    logger.warning(f"Unknown check type: {check}")
            except Exception as e:
                logger.warning(f"Steady state check failed for {check}: {e}")
                return False
        
        return True
    
    async def _inject_failure(self, experiment: ChaosExperiment) -> Optional[str]:
        """Inject failure based on experiment type"""
        
        failure_type = experiment.failure_type
        target = experiment.target
        duration = experiment.duration_seconds
        intensity = experiment.intensity
        params = experiment.parameters
        
        if failure_type == FailureType.SERVICE_FAILURE:
            return await self.injector.inject_service_failure(target, duration, intensity)
        
        elif failure_type == FailureType.NETWORK_LATENCY:
            latency_ms = params.get('latency_ms', 100)
            return await self.injector.inject_network_latency(target, duration, latency_ms)
        
        elif failure_type == FailureType.PACKET_LOSS:
            loss_percentage = params.get('loss_percentage', 1.0)
            return await self.injector.inject_packet_loss(target, duration, loss_percentage)
        
        elif failure_type == FailureType.CPU_STRESS:
            return await self.injector.inject_cpu_stress(target, duration, intensity)
        
        elif failure_type == FailureType.MEMORY_STRESS:
            memory_mb = params.get('memory_mb', 512)
            return await self.injector.inject_memory_stress(target, duration, memory_mb)
        
        elif failure_type == FailureType.DISK_FAILURE:
            return await self.injector.inject_disk_failure(target, duration, intensity)
        
        else:
            logger.warning(f"Unsupported failure type: {failure_type}")
            return None
    
    async def _monitor_during_failure(self, duration_seconds: int, result: ExperimentResult):
        """Monitor system behavior during failure injection"""
        observations = []
        
        # Monitor for the duration
        end_time = time.time() + duration_seconds
        
        while time.time() < end_time:
            metrics = self.monitor.get_metrics_snapshot()
            
            # Check for significant deviations
            if metrics.get('cpu_usage', 0) > 90:
                observations.append(f"High CPU usage detected: {metrics['cpu_usage']:.1f}%")
            
            if metrics.get('memory_usage', 0) > 90:
                observations.append(f"High memory usage detected: {metrics['memory_usage']:.1f}%")
            
            if not metrics.get('app_available', True):
                observations.append("Application became unavailable")
            
            await asyncio.sleep(5)
        
        result.observations.extend(observations)
    
    async def _evaluate_hypothesis(self, experiment: ChaosExperiment, result: ExperimentResult) -> bool:
        """Evaluate if the experiment hypothesis was validated"""
        
        # Basic hypothesis: system should maintain core functionality
        # and recover within reasonable time
        
        criteria_met = 0
        total_criteria = 3
        
        # Criterion 1: System recovered
        if result.system_recovered:
            criteria_met += 1
        
        # Criterion 2: Recovery time reasonable (< 5 minutes)
        if result.recovery_time_seconds < 300:
            criteria_met += 1
        
        # Criterion 3: No critical failures observed
        critical_observations = [obs for obs in result.observations 
                               if 'critical' in obs.lower() or 'fatal' in obs.lower()]
        if len(critical_observations) == 0:
            criteria_met += 1
        
        return criteria_met >= 2  # At least 2 of 3 criteria must be met
    
    def _generate_lessons_learned(self, experiment: ChaosExperiment, result: ExperimentResult) -> List[str]:
        """Generate lessons learned from experiment"""
        lessons = []
        
        if result.system_recovered:
            lessons.append(f"System demonstrated resilience to {experiment.failure_type.value}")
        else:
            lessons.append(f"System failed to recover from {experiment.failure_type.value}")
        
        if result.recovery_time_seconds > 60:
            lessons.append(f"Recovery time ({result.recovery_time_seconds:.1f}s) may be too long for production")
        
        if len(result.observations) > 5:
            lessons.append("System showed multiple stress indicators during failure")
        
        # Add experiment-specific lessons
        if experiment.failure_type == FailureType.CPU_STRESS:
            lessons.append("Consider implementing CPU throttling or auto-scaling")
        elif experiment.failure_type == FailureType.MEMORY_STRESS:
            lessons.append("Monitor memory usage and implement proper garbage collection")
        elif experiment.failure_type == FailureType.NETWORK_LATENCY:
            lessons.append("Implement timeout and retry mechanisms for network calls")
        
        return lessons
    
    async def _generate_resilience_report(self) -> ResilienceReport:
        """Generate comprehensive resilience report"""
        logger.info("📄 Generating resilience report...")
        
        total_experiments = len(self.experiment_results)
        successful_experiments = len([r for r in self.experiment_results 
                                    if r.status == ExperimentStatus.COMPLETED])
        failed_experiments = total_experiments - successful_experiments
        
        # Calculate resilience score (0-100)
        if total_experiments > 0:
            base_score = (successful_experiments / total_experiments) * 100
            
            # Adjust for recovery times
            recovery_times = [r.recovery_time_seconds for r in self.experiment_results 
                            if r.system_recovered]
            
            if recovery_times:
                avg_recovery_time = sum(recovery_times) / len(recovery_times)
                if avg_recovery_time > 120:  # > 2 minutes
                    base_score *= 0.9  # 10% penalty for slow recovery
            
            resilience_score = min(100, base_score)
        else:
            resilience_score = 0
        
        # Calculate average recovery time
        recovery_times = [r.recovery_time_seconds for r in self.experiment_results 
                         if r.system_recovered and r.recovery_time_seconds > 0]
        avg_recovery_time = sum(recovery_times) / len(recovery_times) if recovery_times else 0
        
        # Count steady state violations
        steady_state_violations = len([r for r in self.experiment_results 
                                     if not r.steady_state_maintained])
        
        # Generate critical findings
        critical_findings = []
        if failed_experiments > 0:
            critical_findings.append(f"{failed_experiments} experiments failed to complete successfully")
        
        if avg_recovery_time > 180:  # > 3 minutes
            critical_findings.append(f"Average recovery time ({avg_recovery_time:.1f}s) exceeds acceptable threshold")
        
        # Generate recommendations
        recommendations = self._generate_resilience_recommendations()
        
        report = ResilienceReport(
            test_id=self.test_id,
            timestamp=datetime.now(),
            total_experiments=total_experiments,
            successful_experiments=successful_experiments,
            failed_experiments=failed_experiments,
            system_resilience_score=resilience_score,
            recovery_time_avg=avg_recovery_time,
            steady_state_violations=steady_state_violations,
            critical_findings=critical_findings,
            recommendations=recommendations,
            experiment_results=self.experiment_results
        )
        
        # Save report
        await self._save_resilience_report(report)
        
        return report
    
    def _generate_resilience_recommendations(self) -> List[str]:
        """Generate resilience improvement recommendations"""
        recommendations = []
        
        # Analyze experiment results for patterns
        failed_experiments = [r for r in self.experiment_results 
                            if r.status == ExperimentStatus.FAILED]
        
        if len(failed_experiments) > 0:
            recommendations.append("Implement comprehensive error handling and recovery mechanisms")
        
        # Check for common failure patterns
        cpu_stress_failures = [r for r in failed_experiments 
                              if 'cpu' in r.experiment_id.lower()]
        if cpu_stress_failures:
            recommendations.append("Implement CPU-based auto-scaling and resource limits")
        
        memory_stress_failures = [r for r in failed_experiments 
                                if 'memory' in r.experiment_id.lower()]
        if memory_stress_failures:
            recommendations.append("Optimize memory usage and implement memory monitoring")
        
        network_failures = [r for r in failed_experiments 
                           if 'network' in r.experiment_id.lower()]
        if network_failures:
            recommendations.append("Implement robust network timeout and retry strategies")
        
        # General recommendations
        recommendations.extend([
            "Implement comprehensive monitoring and alerting",
            "Regular chaos engineering practice (monthly experiments)",
            "Develop runbooks for common failure scenarios",
            "Implement automated recovery procedures",
            "Set up proper logging and observability",
            "Consider implementing circuit breakers for external dependencies"
        ])
        
        return recommendations
    
    async def _save_resilience_report(self, report: ResilienceReport):
        """Save resilience report to files"""
        reports_dir = self.project_root / "chaos_reports"
        reports_dir.mkdir(exist_ok=True)
        
        # Save JSON report
        json_report = reports_dir / f"{self.test_id}_chaos_engineering.json"
        with open(json_report, 'w') as f:
            json.dump(asdict(report), f, indent=2, default=str)
        
        # Save human-readable report
        text_report = reports_dir / f"{self.test_id}_chaos_engineering.md"
        await self._generate_markdown_chaos_report(report, text_report)
        
        logger.info(f"📁 Chaos engineering reports saved:")
        logger.info(f"   JSON: {json_report}")
        logger.info(f"   Markdown: {text_report}")
    
    async def _generate_markdown_chaos_report(self, report: ResilienceReport, output_path: Path):
        """Generate human-readable markdown report"""
        
        content = f"""# Chaos Engineering Resilience Report

**Test ID:** {report.test_id}  
**Date:** {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}  
**System Resilience Score:** {report.system_resilience_score:.1f}/100  

## Executive Summary

The chaos engineering validation assessed system resilience through {report.total_experiments} controlled failure experiments. The system demonstrated a resilience score of {report.system_resilience_score:.1f}%, with {report.successful_experiments} successful experiments and {report.failed_experiments} failed experiments.

## Resilience Metrics

| Metric | Value |
|--------|-------|
| Total Experiments | {report.total_experiments} |
| Successful Experiments | {report.successful_experiments} |
| Failed Experiments | {report.failed_experiments} |
| Success Rate | {(report.successful_experiments/max(1,report.total_experiments)*100):.1f}% |
| Average Recovery Time | {report.recovery_time_avg:.1f} seconds |
| Steady State Violations | {report.steady_state_violations} |

## Critical Findings

"""
        for finding in report.critical_findings:
            content += f"- ⚠️ {finding}\n"
        
        if not report.critical_findings:
            content += "- ✅ No critical issues identified\n"
        
        content += f"""

## Experiment Results

"""
        
        for result in report.experiment_results:
            status_emoji = "✅" if result.status == ExperimentStatus.COMPLETED else "❌"
            content += f"""### {status_emoji} Experiment {result.experiment_id}

**Status:** {result.status.value}  
**Duration:** {result.duration_seconds:.1f} seconds  
**System Recovered:** {'Yes' if result.system_recovered else 'No'}  
**Recovery Time:** {result.recovery_time_seconds:.1f} seconds  
**Hypothesis Validated:** {'Yes' if result.hypothesis_validated else 'No'}  

**Observations:**
"""
            for obs in result.observations:
                content += f"- {obs}\n"
            
            content += f"""
**Lessons Learned:**
"""
            for lesson in result.lessons_learned:
                content += f"- {lesson}\n"
            
            content += "\n---\n"
        
        content += f"""

## Recommendations

"""
        for i, rec in enumerate(report.recommendations, 1):
            content += f"{i}. {rec}\n"
        
        content += f"""

## Production Readiness Assessment

Based on the chaos engineering results:

**Resilience Score: {report.system_resilience_score:.1f}/100**

- **80-100:** Excellent resilience - Production ready
- **60-79:** Good resilience - Production ready with monitoring
- **40-59:** Fair resilience - Address issues before production
- **0-39:** Poor resilience - Significant improvements needed

## Next Steps

1. **Immediate (0-1 week):** Address any critical findings
2. **Short-term (1-4 weeks):** Implement high-priority recommendations
3. **Medium-term (1-3 months):** Establish regular chaos engineering practice
4. **Long-term (3-6 months):** Build automated recovery capabilities

## Methodology

This chaos engineering assessment used controlled failure injection to validate:
- System resilience to various failure modes
- Recovery capabilities and time-to-recovery
- Steady-state maintenance during failures
- Overall system reliability under stress

Experiments included service failures, network issues, resource exhaustion, and infrastructure problems to comprehensively test system resilience.

**Framework Version:** 1.0.0  
**Test Environment:** Development/Staging  
"""
        
        with open(output_path, 'w') as f:
            f.write(content)

async def main():
    """Main execution function"""
    print("🎯 Starting Chaos Engineering Framework")
    print("=" * 50)
    
    chaos_framework = ChaosEngineeringFramework()
    
    try:
        # Run chaos engineering validation
        report = await chaos_framework.run_chaos_engineering_validation()
        
        print("\n🎯 CHAOS ENGINEERING COMPLETED")
        print("=" * 40)
        print(f"Test ID: {report.test_id}")
        print(f"Total Experiments: {report.total_experiments}")
        print(f"Successful: {report.successful_experiments}")
        print(f"Failed: {report.failed_experiments}")
        print(f"Resilience Score: {report.system_resilience_score:.1f}/100")
        print(f"Average Recovery Time: {report.recovery_time_avg:.1f}s")
        
        if report.critical_findings:
            print(f"\n⚠️ Critical Findings:")
            for finding in report.critical_findings:
                print(f"  - {finding}")
        
        print(f"\n📄 Reports saved to chaos_reports/ directory")
        
        # Exit with appropriate code
        if report.system_resilience_score >= 80:
            print("\n✅ Excellent system resilience - Production ready")
            return 0
        elif report.system_resilience_score >= 60:
            print("\n🟡 Good system resilience - Production ready with monitoring")
            return 0
        elif report.system_resilience_score >= 40:
            print("\n⚠️ Fair system resilience - Address issues before production")
            return 1
        else:
            print("\n❌ Poor system resilience - Significant improvements needed")
            return 2
            
    except Exception as e:
        logger.error(f"Chaos engineering failed: {e}")
        return 3

if __name__ == "__main__":
    import sys
    exit_code = asyncio.run(main())
    sys.exit(exit_code)