"""
Chaos Test Pipeline - Chaos engineering pipeline for resilience testing.

This module provides chaos engineering capabilities to test system resilience
by introducing controlled failures and monitoring system recovery.
"""

import asyncio
import json
import logging
import random
import signal
import subprocess
import time
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
import threading

import psutil
from prometheus_client import Counter, Histogram, Gauge

logger = logging.getLogger(__name__)

# Metrics
chaos_experiments_total = Counter('chaos_experiments_total', 'Total chaos experiments', ['experiment_type'])
chaos_experiment_duration = Histogram('chaos_experiment_duration_seconds', 'Chaos experiment duration')
system_recovery_time = Histogram('system_recovery_time_seconds', 'System recovery time after chaos')
chaos_failures = Counter('chaos_failures_total', 'Chaos experiment failures', ['failure_type'])
system_availability = Gauge('system_availability_percent', 'System availability during chaos')


class ChaosExperimentType(Enum):
    """Types of chaos experiments."""
    PROCESS_KILLER = "process_killer"
    NETWORK_PARTITION = "network_partition"
    DISK_FILL = "disk_fill"
    MEMORY_LEAK = "memory_leak"
    CPU_BURN = "cpu_burn"
    NETWORK_LATENCY = "network_latency"
    PACKET_LOSS = "packet_loss"
    DEPENDENCY_FAILURE = "dependency_failure"
    RANDOM_FAILURE = "random_failure"


class ImpactLevel(Enum):
    """Impact levels for chaos experiments."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ChaosExperimentConfig:
    """Chaos experiment configuration."""
    experiment_type: ChaosExperimentType
    impact_level: ImpactLevel
    duration_seconds: int = 60
    target_processes: List[str] = field(default_factory=list)
    target_services: List[str] = field(default_factory=list)
    network_interfaces: List[str] = field(default_factory=list)
    recovery_timeout: int = 300  # Maximum time to wait for recovery
    health_check_interval: int = 5  # Health check interval in seconds
    rollback_on_failure: bool = True
    experiment_parameters: Dict[str, Any] = field(default_factory=dict)
    safety_limits: Dict[str, float] = field(default_factory=lambda: {
        'max_cpu_usage': 95.0,
        'max_memory_usage': 90.0,
        'min_disk_space_mb': 1024
    })


@dataclass
class ChaosExperimentResult:
    """Chaos experiment result."""
    experiment_type: ChaosExperimentType
    impact_level: ImpactLevel
    start_time: datetime
    end_time: datetime
    duration: float
    experiment_successful: bool
    system_recovered: bool
    recovery_time: float
    availability_during_experiment: float
    health_checks_failed: int
    health_checks_total: int
    baseline_metrics: Dict[str, float]
    impact_metrics: Dict[str, float]
    recovery_metrics: Dict[str, float]
    timeline: List[Dict[str, Any]]
    errors: List[str]
    warnings: List[str]
    rollback_performed: bool
    lessons_learned: List[str]


class ProcessKillerExperiment:
    """Process killer chaos experiment."""
    
    def __init__(self, config: ChaosExperimentConfig):
        self.config = config
        self.killed_processes = []
        self.stop_event = threading.Event()
        
    async def execute(self) -> ChaosExperimentResult:
        """Execute process killer experiment."""
        start_time = datetime.now()
        timeline = []
        errors = []
        warnings = []
        
        timeline.append({
            'timestamp': start_time.isoformat(),
            'event': 'experiment_started',
            'details': f'Starting process killer experiment'
        })
        
        # Collect baseline metrics
        baseline_metrics = await self._collect_baseline_metrics()
        
        try:
            # Start health monitoring
            health_task = asyncio.create_task(self._monitor_health(timeline))
            
            # Execute chaos - kill target processes
            await self._kill_target_processes(timeline, errors)
            
            # Wait for experiment duration
            await asyncio.sleep(self.config.duration_seconds)
            
            # Stop experiment
            self.stop_event.set()
            
            # Collect impact metrics
            impact_metrics = await self._collect_impact_metrics()
            
            # Monitor recovery
            recovery_start = time.time()
            system_recovered = await self._wait_for_recovery(timeline)
            recovery_time = time.time() - recovery_start
            
            # Collect recovery metrics
            recovery_metrics = await self._collect_recovery_metrics()
            
            # Stop health monitoring
            health_task.cancel()
            
        except Exception as e:
            errors.append(f"Experiment execution error: {e}")
            system_recovered = False
            recovery_time = 0
            impact_metrics = {}
            recovery_metrics = {}
            
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        timeline.append({
            'timestamp': end_time.isoformat(),
            'event': 'experiment_completed',
            'details': f'Experiment completed in {duration:.2f}s'
        })
        
        return ChaosExperimentResult(
            experiment_type=self.config.experiment_type,
            impact_level=self.config.impact_level,
            start_time=start_time,
            end_time=end_time,
            duration=duration,
            experiment_successful=len(errors) == 0,
            system_recovered=system_recovered,
            recovery_time=recovery_time,
            availability_during_experiment=self._calculate_availability(timeline),
            health_checks_failed=self._count_failed_health_checks(timeline),
            health_checks_total=self._count_total_health_checks(timeline),
            baseline_metrics=baseline_metrics,
            impact_metrics=impact_metrics,
            recovery_metrics=recovery_metrics,
            timeline=timeline,
            errors=errors,
            warnings=warnings,
            rollback_performed=False,  # Would be set if rollback was needed
            lessons_learned=self._extract_lessons_learned(timeline, errors, warnings)
        )
        
    async def _collect_baseline_metrics(self) -> Dict[str, float]:
        """Collect baseline system metrics."""
        return {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_percent': psutil.disk_usage('/').percent,
            'process_count': len(psutil.pids()),
            'load_average': psutil.getloadavg()[0] if hasattr(psutil, 'getloadavg') else 0
        }
        
    async def _collect_impact_metrics(self) -> Dict[str, float]:
        """Collect metrics during chaos impact."""
        return await self._collect_baseline_metrics()
        
    async def _collect_recovery_metrics(self) -> Dict[str, float]:
        """Collect metrics after recovery."""
        return await self._collect_baseline_metrics()
        
    async def _kill_target_processes(self, timeline: List[Dict[str, Any]], errors: List[str]) -> None:
        """Kill target processes for chaos experiment."""
        try:
            for process_pattern in self.config.target_processes:
                killed_count = 0
                
                for process in psutil.process_iter(['pid', 'name', 'cmdline']):
                    try:
                        if self._matches_pattern(process, process_pattern):
                            process.terminate()
                            self.killed_processes.append({
                                'pid': process.info['pid'],
                                'name': process.info['name'],
                                'kill_time': time.time()
                            })
                            killed_count += 1
                            
                            timeline.append({
                                'timestamp': datetime.now().isoformat(),
                                'event': 'process_killed',
                                'details': f'Killed process {process.info["name"]} (PID: {process.info["pid"]})'
                            })
                            
                    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                        warnings.append(f"Could not kill process: {e}")
                        
                logger.info(f"Killed {killed_count} processes matching pattern '{process_pattern}'")
                
        except Exception as e:
            errors.append(f"Process killing error: {e}")
            
    def _matches_pattern(self, process: psutil.Process, pattern: str) -> bool:
        """Check if process matches the given pattern."""
        try:
            name = process.info.get('name', '')
            cmdline = ' '.join(process.info.get('cmdline', []))
            
            return (pattern.lower() in name.lower() or 
                   pattern.lower() in cmdline.lower())
        except:
            return False
            
    async def _monitor_health(self, timeline: List[Dict[str, Any]]) -> None:
        """Monitor system health during experiment."""
        while not self.stop_event.is_set():
            try:
                # Perform health checks
                health_status = await self._perform_health_check()
                
                timeline.append({
                    'timestamp': datetime.now().isoformat(),
                    'event': 'health_check',
                    'details': health_status
                })
                
                await asyncio.sleep(self.config.health_check_interval)
                
            except Exception as e:
                timeline.append({
                    'timestamp': datetime.now().isoformat(),
                    'event': 'health_check_error',
                    'details': f'Health check failed: {e}'
                })
                
    async def _perform_health_check(self) -> Dict[str, Any]:
        """Perform system health check."""
        cpu_percent = psutil.cpu_percent()
        memory_percent = psutil.virtual_memory().percent
        disk_usage = psutil.disk_usage('/')
        
        health_status = {
            'cpu_healthy': cpu_percent < self.config.safety_limits['max_cpu_usage'],
            'memory_healthy': memory_percent < self.config.safety_limits['max_memory_usage'],
            'disk_healthy': disk_usage.free > self.config.safety_limits['min_disk_space_mb'] * 1024 * 1024,
            'cpu_percent': cpu_percent,
            'memory_percent': memory_percent,
            'disk_free_mb': disk_usage.free // (1024 * 1024)
        }
        
        health_status['overall_healthy'] = all([
            health_status['cpu_healthy'],
            health_status['memory_healthy'],
            health_status['disk_healthy']
        ])
        
        return health_status
        
    async def _wait_for_recovery(self, timeline: List[Dict[str, Any]]) -> bool:
        """Wait for system recovery after chaos."""
        recovery_start = time.time()
        
        while time.time() - recovery_start < self.config.recovery_timeout:
            health_status = await self._perform_health_check()
            
            if health_status['overall_healthy']:
                timeline.append({
                    'timestamp': datetime.now().isoformat(),
                    'event': 'system_recovered',
                    'details': f'System recovered after {time.time() - recovery_start:.2f}s'
                })
                return True
                
            await asyncio.sleep(self.config.health_check_interval)
            
        timeline.append({
            'timestamp': datetime.now().isoformat(),
            'event': 'recovery_timeout',
            'details': f'System did not recover within {self.config.recovery_timeout}s'
        })
        
        return False
        
    def _calculate_availability(self, timeline: List[Dict[str, Any]]) -> float:
        """Calculate system availability during experiment."""
        health_checks = [event for event in timeline if event['event'] == 'health_check']
        
        if not health_checks:
            return 0.0
            
        healthy_checks = sum(1 for event in health_checks 
                           if event['details'].get('overall_healthy', False))
        
        return (healthy_checks / len(health_checks)) * 100
        
    def _count_failed_health_checks(self, timeline: List[Dict[str, Any]]) -> int:
        """Count failed health checks."""
        return sum(1 for event in timeline 
                  if event['event'] == 'health_check' and 
                  not event['details'].get('overall_healthy', False))
                  
    def _count_total_health_checks(self, timeline: List[Dict[str, Any]]) -> int:
        """Count total health checks."""
        return sum(1 for event in timeline if event['event'] == 'health_check')
        
    def _extract_lessons_learned(self, timeline: List[Dict[str, Any]], 
                                errors: List[str], warnings: List[str]) -> List[str]:
        """Extract lessons learned from the experiment."""
        lessons = []
        
        # Analyze recovery time
        recovery_events = [e for e in timeline if e['event'] == 'system_recovered']
        if recovery_events:
            lessons.append("System demonstrated good recovery capabilities")
        else:
            lessons.append("System recovery needs improvement")
            
        # Analyze process resilience
        killed_processes = [e for e in timeline if e['event'] == 'process_killed']
        if killed_processes:
            lessons.append(f"System handled {len(killed_processes)} process failures")
            
        # Analyze errors
        if errors:
            lessons.append(f"Identified {len(errors)} critical issues requiring attention")
            
        return lessons


class NetworkPartitionExperiment:
    """Network partition chaos experiment."""
    
    def __init__(self, config: ChaosExperimentConfig):
        self.config = config
        self.network_rules = []
        
    async def execute(self) -> ChaosExperimentResult:
        """Execute network partition experiment."""
        start_time = datetime.now()
        timeline = []
        errors = []
        warnings = []
        
        try:
            # Apply network partition
            await self._apply_network_partition(timeline, errors)
            
            # Wait for experiment duration
            await asyncio.sleep(self.config.duration_seconds)
            
            # Remove network partition
            await self._remove_network_partition(timeline, errors)
            
        except Exception as e:
            errors.append(f"Network partition experiment error: {e}")
            
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Create minimal result (full implementation would be more comprehensive)
        return ChaosExperimentResult(
            experiment_type=self.config.experiment_type,
            impact_level=self.config.impact_level,
            start_time=start_time,
            end_time=end_time,
            duration=duration,
            experiment_successful=len(errors) == 0,
            system_recovered=True,  # Simplified
            recovery_time=0.0,
            availability_during_experiment=50.0,  # Simplified
            health_checks_failed=0,
            health_checks_total=0,
            baseline_metrics={},
            impact_metrics={},
            recovery_metrics={},
            timeline=timeline,
            errors=errors,
            warnings=warnings,
            rollback_performed=True,
            lessons_learned=["Network partition experiment completed"]
        )
        
    async def _apply_network_partition(self, timeline: List[Dict[str, Any]], errors: List[str]) -> None:
        """Apply network partition using iptables or tc."""
        try:
            # Example: Block traffic to specific hosts/ports
            target_hosts = self.config.experiment_parameters.get('target_hosts', [])
            
            for host in target_hosts:
                # Use iptables to block traffic (requires root)
                cmd = f"iptables -A OUTPUT -d {host} -j DROP"
                
                try:
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    if result.returncode == 0:
                        self.network_rules.append(cmd)
                        timeline.append({
                            'timestamp': datetime.now().isoformat(),
                            'event': 'network_partition_applied',
                            'details': f'Blocked traffic to {host}'
                        })
                    else:
                        errors.append(f"Failed to apply network rule: {result.stderr}")
                        
                except Exception as e:
                    errors.append(f"Network partition error for {host}: {e}")
                    
        except Exception as e:
            errors.append(f"Network partition setup error: {e}")
            
    async def _remove_network_partition(self, timeline: List[Dict[str, Any]], errors: List[str]) -> None:
        """Remove network partition rules."""
        try:
            for rule in self.network_rules:
                # Convert ADD to DELETE rule
                delete_rule = rule.replace('-A', '-D')
                
                try:
                    result = subprocess.run(delete_rule, shell=True, capture_output=True, text=True)
                    timeline.append({
                        'timestamp': datetime.now().isoformat(),
                        'event': 'network_partition_removed',
                        'details': f'Removed network rule'
                    })
                except Exception as e:
                    errors.append(f"Failed to remove network rule: {e}")
                    
            self.network_rules.clear()
            
        except Exception as e:
            errors.append(f"Network partition removal error: {e}")


class ChaosTestPipeline:
    """Comprehensive chaos testing pipeline."""
    
    def __init__(self):
        self.experiment_implementations = {
            ChaosExperimentType.PROCESS_KILLER: ProcessKillerExperiment,
            ChaosExperimentType.NETWORK_PARTITION: NetworkPartitionExperiment,
            # Additional implementations would be added here
        }
        
    async def execute_chaos_experiment(self, config: ChaosExperimentConfig) -> ChaosExperimentResult:
        """Execute a chaos experiment."""
        chaos_experiments_total.labels(experiment_type=config.experiment_type.value).inc()
        
        experiment_class = self.experiment_implementations.get(config.experiment_type)
        if not experiment_class:
            raise ValueError(f"Unsupported chaos experiment: {config.experiment_type}")
            
        experiment = experiment_class(config)
        
        try:
            start_time = time.time()
            result = await experiment.execute()
            duration = time.time() - start_time
            
            chaos_experiment_duration.observe(duration)
            system_recovery_time.observe(result.recovery_time)
            system_availability.set(result.availability_during_experiment)
            
            logger.info(f"Chaos experiment {config.experiment_type.value} completed")
            return result
            
        except Exception as e:
            chaos_failures.labels(failure_type='execution_error').inc()
            logger.error(f"Chaos experiment {config.experiment_type.value} failed: {e}")
            raise
            
    async def execute_chaos_suite(self, configs: List[ChaosExperimentConfig]) -> List[ChaosExperimentResult]:
        """Execute a suite of chaos experiments."""
        results = []
        
        for config in configs:
            try:
                # Safety check before each experiment
                if await self._safety_check():
                    result = await self.execute_chaos_experiment(config)
                    results.append(result)
                    
                    # Recovery time between experiments
                    await asyncio.sleep(60)
                else:
                    logger.warning(f"Skipping {config.experiment_type.value} due to safety check failure")
                    
            except Exception as e:
                logger.error(f"Failed to execute chaos experiment {config.experiment_type.value}: {e}")
                
        return results
        
    async def _safety_check(self) -> bool:
        """Perform safety check before chaos experiment."""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory_percent = psutil.virtual_memory().percent
            
            # Don't run chaos if system is already stressed
            if cpu_percent > 80 or memory_percent > 80:
                return False
                
            return True
            
        except Exception as e:
            logger.warning(f"Safety check error: {e}")
            return False
            
    def create_chaos_experiment_suite(self) -> List[ChaosExperimentConfig]:
        """Create a comprehensive chaos experiment suite."""
        return [
            # Process killer experiment
            ChaosExperimentConfig(
                experiment_type=ChaosExperimentType.PROCESS_KILLER,
                impact_level=ImpactLevel.MEDIUM,
                duration_seconds=60,
                target_processes=['test_process', 'dummy_service'],
                recovery_timeout=120
            ),
            
            # Network partition experiment
            ChaosExperimentConfig(
                experiment_type=ChaosExperimentType.NETWORK_PARTITION,
                impact_level=ImpactLevel.HIGH,
                duration_seconds=90,
                experiment_parameters={
                    'target_hosts': ['127.0.0.1', 'localhost']
                },
                recovery_timeout=180
            )
        ]
        
    def export_chaos_results(self, results: List[ChaosExperimentResult], output_path: str) -> None:
        """Export chaos experiment results."""
        export_data = []
        
        for result in results:
            data = {
                'experiment_type': result.experiment_type.value,
                'impact_level': result.impact_level.value,
                'start_time': result.start_time.isoformat(),
                'end_time': result.end_time.isoformat(),
                'duration': result.duration,
                'experiment_successful': result.experiment_successful,
                'system_recovered': result.system_recovered,
                'recovery_time': result.recovery_time,
                'availability_during_experiment': result.availability_during_experiment,
                'health_checks_failed': result.health_checks_failed,
                'health_checks_total': result.health_checks_total,
                'baseline_metrics': result.baseline_metrics,
                'impact_metrics': result.impact_metrics,
                'recovery_metrics': result.recovery_metrics,
                'timeline': result.timeline,
                'errors': result.errors,
                'warnings': result.warnings,
                'rollback_performed': result.rollback_performed,
                'lessons_learned': result.lessons_learned
            }
            export_data.append(data)
            
        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2)
            
        logger.info(f"Exported chaos experiment results to {output_path}")


# Example usage
if __name__ == "__main__":
    async def main():
        pipeline = ChaosTestPipeline()
        
        # Create and execute chaos experiment suite
        chaos_configs = pipeline.create_chaos_experiment_suite()
        results = await pipeline.execute_chaos_suite(chaos_configs)
        
        # Export results
        pipeline.export_chaos_results(results, "chaos_experiment_results.json")
        
        # Print summary
        for result in results:
            print(f"Experiment: {result.experiment_type.value}")
            print(f"  Success: {result.experiment_successful}")
            print(f"  Recovered: {result.system_recovered}")
            print(f"  Recovery Time: {result.recovery_time:.2f}s")
            print(f"  Availability: {result.availability_during_experiment:.1f}%")
            print(f"  Lessons: {len(result.lessons_learned)}")
            print()
            
    asyncio.run(main())