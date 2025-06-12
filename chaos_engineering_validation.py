#!/usr/bin/env python3
"""
Chaos Engineering Validation Framework
Agent 10 - Ultimate Test Environment Validation

Implements failure injection scenarios across all system layers with recovery analysis.
"""

import asyncio
import json
import logging
import time
import sys
import traceback
import random
import psutil
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import concurrent.futures
import signal

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ChaosScenario(Enum):
    """Types of chaos engineering scenarios."""
    NETWORK_PARTITION = ("network_partition", "Network connectivity failures")
    SERVICE_CRASH = ("service_crash", "Service process crashes")
    MEMORY_EXHAUSTION = ("memory_exhaustion", "Out of memory conditions")
    CPU_SPIKE = ("cpu_spike", "CPU resource exhaustion")
    DISK_FULL = ("disk_full", "Disk space exhaustion")
    CONNECTION_LEAK = ("connection_leak", "Resource connection leaks")
    LATENCY_INJECTION = ("latency_injection", "Network latency spikes")
    CASCADING_FAILURE = ("cascading_failure", "Multiple component failures")
    CONFIGURATION_CORRUPTION = ("config_corruption", "Configuration file corruption")
    DEPENDENCY_FAILURE = ("dependency_failure", "External dependency failures")
    
    def __init__(self, scenario_id: str, description: str):
        self.scenario_id = scenario_id
        self.description = description

@dataclass
class ChaosExperiment:
    """Configuration for a chaos experiment."""
    scenario: ChaosScenario
    duration_seconds: int
    severity: float  # 0.0 (mild) to 1.0 (severe)
    target_components: List[str]
    recovery_timeout: int
    metrics_to_monitor: List[str]

class ChaosEngineeringValidator:
    """Comprehensive chaos engineering validation framework."""
    
    def __init__(self):
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "chaos_experiments": {},
            "recovery_analysis": {},
            "failure_patterns": {},
            "resilience_metrics": {},
            "breaking_point_analysis": {}
        }
        
        # Define chaos experiments
        self.experiments = [
            ChaosExperiment(
                ChaosScenario.NETWORK_PARTITION,
                duration_seconds=30,
                severity=0.5,
                target_components=["api", "database", "mcp_servers"],
                recovery_timeout=60,
                metrics_to_monitor=["response_time", "error_rate", "availability"]
            ),
            ChaosExperiment(
                ChaosScenario.SERVICE_CRASH,
                duration_seconds=15,
                severity=0.7,
                target_components=["circle_of_experts", "mcp_manager"],
                recovery_timeout=30,
                metrics_to_monitor=["restart_time", "data_consistency", "failover_success"]
            ),
            ChaosExperiment(
                ChaosScenario.MEMORY_EXHAUSTION,
                duration_seconds=45,
                severity=0.8,
                target_components=["core_system"],
                recovery_timeout=90,
                metrics_to_monitor=["memory_recovery", "gc_frequency", "system_stability"]
            ),
            ChaosExperiment(
                ChaosScenario.LATENCY_INJECTION,
                duration_seconds=60,
                severity=0.6,
                target_components=["network", "api_endpoints"],
                recovery_timeout=120,
                metrics_to_monitor=["latency_distribution", "timeout_rate", "circuit_breaker_trips"]
            ),
            ChaosExperiment(
                ChaosScenario.CASCADING_FAILURE,
                duration_seconds=90,
                severity=0.9,
                target_components=["all"],
                recovery_timeout=180,
                metrics_to_monitor=["system_availability", "data_integrity", "recovery_time"]
            )
        ]
        
        self.active_chaos = []
        self.recovery_events = []
        self.system_baseline = None
    
    async def run_chaos_validation(self) -> Dict[str, Any]:
        """Execute complete chaos engineering validation."""
        logger.info("Starting chaos engineering validation...")
        
        try:
            # Capture baseline system state
            self.system_baseline = await self._capture_system_baseline()
            self.results["baseline"] = self.system_baseline
            
            # Execute chaos experiments
            for experiment in self.experiments:
                logger.info(f"Executing chaos experiment: {experiment.scenario.description}")
                
                experiment_results = await self._execute_chaos_experiment(experiment)
                self.results["chaos_experiments"][experiment.scenario.scenario_id] = experiment_results
                
                # Recovery period between experiments
                await self._recovery_period(experiment)
            
            # Analyze overall resilience
            self.results["resilience_analysis"] = await self._analyze_system_resilience()
            
            return self.results
            
        except Exception as e:
            logger.error(f"Chaos validation failed: {str(e)}")
            self.results["error"] = str(e)
            self.results["traceback"] = traceback.format_exc()
            return self.results
    
    async def _execute_chaos_experiment(self, experiment: ChaosExperiment) -> Dict[str, Any]:
        """Execute a single chaos experiment."""
        start_time = time.time()
        
        experiment_results = {
            "scenario": experiment.scenario.scenario_id,
            "description": experiment.scenario.description,
            "config": {
                "duration": experiment.duration_seconds,
                "severity": experiment.severity,
                "target_components": experiment.target_components,
                "recovery_timeout": experiment.recovery_timeout
            },
            "start_time": start_time,
            "phases": {},
            "metrics": {},
            "recovery": {},
            "status": "started"
        }
        
        try:
            # Phase 1: Pre-chaos monitoring
            pre_chaos_metrics = await self._monitor_pre_chaos(experiment)
            experiment_results["phases"]["pre_chaos"] = pre_chaos_metrics
            
            # Phase 2: Chaos injection
            chaos_results = await self._inject_chaos(experiment)
            experiment_results["phases"]["chaos_injection"] = chaos_results
            
            # Phase 3: During-chaos monitoring
            during_chaos_metrics = await self._monitor_during_chaos(experiment)
            experiment_results["phases"]["during_chaos"] = during_chaos_metrics
            
            # Phase 4: Recovery observation
            recovery_results = await self._observe_recovery(experiment)
            experiment_results["phases"]["recovery"] = recovery_results
            
            # Phase 5: Post-chaos validation
            post_chaos_metrics = await self._validate_post_chaos(experiment)
            experiment_results["phases"]["post_chaos"] = post_chaos_metrics
            
            # Analyze experiment results
            experiment_results["analysis"] = self._analyze_experiment(experiment_results)
            experiment_results["status"] = "completed"
            
        except Exception as e:
            experiment_results["status"] = "failed"
            experiment_results["error"] = str(e)
            logger.error(f"Chaos experiment {experiment.scenario.scenario_id} failed: {str(e)}")
        
        experiment_results["end_time"] = time.time()
        experiment_results["total_duration"] = experiment_results["end_time"] - start_time
        
        return experiment_results
    
    async def _monitor_pre_chaos(self, experiment: ChaosExperiment) -> Dict[str, Any]:
        """Monitor system state before chaos injection."""
        logger.debug(f"Pre-chaos monitoring for {experiment.scenario.scenario_id}")
        
        start_time = time.time()
        monitoring_duration = 10  # 10 seconds baseline
        
        metrics = {
            "monitoring_duration": monitoring_duration,
            "samples": []
        }
        
        # Collect baseline metrics
        for i in range(monitoring_duration):
            sample = {
                "timestamp": time.time(),
                "cpu_percent": psutil.cpu_percent(interval=0.1),
                "memory_percent": psutil.virtual_memory().percent,
                "memory_mb": psutil.Process().memory_info().rss / 1024 / 1024,
                "disk_io": self._get_disk_io_stats(),
                "network_io": self._get_network_io_stats(),
                "load_average": psutil.getloadavg()[0] if hasattr(psutil, 'getloadavg') else 0
            }
            metrics["samples"].append(sample)
            await asyncio.sleep(1)
        
        # Calculate baseline statistics
        if metrics["samples"]:
            metrics["baseline"] = {
                "cpu_avg": sum(s["cpu_percent"] for s in metrics["samples"]) / len(metrics["samples"]),
                "memory_avg": sum(s["memory_percent"] for s in metrics["samples"]) / len(metrics["samples"]),
                "memory_mb_avg": sum(s["memory_mb"] for s in metrics["samples"]) / len(metrics["samples"]),
                "load_avg": sum(s["load_average"] for s in metrics["samples"]) / len(metrics["samples"])
            }
        
        return metrics
    
    async def _inject_chaos(self, experiment: ChaosExperiment) -> Dict[str, Any]:
        """Inject chaos according to the experiment specification."""
        logger.info(f"Injecting chaos: {experiment.scenario.description}")
        
        injection_results = {
            "scenario": experiment.scenario.scenario_id,
            "injection_time": time.time(),
            "severity": experiment.severity,
            "target_components": experiment.target_components,
            "injection_success": False,
            "effects": []
        }
        
        try:
            # Route to specific chaos injection method
            if experiment.scenario == ChaosScenario.NETWORK_PARTITION:
                effects = await self._inject_network_chaos(experiment)
            elif experiment.scenario == ChaosScenario.SERVICE_CRASH:
                effects = await self._inject_service_crash(experiment)
            elif experiment.scenario == ChaosScenario.MEMORY_EXHAUSTION:
                effects = await self._inject_memory_chaos(experiment)
            elif experiment.scenario == ChaosScenario.LATENCY_INJECTION:
                effects = await self._inject_latency_chaos(experiment)
            elif experiment.scenario == ChaosScenario.CASCADING_FAILURE:
                effects = await self._inject_cascading_chaos(experiment)
            else:
                effects = await self._inject_generic_chaos(experiment)
            
            injection_results["effects"] = effects
            injection_results["injection_success"] = True
            
        except Exception as e:
            injection_results["injection_error"] = str(e)
            logger.error(f"Chaos injection failed: {str(e)}")
        
        return injection_results
    
    async def _inject_network_chaos(self, experiment: ChaosExperiment) -> List[Dict[str, Any]]:
        """Inject network-related chaos (timeouts, packet loss, etc.)."""
        effects = []
        
        # Simulate network latency
        latency_effect = {
            "type": "network_latency",
            "description": "Increased network latency simulation",
            "severity": experiment.severity,
            "duration": experiment.duration_seconds
        }
        
        # Create simulated network delay
        network_delay = experiment.severity * 0.5  # Up to 500ms delay
        
        async def network_chaos_task():
            end_time = time.time() + experiment.duration_seconds
            while time.time() < end_time:
                # Simulate network operations with injected delay
                await asyncio.sleep(network_delay)
                await asyncio.sleep(0.1)  # Base operation time
        
        # Start chaos task
        chaos_task = asyncio.create_task(network_chaos_task())
        effects.append(latency_effect)
        
        # Wait for chaos duration
        await asyncio.sleep(experiment.duration_seconds)
        
        # Clean up
        chaos_task.cancel()
        try:
            await chaos_task
        except asyncio.CancelledError:
            pass
        
        return effects
    
    async def _inject_service_crash(self, experiment: ChaosExperiment) -> List[Dict[str, Any]]:
        """Inject service crash scenarios."""
        effects = []
        
        crash_effect = {
            "type": "service_crash",
            "description": "Simulated service crash and restart",
            "target_services": experiment.target_components,
            "severity": experiment.severity
        }
        
        # Simulate service crash by raising exceptions in mock services
        for component in experiment.target_components:
            try:
                # Simulate service failure
                await self._simulate_service_failure(component, experiment.duration_seconds)
                crash_effect[f"{component}_crashed"] = True
            except Exception as e:
                crash_effect[f"{component}_error"] = str(e)
        
        effects.append(crash_effect)
        return effects
    
    async def _inject_memory_chaos(self, experiment: ChaosExperiment) -> List[Dict[str, Any]]:
        """Inject memory exhaustion scenarios."""
        effects = []
        
        # Allocate memory to simulate exhaustion
        memory_blocks = []
        initial_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        memory_effect = {
            "type": "memory_exhaustion",
            "description": "Memory allocation stress",
            "initial_memory_mb": initial_memory,
            "severity": experiment.severity
        }
        
        try:
            # Calculate memory to allocate based on severity
            target_memory_mb = int(experiment.severity * 500)  # Up to 500MB
            
            # Allocate memory in chunks
            chunk_size_mb = 50
            for i in range(0, target_memory_mb, chunk_size_mb):
                chunk = bytearray(chunk_size_mb * 1024 * 1024)
                memory_blocks.append(chunk)
                
                # Touch memory to ensure allocation
                for j in range(0, len(chunk), 4096):
                    chunk[j] = random.randint(0, 255)
                
                await asyncio.sleep(0.1)
            
            peak_memory = psutil.Process().memory_info().rss / 1024 / 1024
            memory_effect["peak_memory_mb"] = peak_memory
            memory_effect["allocated_mb"] = peak_memory - initial_memory
            
            # Hold memory for duration
            await asyncio.sleep(experiment.duration_seconds)
            
        finally:
            # Clean up memory
            memory_blocks.clear()
            final_memory = psutil.Process().memory_info().rss / 1024 / 1024
            memory_effect["final_memory_mb"] = final_memory
        
        effects.append(memory_effect)
        return effects
    
    async def _inject_latency_chaos(self, experiment: ChaosExperiment) -> List[Dict[str, Any]]:
        """Inject latency-related chaos."""
        effects = []
        
        latency_effect = {
            "type": "latency_injection",
            "description": "Network and processing latency injection",
            "base_latency_ms": experiment.severity * 1000,  # Up to 1000ms
            "jitter_ms": experiment.severity * 200  # Up to 200ms jitter
        }
        
        # Simulate latency injection
        end_time = time.time() + experiment.duration_seconds
        operation_count = 0
        latency_samples = []
        
        while time.time() < end_time:
            # Inject random latency
            base_latency = experiment.severity * 1.0  # Up to 1 second
            jitter = random.uniform(0, experiment.severity * 0.2)  # Up to 200ms jitter
            total_latency = base_latency + jitter
            
            await asyncio.sleep(total_latency)
            
            latency_samples.append(total_latency * 1000)  # Convert to ms
            operation_count += 1
            
            await asyncio.sleep(0.1)  # Base operation time
        
        latency_effect["operations_affected"] = operation_count
        latency_effect["avg_latency_ms"] = sum(latency_samples) / len(latency_samples) if latency_samples else 0
        latency_effect["max_latency_ms"] = max(latency_samples) if latency_samples else 0
        
        effects.append(latency_effect)
        return effects
    
    async def _inject_cascading_chaos(self, experiment: ChaosExperiment) -> List[Dict[str, Any]]:
        """Inject cascading failure scenarios."""
        effects = []
        
        # Execute multiple chaos scenarios in sequence
        cascading_scenarios = [
            ChaosScenario.LATENCY_INJECTION,
            ChaosScenario.MEMORY_EXHAUSTION,
            ChaosScenario.SERVICE_CRASH
        ]
        
        for i, scenario in enumerate(cascading_scenarios):
            # Create mini-experiment for each cascade step
            mini_experiment = ChaosExperiment(
                scenario=scenario,
                duration_seconds=experiment.duration_seconds // len(cascading_scenarios),
                severity=experiment.severity * (0.3 + 0.2 * i),  # Escalating severity
                target_components=experiment.target_components,
                recovery_timeout=30,
                metrics_to_monitor=experiment.metrics_to_monitor
            )
            
            logger.info(f"Cascading failure step {i+1}: {scenario.description}")
            step_effects = await self._inject_single_chaos(mini_experiment)
            
            cascade_effect = {
                "type": "cascade_step",
                "step": i + 1,
                "scenario": scenario.scenario_id,
                "effects": step_effects
            }
            effects.append(cascade_effect)
            
            # Brief pause between cascade steps
            await asyncio.sleep(5)
        
        return effects
    
    async def _inject_single_chaos(self, experiment: ChaosExperiment) -> List[Dict[str, Any]]:
        """Helper to inject a single chaos scenario."""
        if experiment.scenario == ChaosScenario.LATENCY_INJECTION:
            return await self._inject_latency_chaos(experiment)
        elif experiment.scenario == ChaosScenario.MEMORY_EXHAUSTION:
            return await self._inject_memory_chaos(experiment)
        elif experiment.scenario == ChaosScenario.SERVICE_CRASH:
            return await self._inject_service_crash(experiment)
        else:
            return await self._inject_generic_chaos(experiment)
    
    async def _inject_generic_chaos(self, experiment: ChaosExperiment) -> List[Dict[str, Any]]:
        """Generic chaos injection for unspecified scenarios."""
        effects = []
        
        generic_effect = {
            "type": "generic_chaos",
            "description": f"Generic chaos simulation for {experiment.scenario.scenario_id}",
            "severity": experiment.severity,
            "duration": experiment.duration_seconds
        }
        
        # Simulate some generic system stress
        await asyncio.sleep(experiment.duration_seconds)
        
        effects.append(generic_effect)
        return effects
    
    async def _simulate_service_failure(self, component: str, duration: int):
        """Simulate failure of a specific service component."""
        logger.debug(f"Simulating failure of {component} for {duration}s")
        
        # Simulate service downtime
        await asyncio.sleep(duration * 0.1)  # 10% of duration for "crash"
        
        # Simulate restart time
        restart_time = random.uniform(1, 5)  # 1-5 seconds restart
        await asyncio.sleep(restart_time)
        
        # Service is "recovered"
        logger.debug(f"Service {component} recovered after {restart_time:.2f}s")
    
    async def _monitor_during_chaos(self, experiment: ChaosExperiment) -> Dict[str, Any]:
        """Monitor system behavior during chaos injection."""
        logger.debug(f"Monitoring during chaos: {experiment.scenario.scenario_id}")
        
        monitoring_results = {
            "monitoring_duration": experiment.duration_seconds,
            "samples": [],
            "anomalies": []
        }
        
        start_time = time.time()
        end_time = start_time + experiment.duration_seconds
        
        while time.time() < end_time:
            sample = {
                "timestamp": time.time(),
                "cpu_percent": psutil.cpu_percent(interval=0.1),
                "memory_percent": psutil.virtual_memory().percent,
                "memory_mb": psutil.Process().memory_info().rss / 1024 / 1024,
                "disk_io": self._get_disk_io_stats(),
                "network_io": self._get_network_io_stats(),
                "load_average": psutil.getloadavg()[0] if hasattr(psutil, 'getloadavg') else 0
            }
            
            # Detect anomalies
            if self.system_baseline:
                baseline = self.system_baseline.get("baseline", {})
                if (sample["cpu_percent"] > baseline.get("cpu_avg", 0) * 2 or
                    sample["memory_percent"] > baseline.get("memory_avg", 0) * 1.5):
                    anomaly = {
                        "timestamp": sample["timestamp"],
                        "type": "resource_spike",
                        "cpu_percent": sample["cpu_percent"],
                        "memory_percent": sample["memory_percent"]
                    }
                    monitoring_results["anomalies"].append(anomaly)
            
            monitoring_results["samples"].append(sample)
            await asyncio.sleep(1)
        
        return monitoring_results
    
    async def _observe_recovery(self, experiment: ChaosExperiment) -> Dict[str, Any]:
        """Observe system recovery after chaos injection."""
        logger.debug(f"Observing recovery for {experiment.scenario.scenario_id}")
        
        recovery_results = {
            "recovery_timeout": experiment.recovery_timeout,
            "recovery_start": time.time(),
            "recovery_samples": [],
            "recovery_achieved": False,
            "recovery_time": None
        }
        
        start_time = time.time()
        end_time = start_time + experiment.recovery_timeout
        
        # Get baseline for comparison
        baseline = self.system_baseline.get("baseline", {}) if self.system_baseline else {}
        
        while time.time() < end_time:
            sample = {
                "timestamp": time.time(),
                "cpu_percent": psutil.cpu_percent(interval=0.1),
                "memory_percent": psutil.virtual_memory().percent,
                "memory_mb": psutil.Process().memory_info().rss / 1024 / 1024,
                "elapsed_recovery_time": time.time() - start_time
            }
            
            recovery_results["recovery_samples"].append(sample)
            
            # Check if system has recovered to baseline
            if baseline:
                cpu_recovered = abs(sample["cpu_percent"] - baseline.get("cpu_avg", 0)) < 10
                memory_recovered = abs(sample["memory_percent"] - baseline.get("memory_avg", 0)) < 5
                
                if cpu_recovered and memory_recovered and not recovery_results["recovery_achieved"]:
                    recovery_results["recovery_achieved"] = True
                    recovery_results["recovery_time"] = sample["elapsed_recovery_time"]
                    logger.info(f"System recovered in {recovery_results['recovery_time']:.2f}s")
                    break
            
            await asyncio.sleep(1)
        
        return recovery_results
    
    async def _validate_post_chaos(self, experiment: ChaosExperiment) -> Dict[str, Any]:
        """Validate system state after chaos and recovery."""
        logger.debug(f"Post-chaos validation for {experiment.scenario.scenario_id}")
        
        validation_results = {
            "validation_start": time.time(),
            "health_checks": {},
            "data_integrity": {},
            "performance_checks": {}
        }
        
        # System health checks
        validation_results["health_checks"] = {
            "cpu_stable": psutil.cpu_percent(interval=2) < 50,
            "memory_stable": psutil.virtual_memory().percent < 80,
            "disk_accessible": True,  # Simplified check
            "process_responsive": True  # Simplified check
        }
        
        # Performance validation
        performance_samples = []
        for i in range(5):  # 5-second performance check
            sample = {
                "cpu_percent": psutil.cpu_percent(interval=0.2),
                "memory_mb": psutil.Process().memory_info().rss / 1024 / 1024,
                "response_time": await self._measure_response_time()
            }
            performance_samples.append(sample)
            await asyncio.sleep(1)
        
        if performance_samples:
            validation_results["performance_checks"] = {
                "avg_cpu": sum(s["cpu_percent"] for s in performance_samples) / len(performance_samples),
                "avg_memory_mb": sum(s["memory_mb"] for s in performance_samples) / len(performance_samples),
                "avg_response_time": sum(s["response_time"] for s in performance_samples) / len(performance_samples),
                "performance_degradation": self._calculate_performance_degradation(performance_samples)
            }
        
        return validation_results
    
    async def _measure_response_time(self) -> float:
        """Measure mock response time."""
        start = time.time()
        await asyncio.sleep(0.01)  # Simulate operation
        return time.time() - start
    
    def _calculate_performance_degradation(self, samples: List[Dict]) -> float:
        """Calculate performance degradation compared to baseline."""
        if not self.system_baseline or not samples:
            return 0.0
        
        baseline = self.system_baseline.get("baseline", {})
        current_avg_response = sum(s["response_time"] for s in samples) / len(samples)
        baseline_response = baseline.get("avg_response_time", 0.01)
        
        degradation = (current_avg_response - baseline_response) / baseline_response * 100
        return max(0, degradation)
    
    def _get_disk_io_stats(self) -> Dict[str, int]:
        """Get current disk I/O statistics."""
        try:
            disk_io = psutil.disk_io_counters()
            return {
                "read_bytes": disk_io.read_bytes,
                "write_bytes": disk_io.write_bytes,
                "read_time": disk_io.read_time,
                "write_time": disk_io.write_time
            }
        except Exception:
            return {"read_bytes": 0, "write_bytes": 0, "read_time": 0, "write_time": 0}
    
    def _get_network_io_stats(self) -> Dict[str, int]:
        """Get current network I/O statistics."""
        try:
            net_io = psutil.net_io_counters()
            return {
                "bytes_sent": net_io.bytes_sent,
                "bytes_recv": net_io.bytes_recv,
                "packets_sent": net_io.packets_sent,
                "packets_recv": net_io.packets_recv
            }
        except Exception:
            return {"bytes_sent": 0, "bytes_recv": 0, "packets_sent": 0, "packets_recv": 0}
    
    async def _capture_system_baseline(self) -> Dict[str, Any]:
        """Capture baseline system metrics before chaos testing."""
        logger.info("Capturing system baseline...")
        
        baseline_samples = []
        for i in range(10):  # 10-second baseline
            sample = {
                "timestamp": time.time(),
                "cpu_percent": psutil.cpu_percent(interval=0.1),
                "memory_percent": psutil.virtual_memory().percent,
                "memory_mb": psutil.Process().memory_info().rss / 1024 / 1024,
                "response_time": await self._measure_response_time()
            }
            baseline_samples.append(sample)
            await asyncio.sleep(1)
        
        if baseline_samples:
            baseline = {
                "sample_count": len(baseline_samples),
                "cpu_avg": sum(s["cpu_percent"] for s in baseline_samples) / len(baseline_samples),
                "memory_avg": sum(s["memory_percent"] for s in baseline_samples) / len(baseline_samples),
                "memory_mb_avg": sum(s["memory_mb"] for s in baseline_samples) / len(baseline_samples),
                "avg_response_time": sum(s["response_time"] for s in baseline_samples) / len(baseline_samples)
            }
            
            return {
                "timestamp": time.time(),
                "baseline": baseline,
                "samples": baseline_samples
            }
        
        return {"error": "Could not capture baseline"}
    
    async def _recovery_period(self, experiment: ChaosExperiment):
        """Allow system recovery between chaos experiments."""
        recovery_time = 30  # 30 seconds between experiments
        logger.info(f"Recovery period: {recovery_time}s after {experiment.scenario.description}")
        
        for i in range(recovery_time):
            # Monitor recovery
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory_percent = psutil.virtual_memory().percent
            
            if cpu_percent < 20 and memory_percent < 70:
                logger.debug(f"System recovered after {i+1}s")
                break
            
            await asyncio.sleep(1)
    
    def _analyze_experiment(self, experiment_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze individual experiment results."""
        analysis = {
            "experiment_success": experiment_results.get("status") == "completed",
            "chaos_impact": {},
            "recovery_performance": {},
            "resilience_score": 0.0
        }
        
        # Analyze chaos impact
        phases = experiment_results.get("phases", {})
        if "during_chaos" in phases and "pre_chaos" in phases:
            during_metrics = phases["during_chaos"]
            pre_metrics = phases["pre_chaos"]
            
            if during_metrics.get("samples") and pre_metrics.get("baseline"):
                baseline = pre_metrics["baseline"]
                chaos_samples = during_metrics["samples"]
                
                if chaos_samples:
                    avg_cpu_during = sum(s["cpu_percent"] for s in chaos_samples) / len(chaos_samples)
                    avg_memory_during = sum(s["memory_percent"] for s in chaos_samples) / len(chaos_samples)
                    
                    analysis["chaos_impact"] = {
                        "cpu_increase": avg_cpu_during - baseline.get("cpu_avg", 0),
                        "memory_increase": avg_memory_during - baseline.get("memory_avg", 0),
                        "anomaly_count": len(during_metrics.get("anomalies", []))
                    }
        
        # Analyze recovery performance
        if "recovery" in phases:
            recovery = phases["recovery"]
            analysis["recovery_performance"] = {
                "recovery_achieved": recovery.get("recovery_achieved", False),
                "recovery_time": recovery.get("recovery_time", None),
                "timeout_reached": recovery.get("recovery_time") is None
            }
        
        # Calculate resilience score (0-1)
        score_factors = []
        
        if analysis["experiment_success"]:
            score_factors.append(0.3)  # 30% for experiment completion
        
        if analysis["recovery_performance"].get("recovery_achieved"):
            score_factors.append(0.4)  # 40% for successful recovery
        
        recovery_time = analysis["recovery_performance"].get("recovery_time")
        if recovery_time is not None:
            # Better score for faster recovery (max 30 seconds)
            time_score = max(0, (30 - recovery_time) / 30) * 0.3
            score_factors.append(time_score)
        
        analysis["resilience_score"] = sum(score_factors)
        
        return analysis
    
    async def _analyze_system_resilience(self) -> Dict[str, Any]:
        """Analyze overall system resilience based on all experiments."""
        resilience_analysis = {
            "overall_resilience_score": 0.0,
            "weakest_points": [],
            "strongest_aspects": [],
            "recovery_patterns": {},
            "recommendations": []
        }
        
        # Calculate overall resilience score
        experiment_scores = []
        weakest_experiments = []
        strongest_experiments = []
        
        for exp_id, exp_data in self.results["chaos_experiments"].items():
            if "analysis" in exp_data:
                score = exp_data["analysis"].get("resilience_score", 0.0)
                experiment_scores.append(score)
                
                if score < 0.5:
                    weakest_experiments.append((exp_id, score))
                elif score > 0.8:
                    strongest_experiments.append((exp_id, score))
        
        if experiment_scores:
            resilience_analysis["overall_resilience_score"] = sum(experiment_scores) / len(experiment_scores)
        
        # Identify weak points
        resilience_analysis["weakest_points"] = [
            {"experiment": exp_id, "score": score} 
            for exp_id, score in sorted(weakest_experiments, key=lambda x: x[1])
        ]
        
        # Identify strong aspects
        resilience_analysis["strongest_aspects"] = [
            {"experiment": exp_id, "score": score}
            for exp_id, score in sorted(strongest_experiments, key=lambda x: x[1], reverse=True)
        ]
        
        # Generate recommendations
        overall_score = resilience_analysis["overall_resilience_score"]
        recommendations = []
        
        if overall_score < 0.3:
            recommendations.append("Critical: System shows poor resilience - immediate improvements needed")
        elif overall_score < 0.6:
            recommendations.append("Warning: System resilience below acceptable levels")
        elif overall_score < 0.8:
            recommendations.append("Good: System shows adequate resilience with room for improvement")
        else:
            recommendations.append("Excellent: System demonstrates strong resilience capabilities")
        
        if weakest_experiments:
            recommendations.append(f"Focus improvement efforts on: {', '.join([e[0] for e in weakest_experiments[:3]])}")
        
        resilience_analysis["recommendations"] = recommendations
        
        return resilience_analysis

async def main():
    """Main chaos engineering validation execution."""
    validator = ChaosEngineeringValidator()
    
    try:
        logger.info("Starting chaos engineering validation...")
        results = await validator.run_chaos_validation()
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = f"chaos_engineering_validation_{timestamp}.json"
        
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n{'='*80}")
        print("CHAOS ENGINEERING VALIDATION COMPLETE")
        print(f"{'='*80}")
        
        # Summary
        experiments_completed = len([exp for exp in results["chaos_experiments"].values() 
                                   if exp.get("status") == "completed"])
        total_experiments = len(results["chaos_experiments"])
        
        print(f"Chaos Experiments Completed: {experiments_completed}/{total_experiments}")
        
        if "resilience_analysis" in results:
            analysis = results["resilience_analysis"]
            resilience_score = analysis.get("overall_resilience_score", 0.0)
            print(f"Overall Resilience Score: {resilience_score:.2f}/1.00")
            
            print("\nRecommendations:")
            for rec in analysis.get("recommendations", []):
                print(f"  - {rec}")
            
            if analysis.get("weakest_points"):
                print("\nAreas for improvement:")
                for weakness in analysis["weakest_points"][:3]:
                    print(f"  - {weakness['experiment']}: {weakness['score']:.2f}")
        
        print(f"\nDetailed results saved to: {results_file}")
        
        return experiments_completed >= total_experiments * 0.8  # 80% success threshold
        
    except Exception as e:
        logger.error(f"Chaos engineering validation failed: {str(e)}")
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)