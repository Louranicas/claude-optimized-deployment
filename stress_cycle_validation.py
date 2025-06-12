#!/usr/bin/env python3
"""
Stress Cycle Validation Framework
Agent 10 - Ultimate Test Environment Validation

Implements 7-phase stress cycle testing from baseline to chaos with intelligent ramping.
"""

import asyncio
import json
import logging
import time
import sys
import traceback
import random
import psutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import concurrent.futures
import threading

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class StressPhase(Enum):
    """Stress testing phases from idle to chaos."""
    IDLE = (0, "Idle", "Baseline system performance")
    LIGHT = (1, "Light Load", "Normal operational load")
    MODERATE = (2, "Moderate Load", "Peak operational load")
    HEAVY = (3, "Heavy Load", "Above normal capacity")
    EXTREME = (4, "Extreme Load", "Maximum designed capacity")
    BREAKING = (5, "Breaking Point", "Beyond design limits")
    CHAOS = (6, "Chaos", "System failure scenarios")
    
    def __init__(self, level: int, name: str, description: str):
        self.level = level
        self.phase_name = name
        self.description = description

@dataclass
class StressConfiguration:
    """Configuration for stress testing parameters."""
    concurrent_tasks: int
    request_rate: int  # requests per second
    data_volume_mb: int
    memory_pressure_mb: int
    cpu_pressure_percent: int
    duration_seconds: int
    failure_injection_rate: float  # 0.0 to 1.0
    network_delay_ms: int
    disk_io_intensity: int

class StressCycleValidator:
    """Comprehensive stress cycle validation framework."""
    
    def __init__(self):
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "stress_cycles": {},
            "performance_metrics": {},
            "failure_analysis": {},
            "breaking_points": {},
            "recovery_analysis": {}
        }
        
        # Define stress configurations for each phase
        self.phase_configs = {
            StressPhase.IDLE: StressConfiguration(1, 1, 1, 10, 5, 30, 0.0, 0, 1),
            StressPhase.LIGHT: StressConfiguration(10, 10, 10, 50, 15, 60, 0.01, 10, 5),
            StressPhase.MODERATE: StressConfiguration(50, 50, 50, 100, 30, 60, 0.02, 25, 10),
            StressPhase.HEAVY: StressConfiguration(100, 100, 100, 200, 50, 60, 0.05, 50, 20),
            StressPhase.EXTREME: StressConfiguration(200, 200, 200, 400, 70, 60, 0.10, 100, 40),
            StressPhase.BREAKING: StressConfiguration(500, 500, 500, 800, 85, 60, 0.20, 200, 80),
            StressPhase.CHAOS: StressConfiguration(1000, 1000, 1000, 1000, 95, 60, 0.50, 500, 100)
        }
        
        self.safety_limits = {
            "max_memory_mb": 2000,
            "max_cpu_percent": 90,
            "max_disk_usage_percent": 80
        }
        
        self.circuit_breaker_active = False
        self.emergency_shutdown = False
    
    async def run_full_stress_cycle(self) -> Dict[str, Any]:
        """Execute complete 7-phase stress cycle."""
        logger.info("Starting complete 7-phase stress cycle validation...")
        
        try:
            # Pre-test system state
            initial_state = self._capture_system_state()
            self.results["initial_state"] = initial_state
            
            # Execute all stress phases
            for phase in StressPhase:
                if self.emergency_shutdown:
                    logger.warning("Emergency shutdown activated, stopping stress cycle")
                    break
                
                logger.info(f"Executing {phase.phase_name} (Phase {phase.level})")
                phase_results = await self._execute_stress_phase(phase)
                self.results["stress_cycles"][phase.phase_name] = phase_results
                
                # Check safety conditions
                if not self._check_safety_conditions():
                    logger.warning(f"Safety limits exceeded during {phase.phase_name}")
                    self.emergency_shutdown = True
                    break
                
                # Recovery period between phases
                await self._recovery_period(phase)
            
            # Post-test analysis
            final_state = self._capture_system_state()
            self.results["final_state"] = final_state
            self.results["analysis"] = self._analyze_stress_results()
            
            return self.results
            
        except Exception as e:
            logger.error(f"Stress cycle failed: {str(e)}")
            self.results["error"] = str(e)
            self.results["traceback"] = traceback.format_exc()
            return self.results
    
    async def _execute_stress_phase(self, phase: StressPhase) -> Dict[str, Any]:
        """Execute a single stress testing phase."""
        config = self.phase_configs[phase]
        start_time = time.time()
        
        phase_results = {
            "phase": phase.phase_name,
            "level": phase.level,
            "description": phase.description,
            "config": config.__dict__,
            "start_time": start_time,
            "metrics": {},
            "errors": [],
            "warnings": []
        }
        
        try:
            # Initialize stress testing components
            stress_tasks = []
            
            # Memory pressure simulation
            memory_task = asyncio.create_task(
                self._simulate_memory_pressure(config.memory_pressure_mb, config.duration_seconds)
            )
            stress_tasks.append(memory_task)
            
            # CPU pressure simulation  
            cpu_task = asyncio.create_task(
                self._simulate_cpu_pressure(config.cpu_pressure_percent, config.duration_seconds)
            )
            stress_tasks.append(cpu_task)
            
            # Concurrent request simulation
            request_task = asyncio.create_task(
                self._simulate_request_load(config.concurrent_tasks, config.request_rate, config.duration_seconds)
            )
            stress_tasks.append(request_task)
            
            # Data processing simulation
            data_task = asyncio.create_task(
                self._simulate_data_processing(config.data_volume_mb, config.duration_seconds)
            )
            stress_tasks.append(data_task)
            
            # Failure injection (if configured)
            if config.failure_injection_rate > 0:
                failure_task = asyncio.create_task(
                    self._inject_failures(config.failure_injection_rate, config.duration_seconds)
                )
                stress_tasks.append(failure_task)
            
            # Monitor system during stress
            monitoring_task = asyncio.create_task(
                self._monitor_system_during_stress(config.duration_seconds)
            )
            stress_tasks.append(monitoring_task)
            
            # Execute all stress tasks
            results = await asyncio.gather(*stress_tasks, return_exceptions=True)
            
            # Process results
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    phase_results["errors"].append(f"Task {i} failed: {str(result)}")
                elif isinstance(result, dict):
                    phase_results["metrics"].update(result)
            
            end_time = time.time()
            phase_results["end_time"] = end_time
            phase_results["duration"] = end_time - start_time
            phase_results["status"] = "completed" if not phase_results["errors"] else "failed"
            
        except Exception as e:
            phase_results["status"] = "error"
            phase_results["error"] = str(e)
            logger.error(f"Phase {phase.phase_name} failed: {str(e)}")
        
        return phase_results
    
    async def _simulate_memory_pressure(self, target_mb: int, duration: int) -> Dict[str, Any]:
        """Simulate memory pressure by allocating and manipulating data."""
        logger.debug(f"Simulating {target_mb}MB memory pressure for {duration}s")
        
        start_memory = psutil.Process().memory_info().rss / 1024 / 1024
        allocated_blocks = []
        
        try:
            # Allocate memory in chunks
            chunk_size = min(target_mb // 10, 50)  # Max 50MB per chunk
            for _ in range(0, target_mb, chunk_size):
                if self.emergency_shutdown:
                    break
                
                # Allocate memory block
                block = bytearray(chunk_size * 1024 * 1024)
                allocated_blocks.append(block)
                
                # Write random data to ensure allocation
                for i in range(0, len(block), 4096):
                    block[i] = random.randint(0, 255)
                
                await asyncio.sleep(0.1)  # Allow other tasks to run
            
            # Hold memory for duration
            end_time = time.time() + duration
            while time.time() < end_time and not self.emergency_shutdown:
                # Periodically access memory to prevent optimization
                if allocated_blocks:
                    random_block = random.choice(allocated_blocks)
                    random_index = random.randint(0, len(random_block) - 1)
                    random_block[random_index] = random.randint(0, 255)
                
                await asyncio.sleep(1)
            
            peak_memory = psutil.Process().memory_info().rss / 1024 / 1024
            
            return {
                "memory_start_mb": start_memory,
                "memory_peak_mb": peak_memory,
                "memory_allocated_mb": peak_memory - start_memory,
                "memory_target_mb": target_mb,
                "blocks_allocated": len(allocated_blocks)
            }
            
        finally:
            # Clean up allocated memory
            allocated_blocks.clear()
    
    async def _simulate_cpu_pressure(self, target_percent: int, duration: int) -> Dict[str, Any]:
        """Simulate CPU pressure through computational workload."""
        logger.debug(f"Simulating {target_percent}% CPU pressure for {duration}s")
        
        cpu_count = psutil.cpu_count()
        target_workers = max(1, int(cpu_count * target_percent / 100))
        
        def cpu_intensive_work(work_duration: float):
            """CPU-intensive computation."""
            end_time = time.time() + work_duration
            operations = 0
            while time.time() < end_time:
                # Perform meaningless but CPU-intensive operations
                for i in range(10000):
                    _ = i ** 2 + i ** 3 - i ** 0.5
                operations += 10000
                if time.time() % 1 < 0.01:  # Check for shutdown periodically
                    if self.emergency_shutdown:
                        break
            return operations
        
        start_time = time.time()
        start_cpu = psutil.cpu_percent(interval=1)
        
        # Launch CPU workers
        with concurrent.futures.ThreadPoolExecutor(max_workers=target_workers) as executor:
            futures = []
            for _ in range(target_workers):
                future = executor.submit(cpu_intensive_work, duration)
                futures.append(future)
            
            # Monitor CPU usage during workload
            cpu_samples = []
            while any(not f.done() for f in futures):
                cpu_samples.append(psutil.cpu_percent(interval=0.5))
                if self.emergency_shutdown:
                    break
            
            # Collect results
            total_operations = 0
            for future in concurrent.futures.as_completed(futures, timeout=duration + 10):
                try:
                    operations = future.result()
                    total_operations += operations
                except Exception as e:
                    logger.warning(f"CPU worker failed: {e}")
        
        end_cpu = psutil.cpu_percent(interval=1)
        
        return {
            "cpu_start_percent": start_cpu,
            "cpu_end_percent": end_cpu,
            "cpu_peak_percent": max(cpu_samples) if cpu_samples else 0,
            "cpu_avg_percent": sum(cpu_samples) / len(cpu_samples) if cpu_samples else 0,
            "cpu_target_percent": target_percent,
            "total_operations": total_operations,
            "workers_used": target_workers
        }
    
    async def _simulate_request_load(self, concurrent_tasks: int, rate: int, duration: int) -> Dict[str, Any]:
        """Simulate concurrent request processing load."""
        logger.debug(f"Simulating {concurrent_tasks} concurrent tasks at {rate} req/s for {duration}s")
        
        async def mock_request_handler(request_id: int):
            """Mock request processing."""
            start_time = time.time()
            
            # Simulate request processing time (10-100ms)
            processing_time = random.uniform(0.01, 0.1)
            
            # Simulate some work
            data = {"request_id": request_id, "data": list(range(100))}
            await asyncio.sleep(processing_time)
            
            # Simulate failure injection
            config = self.phase_configs.get(StressPhase.CHAOS, self.phase_configs[StressPhase.IDLE])
            if random.random() < config.failure_injection_rate:
                raise Exception(f"Injected failure for request {request_id}")
            
            return {
                "request_id": request_id,
                "processing_time": processing_time,
                "status": "success"
            }
        
        start_time = time.time()
        end_time = start_time + duration
        
        completed_requests = 0
        failed_requests = 0
        total_processing_time = 0
        
        # Request generation loop
        while time.time() < end_time and not self.emergency_shutdown:
            # Create batch of concurrent requests
            tasks = []
            for i in range(min(concurrent_tasks, rate)):
                task = asyncio.create_task(mock_request_handler(completed_requests + i))
                tasks.append(task)
            
            # Process batch
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for result in results:
                if isinstance(result, Exception):
                    failed_requests += 1
                elif isinstance(result, dict):
                    completed_requests += 1
                    total_processing_time += result.get("processing_time", 0)
            
            # Rate limiting
            await asyncio.sleep(max(0, 1.0 / rate))
        
        actual_duration = time.time() - start_time
        
        return {
            "completed_requests": completed_requests,
            "failed_requests": failed_requests,
            "total_requests": completed_requests + failed_requests,
            "requests_per_second": completed_requests / actual_duration if actual_duration > 0 else 0,
            "average_processing_time": total_processing_time / completed_requests if completed_requests > 0 else 0,
            "success_rate": completed_requests / (completed_requests + failed_requests) if (completed_requests + failed_requests) > 0 else 0,
            "target_concurrent": concurrent_tasks,
            "target_rate": rate
        }
    
    async def _simulate_data_processing(self, data_volume_mb: int, duration: int) -> Dict[str, Any]:
        """Simulate data processing workload."""
        logger.debug(f"Simulating {data_volume_mb}MB data processing for {duration}s")
        
        start_time = time.time()
        end_time = start_time + duration
        
        processed_mb = 0
        operations = 0
        
        while time.time() < end_time and not self.emergency_shutdown:
            # Generate data chunk (1MB at a time)
            chunk_size = min(1, data_volume_mb - processed_mb)
            if chunk_size <= 0:
                break
            
            # Simulate data processing
            data_chunk = [random.random() for _ in range(chunk_size * 256 * 1024)]  # ~1MB of floats
            
            # Process data (sorting, filtering, aggregation)
            data_chunk.sort()
            filtered_data = [x for x in data_chunk if x > 0.5]
            aggregated_value = sum(filtered_data) / len(filtered_data) if filtered_data else 0
            
            processed_mb += chunk_size
            operations += 1
            
            # Allow other tasks to run
            await asyncio.sleep(0.01)
        
        actual_duration = time.time() - start_time
        
        return {
            "data_processed_mb": processed_mb,
            "data_target_mb": data_volume_mb,
            "processing_operations": operations,
            "mb_per_second": processed_mb / actual_duration if actual_duration > 0 else 0,
            "operations_per_second": operations / actual_duration if actual_duration > 0 else 0
        }
    
    async def _inject_failures(self, failure_rate: float, duration: int) -> Dict[str, Any]:
        """Inject failures for chaos testing."""
        logger.debug(f"Injecting failures at {failure_rate} rate for {duration}s")
        
        failure_types = [
            "network_timeout",
            "memory_exhaustion", 
            "disk_full",
            "connection_refused",
            "authentication_failure",
            "rate_limit_exceeded",
            "service_unavailable"
        ]
        
        start_time = time.time()
        end_time = start_time + duration
        
        injected_failures = []
        
        while time.time() < end_time and not self.emergency_shutdown:
            if random.random() < failure_rate:
                failure_type = random.choice(failure_types)
                failure_time = time.time()
                
                # Simulate failure impact
                impact_duration = random.uniform(0.1, 2.0)  # 100ms to 2s impact
                
                failure = {
                    "type": failure_type,
                    "time": failure_time,
                    "impact_duration": impact_duration
                }
                
                injected_failures.append(failure)
                logger.debug(f"Injected failure: {failure_type}")
                
                # Simulate failure impact
                await asyncio.sleep(impact_duration)
            
            await asyncio.sleep(0.1)
        
        return {
            "injected_failures": len(injected_failures),
            "failure_rate": failure_rate,
            "failure_types": {ftype: len([f for f in injected_failures if f["type"] == ftype]) 
                           for ftype in failure_types},
            "failures": injected_failures
        }
    
    async def _monitor_system_during_stress(self, duration: int) -> Dict[str, Any]:
        """Monitor system resources during stress testing."""
        logger.debug(f"Monitoring system for {duration}s")
        
        start_time = time.time()
        end_time = start_time + duration
        
        samples = []
        
        while time.time() < end_time and not self.emergency_shutdown:
            sample = {
                "timestamp": time.time(),
                "cpu_percent": psutil.cpu_percent(interval=0.1),
                "memory_percent": psutil.virtual_memory().percent,
                "memory_mb": psutil.Process().memory_info().rss / 1024 / 1024,
                "disk_usage": psutil.disk_usage('/').percent,
                "load_average": psutil.getloadavg()[0] if hasattr(psutil, 'getloadavg') else 0
            }
            samples.append(sample)
            
            # Check safety limits
            if (sample["memory_percent"] > 90 or 
                sample["cpu_percent"] > 95 or 
                sample["disk_usage"] > 95):
                logger.warning("System approaching critical limits")
                self.circuit_breaker_active = True
            
            await asyncio.sleep(1)
        
        if samples:
            return {
                "sample_count": len(samples),
                "cpu_avg": sum(s["cpu_percent"] for s in samples) / len(samples),
                "cpu_max": max(s["cpu_percent"] for s in samples),
                "memory_avg": sum(s["memory_percent"] for s in samples) / len(samples),
                "memory_max": max(s["memory_percent"] for s in samples),
                "memory_mb_avg": sum(s["memory_mb"] for s in samples) / len(samples),
                "memory_mb_max": max(s["memory_mb"] for s in samples),
                "disk_usage_max": max(s["disk_usage"] for s in samples),
                "samples": samples
            }
        else:
            return {"error": "No monitoring samples collected"}
    
    def _capture_system_state(self) -> Dict[str, Any]:
        """Capture current system state."""
        return {
            "timestamp": time.time(),
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory": dict(psutil.virtual_memory()._asdict()),
            "disk": dict(psutil.disk_usage('/')._asdict()),
            "process_memory_mb": psutil.Process().memory_info().rss / 1024 / 1024,
            "process_cpu_percent": psutil.Process().cpu_percent(),
            "load_average": psutil.getloadavg() if hasattr(psutil, 'getloadavg') else [0, 0, 0]
        }
    
    def _check_safety_conditions(self) -> bool:
        """Check if system is within safety limits."""
        current_state = self._capture_system_state()
        
        safety_checks = [
            current_state["memory"]["percent"] < 95,
            current_state["cpu_percent"] < 98,
            current_state["disk"]["percent"] < 90,
            current_state["process_memory_mb"] < self.safety_limits["max_memory_mb"]
        ]
        
        return all(safety_checks)
    
    async def _recovery_period(self, completed_phase: StressPhase):
        """Allow system to recover between stress phases."""
        if completed_phase.level < StressPhase.HEAVY.level:
            recovery_time = 10  # Short recovery for light phases
        else:
            recovery_time = 30  # Longer recovery for heavy phases
        
        logger.info(f"Recovery period: {recovery_time}s after {completed_phase.phase_name}")
        
        # Monitor recovery
        for i in range(recovery_time):
            if self.emergency_shutdown:
                break
            await asyncio.sleep(1)
            
            # Check if system has recovered
            current_state = self._capture_system_state()
            if (current_state["cpu_percent"] < 20 and 
                current_state["memory"]["percent"] < 70):
                logger.debug(f"System recovered after {i+1}s")
                break
    
    def _analyze_stress_results(self) -> Dict[str, Any]:
        """Analyze stress test results and identify patterns."""
        analysis = {
            "breaking_point": None,
            "performance_degradation": {},
            "failure_patterns": {},
            "recovery_characteristics": {},
            "recommendations": []
        }
        
        # Find breaking point
        for phase_name, phase_data in self.results["stress_cycles"].items():
            if phase_data.get("status") == "failed" or phase_data.get("errors"):
                analysis["breaking_point"] = phase_name
                break
        
        # Analyze performance degradation
        phases_with_metrics = {name: data for name, data in self.results["stress_cycles"].items() 
                             if "metrics" in data and data["metrics"]}
        
        if phases_with_metrics:
            first_phase = list(phases_with_metrics.values())[0]
            last_phase = list(phases_with_metrics.values())[-1]
            
            analysis["performance_degradation"] = {
                "response_time_change": self._calculate_metric_change(
                    first_phase, last_phase, "average_processing_time"
                ),
                "throughput_change": self._calculate_metric_change(
                    first_phase, last_phase, "requests_per_second"
                ),
                "success_rate_change": self._calculate_metric_change(
                    first_phase, last_phase, "success_rate"
                )
            }
        
        # Generate recommendations
        recommendations = []
        if analysis["breaking_point"]:
            recommendations.append(f"System breaking point identified at {analysis['breaking_point']}")
        if self.circuit_breaker_active:
            recommendations.append("Circuit breaker activated during testing - review resource limits")
        if self.emergency_shutdown:
            recommendations.append("Emergency shutdown triggered - investigate safety mechanisms")
        
        if not recommendations:
            recommendations.append("System performed well under all stress conditions")
        
        analysis["recommendations"] = recommendations
        
        return analysis
    
    def _calculate_metric_change(self, first_phase: Dict, last_phase: Dict, metric_path: str) -> Dict[str, Any]:
        """Calculate change in a metric between two phases."""
        try:
            first_value = self._get_nested_metric(first_phase["metrics"], metric_path)
            last_value = self._get_nested_metric(last_phase["metrics"], metric_path)
            
            if first_value is not None and last_value is not None:
                change = last_value - first_value
                percent_change = (change / first_value * 100) if first_value != 0 else 0
                return {
                    "first_value": first_value,
                    "last_value": last_value,
                    "absolute_change": change,
                    "percent_change": percent_change
                }
        except Exception:
            pass
        
        return {"error": f"Could not calculate change for {metric_path}"}
    
    def _get_nested_metric(self, data: Dict, path: str) -> Optional[float]:
        """Get a nested metric value from data."""
        try:
            return data.get(path)
        except Exception:
            return None

async def main():
    """Main stress cycle validation execution."""
    validator = StressCycleValidator()
    
    try:
        logger.info("Starting 7-phase stress cycle validation...")
        results = await validator.run_full_stress_cycle()
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = f"stress_cycle_validation_{timestamp}.json"
        
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n{'='*80}")
        print("STRESS CYCLE VALIDATION COMPLETE")
        print(f"{'='*80}")
        
        # Summary
        cycles_completed = len([phase for phase in results["stress_cycles"].values() 
                              if phase.get("status") == "completed"])
        total_cycles = len(results["stress_cycles"])
        
        print(f"Stress Cycles Completed: {cycles_completed}/{total_cycles}")
        
        if "analysis" in results:
            analysis = results["analysis"]
            if analysis.get("breaking_point"):
                print(f"Breaking Point: {analysis['breaking_point']}")
            else:
                print("Breaking Point: Not reached")
            
            print("\nRecommendations:")
            for rec in analysis.get("recommendations", []):
                print(f"  - {rec}")
        
        if validator.emergency_shutdown:
            print("\nWARNING: Emergency shutdown was triggered during testing")
        
        print(f"\nDetailed results saved to: {results_file}")
        
        return cycles_completed == total_cycles and not validator.emergency_shutdown
        
    except Exception as e:
        logger.error(f"Stress cycle validation failed: {str(e)}")
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)