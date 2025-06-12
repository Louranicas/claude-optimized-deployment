#!/usr/bin/env python3
"""
Advanced Load Generation Orchestrator
====================================

Central coordination and control system for managing multiple load generators
with intelligent synchronization and adaptive load adjustment.
"""

import asyncio
import logging
import json
import time
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from typing import Dict, List, Any, Optional, Callable
from enum import Enum
import threading
from pathlib import Path
import psutil
import numpy as np

from patterns.pattern_engine import PatternEngine
from generators.cpu_load_generator import CPULoadGenerator
from generators.memory_load_generator import MemoryLoadGenerator
from generators.io_load_generator import IOLoadGenerator
from generators.network_load_generator import NetworkLoadGenerator
from generators.application_load_generator import ApplicationLoadGenerator

logger = logging.getLogger(__name__)

class LoadGeneratorType(Enum):
    """Available load generator types"""
    CPU = "cpu"
    MEMORY = "memory"
    IO = "io"
    NETWORK = "network"
    APPLICATION = "application"

class LoadPhase(Enum):
    """Load generation phases"""
    WARMUP = "warmup"
    RAMP_UP = "ramp_up"
    STEADY_STATE = "steady_state"
    BURST = "burst"
    RAMP_DOWN = "ramp_down"
    COOL_DOWN = "cool_down"

@dataclass
class LoadConfiguration:
    """Configuration for load generation"""
    generator_type: LoadGeneratorType
    pattern_name: str
    intensity: float  # 0.0 to 1.0
    duration: int  # seconds
    parameters: Dict[str, Any]
    priority: int = 1  # 1-10, higher is more important
    enabled: bool = True

@dataclass
class SystemMetrics:
    """Current system metrics"""
    cpu_usage: float
    memory_usage: float
    disk_io: Dict[str, float]
    network_io: Dict[str, float]
    load_average: List[float]
    timestamp: datetime

@dataclass
class LoadGeneratorStatus:
    """Status of a load generator"""
    generator_id: str
    generator_type: LoadGeneratorType
    status: str  # running, stopped, error
    current_load: float
    target_load: float
    metrics: Dict[str, float]
    error_message: Optional[str] = None

class LoadOrchestrator:
    """
    Advanced Load Generation Orchestrator
    
    Manages multiple load generators with intelligent coordination,
    adaptive control, and realistic pattern execution.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path
        self.generators: Dict[str, Any] = {}
        self.pattern_engine = PatternEngine()
        self.running = False
        self.current_phase = LoadPhase.WARMUP
        self.load_configurations: List[LoadConfiguration] = []
        self.system_metrics_history: List[SystemMetrics] = []
        self.coordination_callbacks: List[Callable] = []
        
        # Performance thresholds for adaptive control
        self.performance_thresholds = {
            'cpu_max': 85.0,
            'memory_max': 80.0,
            'response_time_max': 5000,  # ms
            'error_rate_max': 0.05  # 5%
        }
        
        # Initialize generators
        self._initialize_generators()
        
        # Load configuration if provided
        if config_path:
            self.load_configuration(config_path)
    
    def _initialize_generators(self):
        """Initialize all load generators"""
        try:
            self.generators[LoadGeneratorType.CPU.value] = CPULoadGenerator()
            self.generators[LoadGeneratorType.MEMORY.value] = MemoryLoadGenerator()
            self.generators[LoadGeneratorType.IO.value] = IOLoadGenerator()
            self.generators[LoadGeneratorType.NETWORK.value] = NetworkLoadGenerator()
            self.generators[LoadGeneratorType.APPLICATION.value] = ApplicationLoadGenerator()
            
            logger.info("All load generators initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize generators: {e}")
            raise
    
    def load_configuration(self, config_path: str):
        """Load load generation configuration from file"""
        try:
            with open(config_path, 'r') as f:
                config_data = json.load(f)
            
            self.load_configurations = []
            for config in config_data.get('load_configurations', []):
                load_config = LoadConfiguration(
                    generator_type=LoadGeneratorType(config['generator_type']),
                    pattern_name=config['pattern_name'],
                    intensity=config['intensity'],
                    duration=config['duration'],
                    parameters=config.get('parameters', {}),
                    priority=config.get('priority', 1),
                    enabled=config.get('enabled', True)
                )
                self.load_configurations.append(load_config)
            
            # Update performance thresholds if provided
            if 'performance_thresholds' in config_data:
                self.performance_thresholds.update(config_data['performance_thresholds'])
            
            logger.info(f"Loaded {len(self.load_configurations)} load configurations")
            
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            raise
    
    def add_load_configuration(self, config: LoadConfiguration):
        """Add a new load configuration"""
        self.load_configurations.append(config)
        logger.info(f"Added load configuration: {config.generator_type.value} - {config.pattern_name}")
    
    def remove_load_configuration(self, generator_type: LoadGeneratorType, pattern_name: str):
        """Remove a load configuration"""
        self.load_configurations = [
            config for config in self.load_configurations
            if not (config.generator_type == generator_type and config.pattern_name == pattern_name)
        ]
        logger.info(f"Removed load configuration: {generator_type.value} - {pattern_name}")
    
    async def start_load_generation(self, scenario_name: str = "default"):
        """Start coordinated load generation"""
        if self.running:
            logger.warning("Load generation already running")
            return
        
        logger.info(f"Starting load generation scenario: {scenario_name}")
        self.running = True
        
        try:
            # Start system monitoring
            monitoring_task = asyncio.create_task(self._monitor_system())
            
            # Start coordination controller
            coordination_task = asyncio.create_task(self._coordination_controller())
            
            # Execute load generation phases
            await self._execute_load_phases()
            
            # Cancel monitoring tasks
            monitoring_task.cancel()
            coordination_task.cancel()
            
            try:
                await monitoring_task
                await coordination_task
            except asyncio.CancelledError:
                pass
            
        except Exception as e:
            logger.error(f"Load generation failed: {e}")
            raise
        finally:
            self.running = False
            await self._stop_all_generators()
    
    async def _execute_load_phases(self):
        """Execute all load generation phases"""
        phases = [
            (LoadPhase.WARMUP, 30),
            (LoadPhase.RAMP_UP, 60),
            (LoadPhase.STEADY_STATE, 300),
            (LoadPhase.BURST, 120),
            (LoadPhase.RAMP_DOWN, 60),
            (LoadPhase.COOL_DOWN, 30)
        ]
        
        for phase, duration in phases:
            if not self.running:
                break
                
            logger.info(f"Starting phase: {phase.value} (duration: {duration}s)")
            self.current_phase = phase
            
            # Execute phase-specific load patterns
            await self._execute_phase_patterns(phase, duration)
            
            logger.info(f"Completed phase: {phase.value}")
    
    async def _execute_phase_patterns(self, phase: LoadPhase, duration: int):
        """Execute load patterns for a specific phase"""
        phase_configs = [
            config for config in self.load_configurations
            if config.enabled and self._is_config_for_phase(config, phase)
        ]
        
        if not phase_configs:
            await asyncio.sleep(duration)
            return
        
        # Start generators for this phase
        tasks = []
        for config in phase_configs:
            task = asyncio.create_task(
                self._run_generator_pattern(config, duration)
            )
            tasks.append(task)
        
        # Wait for phase completion or early termination
        try:
            await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=duration + 10  # Allow slight buffer
            )
        except asyncio.TimeoutError:
            logger.warning(f"Phase {phase.value} timed out")
            # Cancel remaining tasks
            for task in tasks:
                if not task.done():
                    task.cancel()
    
    def _is_config_for_phase(self, config: LoadConfiguration, phase: LoadPhase) -> bool:
        """Determine if a configuration applies to a specific phase"""
        phase_patterns = {
            LoadPhase.WARMUP: ['steady_state', 'low_load'],
            LoadPhase.RAMP_UP: ['ramp_up', 'gradual_increase'],
            LoadPhase.STEADY_STATE: ['steady_state', 'sustained_load'],
            LoadPhase.BURST: ['burst', 'spike', 'high_load'],
            LoadPhase.RAMP_DOWN: ['ramp_down', 'gradual_decrease'],
            LoadPhase.COOL_DOWN: ['steady_state', 'low_load']
        }
        
        return config.pattern_name in phase_patterns.get(phase, [])
    
    async def _run_generator_pattern(self, config: LoadConfiguration, duration: int):
        """Run a specific generator pattern"""
        generator = self.generators.get(config.generator_type.value)
        if not generator:
            logger.error(f"Generator not found: {config.generator_type.value}")
            return
        
        try:
            # Apply adaptive intensity based on current system state
            adaptive_intensity = self._calculate_adaptive_intensity(config.intensity)
            
            # Generate load pattern
            pattern = self.pattern_engine.generate_pattern(
                config.pattern_name,
                duration,
                adaptive_intensity,
                config.parameters
            )
            
            # Execute pattern
            await generator.execute_pattern(pattern)
            
        except Exception as e:
            logger.error(f"Failed to run pattern {config.pattern_name}: {e}")
    
    def _calculate_adaptive_intensity(self, base_intensity: float) -> float:
        """Calculate adaptive intensity based on current system metrics"""
        if not self.system_metrics_history:
            return base_intensity
        
        latest_metrics = self.system_metrics_history[-1]
        
        # Reduce intensity if system is under stress
        cpu_factor = max(0.1, 1.0 - (latest_metrics.cpu_usage / 100.0))
        memory_factor = max(0.1, 1.0 - (latest_metrics.memory_usage / 100.0))
        
        adaptive_factor = min(cpu_factor, memory_factor)
        adaptive_intensity = base_intensity * adaptive_factor
        
        return max(0.1, min(1.0, adaptive_intensity))
    
    async def _monitor_system(self):
        """Monitor system metrics continuously"""
        while self.running:
            try:
                metrics = self._collect_system_metrics()
                self.system_metrics_history.append(metrics)
                
                # Keep only last 1000 metrics entries
                if len(self.system_metrics_history) > 1000:
                    self.system_metrics_history = self.system_metrics_history[-1000:]
                
                # Check for system stress
                await self._check_system_stress(metrics)
                
            except Exception as e:
                logger.error(f"System monitoring error: {e}")
            
            await asyncio.sleep(5)  # Monitor every 5 seconds
    
    def _collect_system_metrics(self) -> SystemMetrics:
        """Collect current system metrics"""
        cpu_usage = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk_io = psutil.disk_io_counters()._asdict() if psutil.disk_io_counters() else {}
        network_io = psutil.net_io_counters()._asdict() if psutil.net_io_counters() else {}
        load_avg = list(psutil.getloadavg()) if hasattr(psutil, 'getloadavg') else [0, 0, 0]
        
        return SystemMetrics(
            cpu_usage=cpu_usage,
            memory_usage=memory.percent,
            disk_io=disk_io,
            network_io=network_io,
            load_average=load_avg,
            timestamp=datetime.now()
        )
    
    async def _check_system_stress(self, metrics: SystemMetrics):
        """Check if system is under stress and adjust accordingly"""
        stress_detected = False
        
        if metrics.cpu_usage > self.performance_thresholds['cpu_max']:
            logger.warning(f"High CPU usage detected: {metrics.cpu_usage}%")
            stress_detected = True
        
        if metrics.memory_usage > self.performance_thresholds['memory_max']:
            logger.warning(f"High memory usage detected: {metrics.memory_usage}%")
            stress_detected = True
        
        if stress_detected:
            await self._reduce_load_intensity()
    
    async def _reduce_load_intensity(self):
        """Reduce load intensity when system stress is detected"""
        logger.info("Reducing load intensity due to system stress")
        
        for generator in self.generators.values():
            if hasattr(generator, 'reduce_intensity'):
                await generator.reduce_intensity(0.8)  # Reduce by 20%
    
    async def _coordination_controller(self):
        """Control coordination between generators"""
        while self.running:
            try:
                # Execute coordination callbacks
                for callback in self.coordination_callbacks:
                    await callback()
                
                # Check generator synchronization
                await self._synchronize_generators()
                
            except Exception as e:
                logger.error(f"Coordination controller error: {e}")
            
            await asyncio.sleep(10)  # Coordinate every 10 seconds
    
    async def _synchronize_generators(self):
        """Synchronize generators for coordinated execution"""
        # Get status from all active generators
        statuses = []
        for gen_type, generator in self.generators.items():
            if hasattr(generator, 'get_status'):
                status = await generator.get_status()
                statuses.append(status)
        
        # Implement synchronization logic based on statuses
        # This could include load balancing, phase coordination, etc.
        pass
    
    async def _stop_all_generators(self):
        """Stop all running generators"""
        logger.info("Stopping all load generators")
        
        for generator in self.generators.values():
            if hasattr(generator, 'stop'):
                try:
                    await generator.stop()
                except Exception as e:
                    logger.error(f"Error stopping generator: {e}")
    
    def get_generator_status(self) -> List[LoadGeneratorStatus]:
        """Get status of all generators"""
        statuses = []
        
        for gen_type, generator in self.generators.items():
            try:
                if hasattr(generator, 'get_status'):
                    status = generator.get_status()
                    statuses.append(status)
                else:
                    # Create basic status
                    status = LoadGeneratorStatus(
                        generator_id=gen_type,
                        generator_type=LoadGeneratorType(gen_type),
                        status="unknown",
                        current_load=0.0,
                        target_load=0.0,
                        metrics={}
                    )
                    statuses.append(status)
            except Exception as e:
                logger.error(f"Failed to get status for {gen_type}: {e}")
        
        return statuses
    
    def add_coordination_callback(self, callback: Callable):
        """Add a coordination callback function"""
        self.coordination_callbacks.append(callback)
    
    def get_system_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of system metrics"""
        if not self.system_metrics_history:
            return {}
        
        recent_metrics = self.system_metrics_history[-60:]  # Last 5 minutes
        
        cpu_values = [m.cpu_usage for m in recent_metrics]
        memory_values = [m.memory_usage for m in recent_metrics]
        
        return {
            'cpu': {
                'current': cpu_values[-1] if cpu_values else 0,
                'average': np.mean(cpu_values) if cpu_values else 0,
                'max': np.max(cpu_values) if cpu_values else 0,
                'min': np.min(cpu_values) if cpu_values else 0
            },
            'memory': {
                'current': memory_values[-1] if memory_values else 0,
                'average': np.mean(memory_values) if memory_values else 0,
                'max': np.max(memory_values) if memory_values else 0,
                'min': np.min(memory_values) if memory_values else 0
            },
            'load_average': recent_metrics[-1].load_average if recent_metrics else [0, 0, 0],
            'sample_count': len(recent_metrics),
            'time_range': {
                'start': recent_metrics[0].timestamp.isoformat() if recent_metrics else None,
                'end': recent_metrics[-1].timestamp.isoformat() if recent_metrics else None
            }
        }
    
    def export_metrics(self, filepath: str):
        """Export metrics to file"""
        try:
            metrics_data = {
                'generator_status': [asdict(status) for status in self.get_generator_status()],
                'system_metrics_summary': self.get_system_metrics_summary(),
                'configuration': [asdict(config) for config in self.load_configurations],
                'export_timestamp': datetime.now().isoformat()
            }
            
            with open(filepath, 'w') as f:
                json.dump(metrics_data, f, indent=2, default=str)
            
            logger.info(f"Metrics exported to {filepath}")
            
        except Exception as e:
            logger.error(f"Failed to export metrics: {e}")


# Example usage and testing
async def example_usage():
    """Example usage of LoadOrchestrator"""
    orchestrator = LoadOrchestrator()
    
    # Add some test configurations
    cpu_config = LoadConfiguration(
        generator_type=LoadGeneratorType.CPU,
        pattern_name="steady_state",
        intensity=0.5,
        duration=120,
        parameters={'threads': 4}
    )
    orchestrator.add_load_configuration(cpu_config)
    
    memory_config = LoadConfiguration(
        generator_type=LoadGeneratorType.MEMORY,
        pattern_name="gradual_increase",
        intensity=0.7,
        duration=180,
        parameters={'allocation_size': '100MB'}
    )
    orchestrator.add_load_configuration(memory_config)
    
    # Start load generation
    await orchestrator.start_load_generation("example_scenario")
    
    # Export results
    orchestrator.export_metrics("load_test_results.json")


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run example
    asyncio.run(example_usage())