"""
Core Stress Testing Cycle Manager

Implements 7-phase progressive ramping system with intelligent load orchestration.
Coordinates multiple load types and manages cycle transitions safely.
"""

import asyncio
import time
import logging
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
import yaml
import json

from .load_controller import LoadController
from .safety_manager import SafetyManager
from .metrics_collector import MetricsCollector
from .adaptive_ramping import AdaptiveRampingEngine


class StressPhase(Enum):
    """7-phase stress testing cycle"""
    IDLE = 0        # 0% load - Baseline measurement
    LIGHT = 1       # 10-25% load - Normal operation
    MEDIUM = 2      # 25-50% load - Busy period
    HEAVY = 3       # 50-75% load - Peak usage
    EXTREME = 4     # 75-90% load - Overload condition
    CRITICAL = 5    # 90-95% load - Near-failure testing
    CHAOS = 6       # 95%+ load - Failure condition testing


class CycleState(Enum):
    """Cycle execution states"""
    STOPPED = "stopped"
    INITIALIZING = "initializing"
    RAMPING_UP = "ramping_up"
    STEADY_STATE = "steady_state"
    RAMPING_DOWN = "ramping_down"
    EMERGENCY_STOP = "emergency_stop"
    COMPLETED = "completed"


@dataclass
class PhaseConfig:
    """Configuration for a stress testing phase"""
    phase: StressPhase
    min_load_percent: float
    max_load_percent: float
    duration_seconds: int
    ramp_up_seconds: int
    ramp_down_seconds: int
    cpu_weight: float = 1.0
    memory_weight: float = 1.0
    io_weight: float = 1.0
    network_weight: float = 1.0
    safety_thresholds: Dict[str, float] = field(default_factory=dict)
    adaptive_enabled: bool = True


@dataclass
class CycleStatus:
    """Current cycle execution status"""
    state: CycleState
    current_phase: Optional[StressPhase]
    phase_start_time: Optional[datetime]
    cycle_start_time: Optional[datetime]
    total_elapsed: float
    phase_elapsed: float
    current_load_percent: float
    target_load_percent: float
    safety_triggered: bool
    metrics: Dict[str, Any] = field(default_factory=dict)


class StressCycleManager:
    """
    Core stress testing cycle manager with intelligent ramping and safety controls
    """
    
    def __init__(self, config_path: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        
        # Core components
        self.load_controller = LoadController()
        self.safety_manager = SafetyManager()
        self.metrics_collector = MetricsCollector()
        self.adaptive_ramping = AdaptiveRampingEngine()
        
        # Configuration
        self.phases: List[PhaseConfig] = []
        self.config_path = config_path
        self.load_config()
        
        # State management
        self.status = CycleStatus(
            state=CycleState.STOPPED,
            current_phase=None,
            phase_start_time=None,
            cycle_start_time=None,
            total_elapsed=0.0,
            phase_elapsed=0.0,
            current_load_percent=0.0,
            target_load_percent=0.0,
            safety_triggered=False
        )
        
        # Control flags
        self._running = False
        self._emergency_stop = False
        self._pause_requested = False
        
        # Callbacks
        self.phase_change_callbacks: List[Callable] = []
        self.metrics_callbacks: List[Callable] = []
        self.safety_callbacks: List[Callable] = []
        
        # Performance tracking
        self.cycle_history: List[Dict] = []
        self.performance_data: Dict = {}
    
    def load_config(self):
        """Load stress cycle configuration"""
        if not self.config_path:
            self._load_default_config()
        else:
            try:
                with open(self.config_path, 'r') as f:
                    config_data = yaml.safe_load(f)
                self._parse_config(config_data)
            except Exception as e:
                self.logger.error(f"Failed to load config from {self.config_path}: {e}")
                self._load_default_config()
    
    def _load_default_config(self):
        """Load default 7-phase configuration"""
        self.phases = [
            PhaseConfig(
                phase=StressPhase.IDLE,
                min_load_percent=0.0,
                max_load_percent=5.0,
                duration_seconds=60,
                ramp_up_seconds=10,
                ramp_down_seconds=10,
                safety_thresholds={"cpu": 20, "memory": 30}
            ),
            PhaseConfig(
                phase=StressPhase.LIGHT,
                min_load_percent=10.0,
                max_load_percent=25.0,
                duration_seconds=120,
                ramp_up_seconds=30,
                ramp_down_seconds=20,
                safety_thresholds={"cpu": 40, "memory": 50}
            ),
            PhaseConfig(
                phase=StressPhase.MEDIUM,
                min_load_percent=25.0,
                max_load_percent=50.0,
                duration_seconds=180,
                ramp_up_seconds=45,
                ramp_down_seconds=30,
                safety_thresholds={"cpu": 70, "memory": 70}
            ),
            PhaseConfig(
                phase=StressPhase.HEAVY,
                min_load_percent=50.0,
                max_load_percent=75.0,
                duration_seconds=240,
                ramp_up_seconds=60,
                ramp_down_seconds=45,
                safety_thresholds={"cpu": 85, "memory": 80}
            ),
            PhaseConfig(
                phase=StressPhase.EXTREME,
                min_load_percent=75.0,
                max_load_percent=90.0,
                duration_seconds=180,
                ramp_up_seconds=90,
                ramp_down_seconds=60,
                safety_thresholds={"cpu": 95, "memory": 90}
            ),
            PhaseConfig(
                phase=StressPhase.CRITICAL,
                min_load_percent=90.0,
                max_load_percent=95.0,
                duration_seconds=120,
                ramp_up_seconds=120,
                ramp_down_seconds=90,
                safety_thresholds={"cpu": 98, "memory": 95}
            ),
            PhaseConfig(
                phase=StressPhase.CHAOS,
                min_load_percent=95.0,
                max_load_percent=100.0,
                duration_seconds=60,
                ramp_up_seconds=60,
                ramp_down_seconds=120,
                safety_thresholds={"cpu": 99, "memory": 98}
            )
        ]
    
    def _parse_config(self, config_data: Dict):
        """Parse configuration data into PhaseConfig objects"""
        self.phases = []
        for phase_data in config_data.get('phases', []):
            phase_config = PhaseConfig(
                phase=StressPhase(phase_data['phase']),
                min_load_percent=phase_data['min_load_percent'],
                max_load_percent=phase_data['max_load_percent'],
                duration_seconds=phase_data['duration_seconds'],
                ramp_up_seconds=phase_data['ramp_up_seconds'],
                ramp_down_seconds=phase_data['ramp_down_seconds'],
                cpu_weight=phase_data.get('cpu_weight', 1.0),
                memory_weight=phase_data.get('memory_weight', 1.0),
                io_weight=phase_data.get('io_weight', 1.0),
                network_weight=phase_data.get('network_weight', 1.0),
                safety_thresholds=phase_data.get('safety_thresholds', {}),
                adaptive_enabled=phase_data.get('adaptive_enabled', True)
            )
            self.phases.append(phase_config)
    
    async def start_cycle(self, phases: Optional[List[StressPhase]] = None) -> bool:
        """
        Start stress testing cycle
        
        Args:
            phases: Optional list of specific phases to run
            
        Returns:
            bool: True if cycle started successfully
        """
        if self._running:
            self.logger.warning("Cycle already running")
            return False
        
        try:
            self.logger.info("Starting stress testing cycle")
            
            # Initialize components
            await self._initialize_cycle()
            
            # Filter phases if specified
            target_phases = self.phases
            if phases:
                target_phases = [p for p in self.phases if p.phase in phases]
            
            if not target_phases:
                self.logger.error("No valid phases to execute")
                return False
            
            # Start cycle execution
            self._running = True
            self._emergency_stop = False
            self.status.state = CycleState.INITIALIZING
            self.status.cycle_start_time = datetime.now()
            
            # Execute phases
            for phase_config in target_phases:
                if not self._running or self._emergency_stop:
                    break
                
                success = await self._execute_phase(phase_config)
                if not success:
                    self.logger.error(f"Phase {phase_config.phase.name} failed")
                    break
            
            # Cleanup and finalize
            await self._finalize_cycle()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Cycle execution failed: {e}")
            await self._emergency_shutdown()
            return False
    
    async def stop_cycle(self, emergency: bool = False):
        """Stop the current cycle"""
        if emergency:
            self._emergency_stop = True
            self.status.state = CycleState.EMERGENCY_STOP
            await self._emergency_shutdown()
        else:
            self._running = False
            await self._graceful_shutdown()
    
    async def pause_cycle(self):
        """Pause the current cycle"""
        self._pause_requested = True
        self.logger.info("Cycle pause requested")
    
    async def resume_cycle(self):
        """Resume a paused cycle"""
        self._pause_requested = False
        self.logger.info("Cycle resumed")
    
    async def _initialize_cycle(self):
        """Initialize cycle components and baseline measurements"""
        self.logger.info("Initializing stress testing cycle")
        
        # Initialize load controller
        await self.load_controller.initialize()
        
        # Initialize safety manager
        await self.safety_manager.initialize()
        
        # Initialize metrics collector
        await self.metrics_collector.start_collection()
        
        # Initialize adaptive ramping
        await self.adaptive_ramping.initialize()
        
        # Take baseline measurements
        baseline_metrics = await self.metrics_collector.collect_baseline()
        self.performance_data['baseline'] = baseline_metrics
        
        self.logger.info("Cycle initialization completed")
    
    async def _execute_phase(self, phase_config: PhaseConfig) -> bool:
        """
        Execute a single stress testing phase
        
        Args:
            phase_config: Configuration for the phase to execute
            
        Returns:
            bool: True if phase completed successfully
        """
        try:
            self.logger.info(f"Starting phase: {phase_config.phase.name}")
            
            # Update status
            self.status.current_phase = phase_config.phase
            self.status.phase_start_time = datetime.now()
            self.status.state = CycleState.RAMPING_UP
            
            # Configure safety thresholds
            await self.safety_manager.set_thresholds(phase_config.safety_thresholds)
            
            # Execute ramp-up
            await self._ramp_up_phase(phase_config)
            
            if not self._running or self._emergency_stop:
                return False
            
            # Execute steady state
            self.status.state = CycleState.STEADY_STATE
            await self._steady_state_phase(phase_config)
            
            if not self._running or self._emergency_stop:
                return False
            
            # Execute ramp-down
            self.status.state = CycleState.RAMPING_DOWN
            await self._ramp_down_phase(phase_config)
            
            # Notify phase completion
            await self._notify_phase_change(phase_config.phase, "completed")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Phase {phase_config.phase.name} execution failed: {e}")
            return False
    
    async def _ramp_up_phase(self, phase_config: PhaseConfig):
        """Execute ramp-up portion of phase"""
        start_time = time.time()
        ramp_duration = phase_config.ramp_up_seconds
        
        while time.time() - start_time < ramp_duration:
            if not self._running or self._emergency_stop:
                break
            
            # Handle pause
            while self._pause_requested and self._running:
                await asyncio.sleep(0.1)
            
            # Calculate current load percentage
            elapsed = time.time() - start_time
            progress = min(elapsed / ramp_duration, 1.0)
            
            if phase_config.adaptive_enabled:
                # Use adaptive ramping
                target_load = await self.adaptive_ramping.calculate_target_load(
                    phase_config, progress
                )
            else:
                # Linear ramping
                target_load = phase_config.min_load_percent + (
                    (phase_config.max_load_percent - phase_config.min_load_percent) * progress
                )
            
            # Apply load
            await self._apply_load(phase_config, target_load)
            
            # Check safety conditions
            if await self.safety_manager.check_emergency_conditions():
                self.logger.warning("Emergency conditions detected during ramp-up")
                self._emergency_stop = True
                break
            
            # Update status
            self.status.current_load_percent = target_load
            self.status.target_load_percent = phase_config.max_load_percent
            self.status.phase_elapsed = elapsed
            
            await asyncio.sleep(0.5)  # 500ms update interval
    
    async def _steady_state_phase(self, phase_config: PhaseConfig):
        """Execute steady state portion of phase"""
        start_time = time.time()
        duration = phase_config.duration_seconds
        
        target_load = phase_config.max_load_percent
        
        while time.time() - start_time < duration:
            if not self._running or self._emergency_stop:
                break
            
            # Handle pause
            while self._pause_requested and self._running:
                await asyncio.sleep(0.1)
            
            # Maintain load with adaptive adjustments
            if phase_config.adaptive_enabled:
                target_load = await self.adaptive_ramping.adjust_steady_state_load(
                    phase_config, target_load
                )
            
            # Apply load
            await self._apply_load(phase_config, target_load)
            
            # Check safety conditions
            if await self.safety_manager.check_emergency_conditions():
                self.logger.warning("Emergency conditions detected during steady state")
                self._emergency_stop = True
                break
            
            # Collect detailed metrics during steady state
            metrics = await self.metrics_collector.collect_metrics()
            await self._notify_metrics_update(metrics)
            
            # Update status
            elapsed = time.time() - start_time
            self.status.current_load_percent = target_load
            self.status.phase_elapsed = self.status.phase_elapsed + elapsed
            
            await asyncio.sleep(1.0)  # 1s update interval for steady state
    
    async def _ramp_down_phase(self, phase_config: PhaseConfig):
        """Execute ramp-down portion of phase"""
        start_time = time.time()
        ramp_duration = phase_config.ramp_down_seconds
        initial_load = self.status.current_load_percent
        
        while time.time() - start_time < ramp_duration:
            if not self._running:  # Don't check emergency_stop during ramp-down
                break
            
            # Calculate current load percentage
            elapsed = time.time() - start_time
            progress = min(elapsed / ramp_duration, 1.0)
            
            # Linear ramp-down to minimum
            target_load = initial_load * (1.0 - progress)
            target_load = max(target_load, phase_config.min_load_percent)
            
            # Apply load
            await self._apply_load(phase_config, target_load)
            
            # Update status
            self.status.current_load_percent = target_load
            self.status.phase_elapsed = self.status.phase_elapsed + elapsed
            
            await asyncio.sleep(0.5)  # 500ms update interval
    
    async def _apply_load(self, phase_config: PhaseConfig, load_percent: float):
        """Apply calculated load across all resource types"""
        # Calculate weighted loads for each resource type
        cpu_load = load_percent * phase_config.cpu_weight
        memory_load = load_percent * phase_config.memory_weight
        io_load = load_percent * phase_config.io_weight
        network_load = load_percent * phase_config.network_weight
        
        # Apply loads
        await self.load_controller.set_cpu_load(cpu_load)
        await self.load_controller.set_memory_load(memory_load)
        await self.load_controller.set_io_load(io_load)
        await self.load_controller.set_network_load(network_load)
    
    async def _finalize_cycle(self):
        """Finalize cycle execution and cleanup"""
        self.logger.info("Finalizing stress testing cycle")
        
        # Stop all loads
        await self.load_controller.stop_all_loads()
        
        # Collect final metrics
        final_metrics = await self.metrics_collector.collect_final_metrics()
        self.performance_data['final'] = final_metrics
        
        # Generate cycle summary
        cycle_summary = await self._generate_cycle_summary()
        self.cycle_history.append(cycle_summary)
        
        # Update status
        self.status.state = CycleState.COMPLETED
        self.status.total_elapsed = (
            datetime.now() - self.status.cycle_start_time
        ).total_seconds()
        
        # Cleanup
        await self.metrics_collector.stop_collection()
        self._running = False
        
        self.logger.info("Cycle finalization completed")
    
    async def _emergency_shutdown(self):
        """Emergency shutdown procedures"""
        self.logger.error("Executing emergency shutdown")
        
        try:
            # Immediate load stop
            await self.load_controller.emergency_stop()
            
            # Safety manager emergency procedures
            await self.safety_manager.emergency_shutdown()
            
            # Stop metrics collection
            await self.metrics_collector.emergency_stop()
            
            # Update status
            self.status.state = CycleState.EMERGENCY_STOP
            self.status.safety_triggered = True
            
            # Notify callbacks
            await self._notify_safety_event("emergency_shutdown")
            
        except Exception as e:
            self.logger.critical(f"Emergency shutdown failed: {e}")
        
        finally:
            self._running = False
            self._emergency_stop = True
    
    async def _graceful_shutdown(self):
        """Graceful shutdown procedures"""
        self.logger.info("Executing graceful shutdown")
        
        # Gradual load reduction
        await self.load_controller.graceful_shutdown()
        
        # Stop components
        await self.safety_manager.shutdown()
        await self.metrics_collector.stop_collection()
        
        # Update status
        self.status.state = CycleState.STOPPED
        self._running = False
    
    async def _generate_cycle_summary(self) -> Dict:
        """Generate comprehensive cycle summary"""
        return {
            'cycle_id': f"cycle_{int(time.time())}",
            'start_time': self.status.cycle_start_time.isoformat(),
            'end_time': datetime.now().isoformat(),
            'total_duration': self.status.total_elapsed,
            'phases_executed': [p.phase.name for p in self.phases],
            'safety_triggered': self.status.safety_triggered,
            'performance_data': self.performance_data,
            'final_status': self.status.state.value
        }
    
    # Callback registration methods
    def register_phase_change_callback(self, callback: Callable):
        """Register callback for phase changes"""
        self.phase_change_callbacks.append(callback)
    
    def register_metrics_callback(self, callback: Callable):
        """Register callback for metrics updates"""
        self.metrics_callbacks.append(callback)
    
    def register_safety_callback(self, callback: Callable):
        """Register callback for safety events"""
        self.safety_callbacks.append(callback)
    
    # Notification methods
    async def _notify_phase_change(self, phase: StressPhase, event: str):
        """Notify registered callbacks of phase changes"""
        for callback in self.phase_change_callbacks:
            try:
                await callback(phase, event, self.status)
            except Exception as e:
                self.logger.error(f"Phase change callback failed: {e}")
    
    async def _notify_metrics_update(self, metrics: Dict):
        """Notify registered callbacks of metrics updates"""
        for callback in self.metrics_callbacks:
            try:
                await callback(metrics, self.status)
            except Exception as e:
                self.logger.error(f"Metrics callback failed: {e}")
    
    async def _notify_safety_event(self, event: str):
        """Notify registered callbacks of safety events"""
        for callback in self.safety_callbacks:
            try:
                await callback(event, self.status)
            except Exception as e:
                self.logger.error(f"Safety callback failed: {e}")
    
    # Status and control methods
    def get_status(self) -> CycleStatus:
        """Get current cycle status"""
        return self.status
    
    def get_cycle_history(self) -> List[Dict]:
        """Get historical cycle data"""
        return self.cycle_history
    
    def is_running(self) -> bool:
        """Check if cycle is currently running"""
        return self._running
    
    async def adjust_target_load(self, phase: StressPhase, new_target: float):
        """Dynamically adjust target load for current phase"""
        if self.status.current_phase == phase and self._running:
            self.logger.info(f"Adjusting target load to {new_target}% for phase {phase.name}")
            self.status.target_load_percent = new_target
            
            # Apply immediate adjustment if in steady state
            if self.status.state == CycleState.STEADY_STATE:
                current_config = next(
                    (p for p in self.phases if p.phase == phase), None
                )
                if current_config:
                    await self._apply_load(current_config, new_target)