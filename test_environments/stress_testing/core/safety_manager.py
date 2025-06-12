"""
Safety Manager for Stress Testing Framework

Implements circuit breakers, safety thresholds, and emergency shutdown mechanisms
to prevent system destruction during stress testing.
"""

import asyncio
import time
import logging
import psutil
import threading
from typing import Dict, List, Optional, Callable, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json
import os


class SafetyLevel(Enum):
    """Safety alert levels"""
    NORMAL = "normal"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class ThresholdType(Enum):
    """Types of safety thresholds"""
    CPU_USAGE = "cpu_usage"
    MEMORY_USAGE = "memory_usage"
    DISK_USAGE = "disk_usage"
    TEMPERATURE = "temperature"
    LOAD_AVERAGE = "load_average"
    SWAP_USAGE = "swap_usage"
    PROCESS_COUNT = "process_count"
    NETWORK_CONNECTIONS = "network_connections"


@dataclass
class SafetyThreshold:
    """Configuration for a safety threshold"""
    type: ThresholdType
    warning_level: float
    critical_level: float
    emergency_level: float
    check_interval: float = 1.0
    consecutive_violations: int = 3
    enabled: bool = True


@dataclass
class SafetyViolation:
    """Record of a safety threshold violation"""
    threshold_type: ThresholdType
    level: SafetyLevel
    current_value: float
    threshold_value: float
    timestamp: float
    consecutive_count: int
    message: str


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker"""
    failure_threshold: int = 5
    recovery_timeout: float = 30.0
    half_open_max_calls: int = 3
    success_threshold: int = 2


class CircuitBreakerState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Blocking calls due to failures
    HALF_OPEN = "half_open"  # Testing if service recovered


class CircuitBreaker:
    """Circuit breaker implementation for safety control"""
    
    def __init__(self, name: str, config: CircuitBreakerConfig):
        self.name = name
        self.config = config
        self.state = CircuitBreakerState.CLOSED
        
        # Failure tracking
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = 0.0
        
        # Half-open state tracking
        self.half_open_calls = 0
        
        self.logger = logging.getLogger(f"{__name__}.CircuitBreaker.{name}")
    
    async def call(self, func: Callable, *args, **kwargs):
        """Execute function through circuit breaker"""
        if self.state == CircuitBreakerState.OPEN:
            # Check if we should transition to half-open
            if time.time() - self.last_failure_time >= self.config.recovery_timeout:
                self.state = CircuitBreakerState.HALF_OPEN
                self.half_open_calls = 0
                self.logger.info(f"Circuit breaker {self.name} transitioning to HALF_OPEN")
            else:
                raise Exception(f"Circuit breaker {self.name} is OPEN")
        
        if self.state == CircuitBreakerState.HALF_OPEN:
            if self.half_open_calls >= self.config.half_open_max_calls:
                raise Exception(f"Circuit breaker {self.name} HALF_OPEN call limit exceeded")
        
        try:
            # Execute the function
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)
            
            # Handle success
            await self._on_success()
            return result
            
        except Exception as e:
            # Handle failure
            await self._on_failure()
            raise
    
    async def _on_success(self):
        """Handle successful call"""
        if self.state == CircuitBreakerState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.config.success_threshold:
                self.state = CircuitBreakerState.CLOSED
                self.failure_count = 0
                self.success_count = 0
                self.logger.info(f"Circuit breaker {self.name} transitioning to CLOSED")
        elif self.state == CircuitBreakerState.CLOSED:
            self.failure_count = 0  # Reset failure count on success
    
    async def _on_failure(self):
        """Handle failed call"""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.state == CircuitBreakerState.HALF_OPEN:
            self.state = CircuitBreakerState.OPEN
            self.logger.warning(f"Circuit breaker {self.name} transitioning to OPEN from HALF_OPEN")
        elif self.state == CircuitBreakerState.CLOSED:
            if self.failure_count >= self.config.failure_threshold:
                self.state = CircuitBreakerState.OPEN
                self.logger.warning(f"Circuit breaker {self.name} transitioning to OPEN")
    
    def get_state(self) -> CircuitBreakerState:
        """Get current circuit breaker state"""
        return self.state
    
    def reset(self):
        """Reset circuit breaker to closed state"""
        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.half_open_calls = 0
        self.logger.info(f"Circuit breaker {self.name} reset to CLOSED")


class SystemMonitor:
    """System resource monitoring for safety checks"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.SystemMonitor")
        self._monitoring = False
        self._monitor_task: Optional[asyncio.Task] = None
        self.current_metrics: Dict[str, float] = {}
        self.metric_history: List[Dict] = []
        self.max_history = 1000
    
    async def start_monitoring(self, interval: float = 1.0):
        """Start system monitoring"""
        if self._monitoring:
            return
        
        self._monitoring = True
        self._monitor_task = asyncio.create_task(self._monitor_loop(interval))
        self.logger.info("System monitoring started")
    
    async def stop_monitoring(self):
        """Stop system monitoring"""
        if not self._monitoring:
            return
        
        self._monitoring = False
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        
        self.logger.info("System monitoring stopped")
    
    async def _monitor_loop(self, interval: float):
        """Main monitoring loop"""
        while self._monitoring:
            try:
                metrics = await self._collect_metrics()
                self.current_metrics = metrics
                
                # Add to history
                self.metric_history.append({
                    'timestamp': time.time(),
                    'metrics': metrics.copy()
                })
                
                # Trim history
                if len(self.metric_history) > self.max_history:
                    self.metric_history = self.metric_history[-self.max_history:]
                
                await asyncio.sleep(interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Monitoring error: {e}")
                await asyncio.sleep(interval)
    
    async def _collect_metrics(self) -> Dict[str, float]:
        """Collect current system metrics"""
        metrics = {}
        
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=0.1)
            metrics['cpu_usage'] = cpu_percent
            
            # Load average
            if hasattr(os, 'getloadavg'):
                load_avg = os.getloadavg()[0]  # 1-minute load average
                metrics['load_average'] = load_avg
            
            # Memory metrics
            memory = psutil.virtual_memory()
            metrics['memory_usage'] = memory.percent
            
            # Swap metrics
            swap = psutil.swap_memory()
            metrics['swap_usage'] = swap.percent
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            metrics['disk_usage'] = disk.percent
            
            # Process count
            metrics['process_count'] = len(psutil.pids())
            
            # Network connections
            connections = psutil.net_connections()
            metrics['network_connections'] = len(connections)
            
            # Temperature (if available)
            try:
                temps = psutil.sensors_temperatures()
                if temps:
                    # Get average temperature across all sensors
                    all_temps = []
                    for sensor_name, sensor_list in temps.items():
                        for sensor in sensor_list:
                            if sensor.current:
                                all_temps.append(sensor.current)
                    
                    if all_temps:
                        metrics['temperature'] = sum(all_temps) / len(all_temps)
            except:
                pass  # Temperature monitoring not available
            
        except Exception as e:
            self.logger.error(f"Metrics collection error: {e}")
        
        return metrics
    
    def get_current_metrics(self) -> Dict[str, float]:
        """Get current system metrics"""
        return self.current_metrics.copy()
    
    def get_metric_history(self, metric_name: str, duration: float) -> List[Tuple[float, float]]:
        """Get history for specific metric over duration (seconds)"""
        cutoff_time = time.time() - duration
        history = []
        
        for entry in self.metric_history:
            if entry['timestamp'] >= cutoff_time:
                if metric_name in entry['metrics']:
                    history.append((entry['timestamp'], entry['metrics'][metric_name]))
        
        return history


class SafetyManager:
    """
    Main safety manager coordinating all safety mechanisms
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Components
        self.system_monitor = SystemMonitor()
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        
        # Safety configuration
        self.thresholds: Dict[ThresholdType, SafetyThreshold] = {}
        self.load_default_thresholds()
        
        # Violation tracking
        self.violation_history: List[SafetyViolation] = []
        self.consecutive_violations: Dict[ThresholdType, int] = {}
        
        # State
        self.initialized = False
        self.monitoring_active = False
        self.emergency_triggered = False
        
        # Callbacks
        self.violation_callbacks: List[Callable] = []
        self.emergency_callbacks: List[Callable] = []
        
        # Safety task
        self._safety_task: Optional[asyncio.Task] = None
    
    def load_default_thresholds(self):
        """Load default safety thresholds"""
        self.thresholds = {
            ThresholdType.CPU_USAGE: SafetyThreshold(
                type=ThresholdType.CPU_USAGE,
                warning_level=80.0,
                critical_level=90.0,
                emergency_level=95.0,
                check_interval=1.0,
                consecutive_violations=3
            ),
            ThresholdType.MEMORY_USAGE: SafetyThreshold(
                type=ThresholdType.MEMORY_USAGE,
                warning_level=85.0,
                critical_level=95.0,
                emergency_level=98.0,
                check_interval=1.0,
                consecutive_violations=3
            ),
            ThresholdType.DISK_USAGE: SafetyThreshold(
                type=ThresholdType.DISK_USAGE,
                warning_level=90.0,
                critical_level=95.0,
                emergency_level=98.0,
                check_interval=5.0,
                consecutive_violations=2
            ),
            ThresholdType.LOAD_AVERAGE: SafetyThreshold(
                type=ThresholdType.LOAD_AVERAGE,
                warning_level=psutil.cpu_count() * 2.0,
                critical_level=psutil.cpu_count() * 4.0,
                emergency_level=psutil.cpu_count() * 6.0,
                check_interval=1.0,
                consecutive_violations=5
            ),
            ThresholdType.SWAP_USAGE: SafetyThreshold(
                type=ThresholdType.SWAP_USAGE,
                warning_level=50.0,
                critical_level=80.0,
                emergency_level=95.0,
                check_interval=2.0,
                consecutive_violations=3
            ),
            ThresholdType.TEMPERATURE: SafetyThreshold(
                type=ThresholdType.TEMPERATURE,
                warning_level=70.0,
                critical_level=80.0,
                emergency_level=85.0,
                check_interval=2.0,
                consecutive_violations=3
            )
        }
    
    async def initialize(self):
        """Initialize safety manager"""
        if self.initialized:
            return
        
        self.logger.info("Initializing safety manager")
        
        # Initialize circuit breakers
        self._create_default_circuit_breakers()
        
        # Start system monitoring
        await self.system_monitor.start_monitoring(0.5)
        
        # Start safety monitoring
        self._safety_task = asyncio.create_task(self._safety_monitor_loop())
        
        self.initialized = True
        self.monitoring_active = True
        self.logger.info("Safety manager initialized")
    
    def _create_default_circuit_breakers(self):
        """Create default circuit breakers"""
        configs = {
            'cpu_protection': CircuitBreakerConfig(
                failure_threshold=3,
                recovery_timeout=10.0,
                half_open_max_calls=2,
                success_threshold=2
            ),
            'memory_protection': CircuitBreakerConfig(
                failure_threshold=2,
                recovery_timeout=15.0,
                half_open_max_calls=1,
                success_threshold=1
            ),
            'system_protection': CircuitBreakerConfig(
                failure_threshold=1,
                recovery_timeout=30.0,
                half_open_max_calls=1,
                success_threshold=1
            )
        }
        
        for name, config in configs.items():
            self.circuit_breakers[name] = CircuitBreaker(name, config)
    
    async def set_thresholds(self, threshold_config: Dict[str, float]):
        """Set custom safety thresholds"""
        for threshold_name, value in threshold_config.items():
            # Map string names to threshold types
            threshold_type = None
            for t_type in ThresholdType:
                if t_type.value == threshold_name or t_type.name.lower() == threshold_name.lower():
                    threshold_type = t_type
                    break
            
            if threshold_type and threshold_type in self.thresholds:
                # Update the critical level (most commonly adjusted)
                self.thresholds[threshold_type].critical_level = value
                self.logger.info(f"Updated {threshold_type.value} critical threshold to {value}")
    
    async def _safety_monitor_loop(self):
        """Main safety monitoring loop"""
        while self.monitoring_active:
            try:
                # Check all safety thresholds
                await self._check_safety_thresholds()
                
                await asyncio.sleep(0.5)  # Check every 500ms
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Safety monitoring error: {e}")
                await asyncio.sleep(1.0)
    
    async def _check_safety_thresholds(self):
        """Check all configured safety thresholds"""
        current_metrics = self.system_monitor.get_current_metrics()
        
        for threshold_type, threshold in self.thresholds.items():
            if not threshold.enabled:
                continue
            
            metric_name = threshold_type.value
            if metric_name not in current_metrics:
                continue
            
            current_value = current_metrics[metric_name]
            violation_level = self._check_threshold_violation(threshold, current_value)
            
            if violation_level != SafetyLevel.NORMAL:
                await self._handle_threshold_violation(threshold_type, violation_level, current_value)
            else:
                # Reset consecutive violation count
                self.consecutive_violations[threshold_type] = 0
    
    def _check_threshold_violation(self, threshold: SafetyThreshold, 
                                 current_value: float) -> SafetyLevel:
        """Check if a threshold is violated and at what level"""
        if current_value >= threshold.emergency_level:
            return SafetyLevel.EMERGENCY
        elif current_value >= threshold.critical_level:
            return SafetyLevel.CRITICAL
        elif current_value >= threshold.warning_level:
            return SafetyLevel.WARNING
        else:
            return SafetyLevel.NORMAL
    
    async def _handle_threshold_violation(self, threshold_type: ThresholdType, 
                                        level: SafetyLevel, current_value: float):
        """Handle a safety threshold violation"""
        # Track consecutive violations
        self.consecutive_violations[threshold_type] = (
            self.consecutive_violations.get(threshold_type, 0) + 1
        )
        
        threshold = self.thresholds[threshold_type]
        
        # Check if we have enough consecutive violations to trigger action
        if self.consecutive_violations[threshold_type] >= threshold.consecutive_violations:
            violation = SafetyViolation(
                threshold_type=threshold_type,
                level=level,
                current_value=current_value,
                threshold_value=self._get_threshold_value(threshold, level),
                timestamp=time.time(),
                consecutive_count=self.consecutive_violations[threshold_type],
                message=f"{threshold_type.value} at {current_value:.1f} exceeded {level.value} threshold"
            )
            
            self.violation_history.append(violation)
            
            # Notify violation callbacks
            await self._notify_violation(violation)
            
            # Take action based on severity
            if level == SafetyLevel.EMERGENCY:
                await self._trigger_emergency_response(violation)
            elif level == SafetyLevel.CRITICAL:
                await self._trigger_critical_response(violation)
    
    def _get_threshold_value(self, threshold: SafetyThreshold, level: SafetyLevel) -> float:
        """Get threshold value for specific level"""
        if level == SafetyLevel.EMERGENCY:
            return threshold.emergency_level
        elif level == SafetyLevel.CRITICAL:
            return threshold.critical_level
        elif level == SafetyLevel.WARNING:
            return threshold.warning_level
        else:
            return 0.0
    
    async def _trigger_emergency_response(self, violation: SafetyViolation):
        """Trigger emergency response for critical violation"""
        if self.emergency_triggered:
            return  # Already in emergency mode
        
        self.logger.critical(f"EMERGENCY: {violation.message}")
        self.emergency_triggered = True
        
        # Notify emergency callbacks
        await self._notify_emergency(violation)
        
        # Open system protection circuit breaker
        if 'system_protection' in self.circuit_breakers:
            cb = self.circuit_breakers['system_protection']
            await cb._on_failure()  # Force circuit breaker open
    
    async def _trigger_critical_response(self, violation: SafetyViolation):
        """Trigger critical response for severe violation"""
        self.logger.error(f"CRITICAL: {violation.message}")
        
        # Open appropriate circuit breaker
        if violation.threshold_type == ThresholdType.CPU_USAGE:
            if 'cpu_protection' in self.circuit_breakers:
                await self.circuit_breakers['cpu_protection']._on_failure()
        elif violation.threshold_type == ThresholdType.MEMORY_USAGE:
            if 'memory_protection' in self.circuit_breakers:
                await self.circuit_breakers['memory_protection']._on_failure()
    
    async def check_emergency_conditions(self) -> bool:
        """Check if emergency conditions are present"""
        return self.emergency_triggered
    
    async def check_circuit_breaker(self, name: str) -> bool:
        """Check if circuit breaker allows operation"""
        if name not in self.circuit_breakers:
            return True  # No circuit breaker, allow operation
        
        cb = self.circuit_breakers[name]
        return cb.get_state() == CircuitBreakerState.CLOSED
    
    async def execute_with_protection(self, name: str, func: Callable, *args, **kwargs):
        """Execute function with circuit breaker protection"""
        if name not in self.circuit_breakers:
            # No protection, execute directly
            if asyncio.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            else:
                return func(*args, **kwargs)
        
        return await self.circuit_breakers[name].call(func, *args, **kwargs)
    
    async def emergency_shutdown(self):
        """Perform emergency shutdown of safety manager"""
        self.logger.critical("Emergency shutdown initiated")
        
        self.emergency_triggered = True
        self.monitoring_active = False
        
        # Open all circuit breakers
        for cb in self.circuit_breakers.values():
            cb.state = CircuitBreakerState.OPEN
        
        # Stop monitoring
        await self.system_monitor.stop_monitoring()
        
        if self._safety_task:
            self._safety_task.cancel()
            try:
                await self._safety_task
            except asyncio.CancelledError:
                pass
    
    async def shutdown(self):
        """Normal shutdown of safety manager"""
        self.logger.info("Safety manager shutting down")
        
        self.monitoring_active = False
        
        # Stop monitoring
        await self.system_monitor.stop_monitoring()
        
        if self._safety_task:
            self._safety_task.cancel()
            try:
                await self._safety_task
            except asyncio.CancelledError:
                pass
        
        # Reset circuit breakers
        for cb in self.circuit_breakers.values():
            cb.reset()
        
        self.initialized = False
    
    # Callback registration
    def register_violation_callback(self, callback: Callable):
        """Register callback for safety violations"""
        self.violation_callbacks.append(callback)
    
    def register_emergency_callback(self, callback: Callable):
        """Register callback for emergency events"""
        self.emergency_callbacks.append(callback)
    
    # Notification methods
    async def _notify_violation(self, violation: SafetyViolation):
        """Notify registered callbacks of safety violation"""
        for callback in self.violation_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(violation)
                else:
                    callback(violation)
            except Exception as e:
                self.logger.error(f"Violation callback failed: {e}")
    
    async def _notify_emergency(self, violation: SafetyViolation):
        """Notify registered callbacks of emergency event"""
        for callback in self.emergency_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(violation)
                else:
                    callback(violation)
            except Exception as e:
                self.logger.error(f"Emergency callback failed: {e}")
    
    # Status and information methods
    def get_violation_history(self) -> List[SafetyViolation]:
        """Get history of safety violations"""
        return self.violation_history.copy()
    
    def get_current_status(self) -> Dict[str, Any]:
        """Get current safety manager status"""
        return {
            'initialized': self.initialized,
            'monitoring_active': self.monitoring_active,
            'emergency_triggered': self.emergency_triggered,
            'circuit_breakers': {
                name: cb.get_state().value
                for name, cb in self.circuit_breakers.items()
            },
            'current_metrics': self.system_monitor.get_current_metrics(),
            'recent_violations': len([
                v for v in self.violation_history
                if time.time() - v.timestamp < 300  # Last 5 minutes
            ])
        }
    
    def reset_emergency_state(self):
        """Reset emergency state (use with caution)"""
        self.logger.warning("Resetting emergency state")
        self.emergency_triggered = False
        
        # Reset circuit breakers
        for cb in self.circuit_breakers.values():
            cb.reset()
        
        # Clear consecutive violations
        self.consecutive_violations.clear()