"""
Memory Response - Automated response system for memory pressure.

This module provides automated responses to memory pressure including:
- Garbage collection triggers
- Memory cleanup operations
- Component resource scaling
- Circuit breaker activation
- Emergency shutdown procedures
"""

import asyncio
import gc
import time
import psutil
from typing import Dict, List, Optional, Callable, Any, Set
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import logging
from prometheus_client import Counter, Histogram, Gauge

from ..core.logging_config import get_logger
from ..core.exceptions import MonitoringError
from ..core.circuit_breaker import CircuitBreaker
from .memory_monitor import MemoryMonitor, MemorySnapshot, get_memory_monitor
from .memory_alerts import MemoryAlert, AlertLevel, MemoryAlertManager

logger = get_logger(__name__)

# Prometheus metrics
memory_responses_triggered_counter = Counter(
    'memory_responses_triggered_total',
    'Total number of memory responses triggered',
    ['response_type', 'trigger_level']
)

memory_cleanup_bytes_freed_gauge = Gauge(
    'memory_cleanup_bytes_freed',
    'Bytes freed by memory cleanup operations',
    ['cleanup_type']
)

memory_response_duration_histogram = Histogram(
    'memory_response_duration_seconds',
    'Time taken to execute memory responses',
    ['response_type']
)


class ResponseType(Enum):
    """Types of automated memory responses."""
    GARBAGE_COLLECTION = "gc"
    CACHE_CLEANUP = "cache_cleanup"
    CONNECTION_POOLING = "connection_pooling"
    CIRCUIT_BREAKER = "circuit_breaker"
    COMPONENT_SCALING = "component_scaling"
    EMERGENCY_SHUTDOWN = "emergency_shutdown"


class ResponseTrigger(Enum):
    """Triggers for memory responses."""
    THRESHOLD = "threshold"
    ALERT = "alert"
    PREDICTION = "prediction"
    MANUAL = "manual"


@dataclass
class ResponseAction:
    """Configuration for an automated memory response action."""
    name: str
    response_type: ResponseType
    trigger_threshold: float  # Memory percentage or bytes
    enabled: bool = True
    cooldown_seconds: int = 60
    max_executions_per_hour: int = 10
    priority: int = 1  # Higher number = higher priority
    component: Optional[str] = None
    
    # Action-specific configuration
    config: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.config is None:
            self.config = {}


@dataclass
class ResponseExecution:
    """Record of a response action execution."""
    action: ResponseAction
    trigger: ResponseTrigger
    timestamp: datetime
    trigger_value: float
    success: bool
    duration: float
    bytes_freed: int = 0
    error: Optional[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class MemoryResponseManager:
    """Manages automated responses to memory pressure."""
    
    def __init__(
        self,
        memory_monitor: Optional[MemoryMonitor] = None,
        alert_manager: Optional[MemoryAlertManager] = None
    ):
        self.memory_monitor = memory_monitor or get_memory_monitor()
        self.alert_manager = alert_manager
        
        # Response actions
        self.response_actions: List[ResponseAction] = []
        self._initialize_default_actions()
        
        # Execution tracking
        self.execution_history: List[ResponseExecution] = []
        self.last_execution_time: Dict[str, datetime] = {}
        self.execution_count_hour: Dict[str, int] = {}
        
        # Component handlers
        self.component_handlers: Dict[str, Any] = {}
        self.cleanup_handlers: Dict[str, Callable[[], int]] = {}
        
        # Circuit breakers for emergency responses
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        
        # State
        self._responding = False
        self._response_task: Optional[asyncio.Task] = None
    
    def _initialize_default_actions(self) -> None:
        """Initialize default memory response actions."""
        self.response_actions = [
            # Level 1: Warning (70%) - Gentle cleanup
            ResponseAction(
                name="gentle_gc",
                response_type=ResponseType.GARBAGE_COLLECTION,
                trigger_threshold=70.0,
                cooldown_seconds=120,
                max_executions_per_hour=5,
                priority=1,
                config={"generation": 0}  # Only gen 0 collections
            ),
            
            # Level 2: High (80%) - Aggressive cleanup
            ResponseAction(
                name="aggressive_gc",
                response_type=ResponseType.GARBAGE_COLLECTION,
                trigger_threshold=80.0,
                cooldown_seconds=60,
                max_executions_per_hour=10,
                priority=2,
                config={"full_collection": True}
            ),
            ResponseAction(
                name="cache_cleanup",
                response_type=ResponseType.CACHE_CLEANUP,
                trigger_threshold=80.0,
                cooldown_seconds=180,
                max_executions_per_hour=3,
                priority=2
            ),
            
            # Level 3: Critical (90%) - Resource management
            ResponseAction(
                name="connection_cleanup",
                response_type=ResponseType.CONNECTION_POOLING,
                trigger_threshold=90.0,
                cooldown_seconds=60,
                max_executions_per_hour=6,
                priority=3
            ),
            ResponseAction(
                name="circuit_breaker_activation",
                response_type=ResponseType.CIRCUIT_BREAKER,
                trigger_threshold=90.0,
                cooldown_seconds=30,
                max_executions_per_hour=12,
                priority=3
            ),
            
            # Level 4: Emergency (95%) - Drastic measures
            ResponseAction(
                name="component_scaling_down",
                response_type=ResponseType.COMPONENT_SCALING,
                trigger_threshold=95.0,
                cooldown_seconds=30,
                max_executions_per_hour=6,
                priority=4
            ),
            ResponseAction(
                name="emergency_shutdown",
                response_type=ResponseType.EMERGENCY_SHUTDOWN,
                trigger_threshold=98.0,
                cooldown_seconds=300,
                max_executions_per_hour=2,
                priority=5
            ),
            
            # Component-specific actions
            ResponseAction(
                name="circle_of_experts_cleanup",
                response_type=ResponseType.COMPONENT_SCALING,
                trigger_threshold=1073741824,  # 1GB
                component="circle_of_experts",
                cooldown_seconds=60,
                max_executions_per_hour=5,
                priority=2
            )
        ]
    
    async def start(self) -> None:
        """Start the memory response system."""
        if self._responding:
            logger.warning("Memory response manager already started")
            return
        
        self._responding = True
        self._response_task = asyncio.create_task(self._response_loop())
        
        # Register alert handler if alert manager is available
        if self.alert_manager:
            self.alert_manager.add_notification_handler(self._handle_alert)
        
        logger.info("Memory response manager started")
    
    async def stop(self) -> None:
        """Stop the memory response system."""
        if not self._responding:
            return
        
        self._responding = False
        if self._response_task:
            self._response_task.cancel()
            try:
                await self._response_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Memory response manager stopped")
    
    async def _response_loop(self) -> None:
        """Main response evaluation loop."""
        while self._responding:
            try:
                await self._evaluate_responses()
                await self._cleanup_execution_history()
                await asyncio.sleep(5)  # Evaluate every 5 seconds
                
            except Exception as e:
                logger.error(f"Error in memory response loop: {e}")
                await asyncio.sleep(5)
    
    async def _evaluate_responses(self) -> None:
        """Evaluate whether to trigger response actions."""
        snapshot = self.memory_monitor.get_current_snapshot()
        if not snapshot:
            return
        
        # Sort actions by priority (higher first)
        sorted_actions = sorted(
            self.response_actions,
            key=lambda x: x.priority,
            reverse=True
        )
        
        for action in sorted_actions:
            if not action.enabled:
                continue
            
            should_trigger = await self._should_trigger_action(action, snapshot)
            if should_trigger:
                await self._execute_action(action, ResponseTrigger.THRESHOLD, snapshot.percent_used)
                break  # Only execute highest priority action
    
    async def _should_trigger_action(
        self,
        action: ResponseAction,
        snapshot: MemorySnapshot
    ) -> bool:
        """Determine if an action should be triggered."""
        # Check threshold
        current_value = snapshot.percent_used
        if action.component:
            current_value = snapshot.component_usage.get(action.component, 0)
        
        if current_value < action.trigger_threshold:
            return False
        
        # Check cooldown
        last_execution = self.last_execution_time.get(action.name)
        if last_execution:
            time_since_last = (datetime.now() - last_execution).total_seconds()
            if time_since_last < action.cooldown_seconds:
                return False
        
        # Check execution limit
        current_hour_count = self._get_current_hour_executions(action.name)
        if current_hour_count >= action.max_executions_per_hour:
            return False
        
        return True
    
    async def _execute_action(
        self,
        action: ResponseAction,
        trigger: ResponseTrigger,
        trigger_value: float
    ) -> ResponseExecution:
        """Execute a memory response action."""
        start_time = time.time()
        
        try:
            logger.info(f"Executing memory response: {action.name} (trigger: {trigger_value:.1f})")
            
            bytes_freed = 0
            success = True
            error = None
            
            if action.response_type == ResponseType.GARBAGE_COLLECTION:
                bytes_freed = await self._execute_garbage_collection(action)
            elif action.response_type == ResponseType.CACHE_CLEANUP:
                bytes_freed = await self._execute_cache_cleanup(action)
            elif action.response_type == ResponseType.CONNECTION_POOLING:
                bytes_freed = await self._execute_connection_cleanup(action)
            elif action.response_type == ResponseType.CIRCUIT_BREAKER:
                await self._execute_circuit_breaker_activation(action)
            elif action.response_type == ResponseType.COMPONENT_SCALING:
                bytes_freed = await self._execute_component_scaling(action)
            elif action.response_type == ResponseType.EMERGENCY_SHUTDOWN:
                await self._execute_emergency_shutdown(action)
            else:
                raise ValueError(f"Unknown response type: {action.response_type}")
            
        except Exception as e:
            success = False
            error = str(e)
            logger.error(f"Error executing memory response {action.name}: {e}")
        
        duration = time.time() - start_time
        
        # Record execution
        execution = ResponseExecution(
            action=action,
            trigger=trigger,
            timestamp=datetime.now(),
            trigger_value=trigger_value,
            success=success,
            duration=duration,
            bytes_freed=bytes_freed,
            error=error
        )
        
        self.execution_history.append(execution)
        self.last_execution_time[action.name] = execution.timestamp
        self._increment_hour_count(action.name)
        
        # Update metrics
        memory_responses_triggered_counter.labels(
            response_type=action.response_type.value,
            trigger_level=trigger.value
        ).inc()
        
        if bytes_freed > 0:
            memory_cleanup_bytes_freed_gauge.labels(
                cleanup_type=action.response_type.value
            ).set(bytes_freed)
        
        memory_response_duration_histogram.labels(
            response_type=action.response_type.value
        ).observe(duration)
        
        logger.info(
            f"Memory response completed: {action.name} "
            f"(success: {success}, freed: {bytes_freed} bytes, duration: {duration:.2f}s)"
        )
        
        return execution
    
    async def _execute_garbage_collection(self, action: ResponseAction) -> int:
        """Execute garbage collection response."""
        initial_memory = psutil.Process().memory_info().rss
        
        if action.config.get("full_collection", False):
            # Full garbage collection
            gc.collect()
            gc.collect()  # Run twice for better cleanup
            gc.collect()
        else:
            # Generation-specific collection
            generation = action.config.get("generation", 0)
            if generation == 0:
                gc.collect(0)
            elif generation == 1:
                gc.collect(1)
            else:
                gc.collect()
        
        # Give system time to reclaim memory
        await asyncio.sleep(0.1)
        
        final_memory = psutil.Process().memory_info().rss
        bytes_freed = max(0, initial_memory - final_memory)
        
        return bytes_freed
    
    async def _execute_cache_cleanup(self, action: ResponseAction) -> int:
        """Execute cache cleanup response."""
        bytes_freed = 0
        
        # Call registered cleanup handlers
        for cleanup_name, cleanup_handler in self.cleanup_handlers.items():
            try:
                freed = cleanup_handler()
                bytes_freed += freed
                logger.info(f"Cache cleanup '{cleanup_name}' freed {freed} bytes")
            except Exception as e:
                logger.error(f"Error in cache cleanup '{cleanup_name}': {e}")
        
        # System-level cache cleanup
        try:
            # Force Python to release unused memory blocks
            import ctypes
            libc = ctypes.CDLL("libc.so.6")
            libc.malloc_trim(0)
            bytes_freed += 1024 * 1024  # Estimate
        except Exception:
            pass
        
        return bytes_freed
    
    async def _execute_connection_cleanup(self, action: ResponseAction) -> int:
        """Execute connection pool cleanup response."""
        bytes_freed = 0
        
        # Cleanup database connections
        try:
            from ..database.connection import cleanup_connections
            freed = await cleanup_connections()
            bytes_freed += freed
        except Exception as e:
            logger.error(f"Error cleaning up database connections: {e}")
        
        # Cleanup HTTP connections
        try:
            # Close idle HTTP connections
            import aiohttp
            connector = aiohttp.TCPConnector()
            await connector.close()
            bytes_freed += 64 * 1024  # Estimate
        except Exception as e:
            logger.error(f"Error cleaning up HTTP connections: {e}")
        
        return bytes_freed
    
    async def _execute_circuit_breaker_activation(self, action: ResponseAction) -> None:
        """Execute circuit breaker activation response."""
        # Activate circuit breakers for non-essential services
        critical_services = action.config.get("critical_services", [])
        
        for component, handler in self.component_handlers.items():
            if component in critical_services:
                continue
            
            try:
                if hasattr(handler, 'activate_circuit_breaker'):
                    handler.activate_circuit_breaker()
                    logger.info(f"Activated circuit breaker for {component}")
            except Exception as e:
                logger.error(f"Error activating circuit breaker for {component}: {e}")
    
    async def _execute_component_scaling(self, action: ResponseAction) -> int:
        """Execute component scaling response."""
        bytes_freed = 0
        
        if action.component:
            # Scale down specific component
            handler = self.component_handlers.get(action.component)
            if handler and hasattr(handler, 'scale_down'):
                try:
                    freed = handler.scale_down()
                    bytes_freed += freed
                    logger.info(f"Scaled down {action.component}, freed {freed} bytes")
                except Exception as e:
                    logger.error(f"Error scaling down {action.component}: {e}")
        else:
            # Scale down all non-critical components
            critical_components = action.config.get("critical_components", [])
            
            for component, handler in self.component_handlers.items():
                if component in critical_components:
                    continue
                
                if hasattr(handler, 'scale_down'):
                    try:
                        freed = handler.scale_down()
                        bytes_freed += freed
                        logger.info(f"Scaled down {component}, freed {freed} bytes")
                    except Exception as e:
                        logger.error(f"Error scaling down {component}: {e}")
        
        return bytes_freed
    
    async def _execute_emergency_shutdown(self, action: ResponseAction) -> None:
        """Execute emergency shutdown response."""
        logger.critical("EMERGENCY: Initiating emergency shutdown due to memory pressure")
        
        # Stop non-critical services
        critical_services = action.config.get("critical_services", ["monitoring", "logging"])
        
        for component, handler in self.component_handlers.items():
            if component in critical_services:
                continue
            
            try:
                if hasattr(handler, 'emergency_stop'):
                    handler.emergency_stop()
                elif hasattr(handler, 'stop'):
                    await handler.stop()
                logger.warning(f"Emergency stopped {component}")
            except Exception as e:
                logger.error(f"Error emergency stopping {component}: {e}")
        
        # If configured, exit the process
        if action.config.get("exit_process", False):
            logger.critical("Emergency shutdown: Exiting process")
            import sys
            sys.exit(1)
    
    def _handle_alert(self, alert: MemoryAlert) -> None:
        """Handle memory alert notifications."""
        # Find appropriate response action for alert level
        for action in self.response_actions:
            if not action.enabled:
                continue
            
            # Match alert level to action priority
            alert_priority_map = {
                AlertLevel.WARNING: 1,
                AlertLevel.HIGH: 2,
                AlertLevel.CRITICAL: 3,
                AlertLevel.EMERGENCY: 4
            }
            
            if action.priority == alert_priority_map.get(alert.level):
                # Execute action asynchronously
                asyncio.create_task(
                    self._execute_action(action, ResponseTrigger.ALERT, alert.current_value)
                )
                break
    
    def _get_current_hour_executions(self, action_name: str) -> int:
        """Get number of executions in current hour."""
        current_hour = datetime.now().replace(minute=0, second=0, microsecond=0)
        
        count = 0
        for execution in self.execution_history:
            if (execution.action.name == action_name and 
                execution.timestamp >= current_hour):
                count += 1
        
        return count
    
    def _increment_hour_count(self, action_name: str) -> None:
        """Increment execution count for current hour."""
        current_hour = datetime.now().strftime("%Y-%m-%d-%H")
        key = f"{action_name}_{current_hour}"
        self.execution_count_hour[key] = self.execution_count_hour.get(key, 0) + 1
    
    async def _cleanup_execution_history(self) -> None:
        """Clean up old execution history."""
        cutoff = datetime.now() - timedelta(hours=24)
        self.execution_history = [
            execution for execution in self.execution_history
            if execution.timestamp > cutoff
        ]
    
    def register_component_handler(self, component: str, handler: Any) -> None:
        """Register a component handler for scaling operations."""
        self.component_handlers[component] = handler
        logger.info(f"Registered component handler for '{component}'")
    
    def register_cleanup_handler(self, name: str, handler: Callable[[], int]) -> None:
        """Register a cleanup handler that returns bytes freed."""
        self.cleanup_handlers[name] = handler
        logger.info(f"Registered cleanup handler '{name}'")
    
    def add_response_action(self, action: ResponseAction) -> None:
        """Add a custom response action."""
        self.response_actions.append(action)
        logger.info(f"Added response action: {action.name}")
    
    async def trigger_manual_response(self, action_name: str, trigger_value: float = 0.0) -> ResponseExecution:
        """Manually trigger a response action."""
        action = None
        for a in self.response_actions:
            if a.name == action_name:
                action = a
                break
        
        if not action:
            raise ValueError(f"Response action '{action_name}' not found")
        
        return await self._execute_action(action, ResponseTrigger.MANUAL, trigger_value)
    
    def get_execution_history(self, hours: int = 24) -> List[ResponseExecution]:
        """Get execution history for specified hours."""
        cutoff = datetime.now() - timedelta(hours=hours)
        return [
            execution for execution in self.execution_history
            if execution.timestamp > cutoff
        ]
    
    def get_response_actions(self) -> List[ResponseAction]:
        """Get list of configured response actions."""
        return self.response_actions.copy()


# Global response manager instance
_response_manager: Optional[MemoryResponseManager] = None


async def get_response_manager() -> MemoryResponseManager:
    """Get or create the global response manager instance."""
    global _response_manager
    if _response_manager is None:
        _response_manager = MemoryResponseManager()
        await _response_manager.start()
    return _response_manager


async def shutdown_response_manager() -> None:
    """Shutdown the global response manager."""
    global _response_manager
    if _response_manager is not None:
        await _response_manager.stop()
        _response_manager = None