"""
Base classes for chaos engineering scenarios.
"""

import asyncio
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set
import logging

logger = logging.getLogger(__name__)


class ScenarioStatus(Enum):
    """Status of a chaos scenario."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ImpactLevel(Enum):
    """Impact level of a chaos scenario."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ScenarioResult:
    """Result of a chaos scenario execution."""
    scenario_id: str
    status: ScenarioStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    duration: Optional[timedelta] = None
    impact_level: ImpactLevel = ImpactLevel.LOW
    metrics: Dict[str, Any] = field(default_factory=dict)
    observations: List[str] = field(default_factory=list)
    recovery_time: Optional[timedelta] = None
    degradation_detected: bool = False
    system_recovered: bool = False
    error_messages: List[str] = field(default_factory=list)


@dataclass
class ScenarioConfig:
    """Configuration for a chaos scenario."""
    name: str
    description: str
    duration: timedelta
    impact_level: ImpactLevel
    target_components: Set[str]
    rollback_timeout: timedelta = timedelta(minutes=5)
    safety_checks: bool = True
    dry_run: bool = False
    parameters: Dict[str, Any] = field(default_factory=dict)


class ChaosScenario(ABC):
    """Base class for chaos engineering scenarios."""
    
    def __init__(self, config: ScenarioConfig):
        self.config = config
        self.scenario_id = f"{config.name}_{int(time.time())}"
        self.result = ScenarioResult(
            scenario_id=self.scenario_id,
            status=ScenarioStatus.PENDING,
            start_time=datetime.now(),
            impact_level=config.impact_level
        )
        self._cancelled = False
        self._rollback_handlers = []
        
    @abstractmethod
    async def setup(self) -> bool:
        """
        Setup the scenario environment.
        
        Returns:
            bool: True if setup was successful
        """
        pass
    
    @abstractmethod
    async def execute_chaos(self) -> bool:
        """
        Execute the chaos scenario.
        
        Returns:
            bool: True if chaos was successfully introduced
        """
        pass
    
    @abstractmethod
    async def monitor_impact(self) -> Dict[str, Any]:
        """
        Monitor the impact of the chaos scenario.
        
        Returns:
            Dict containing impact metrics
        """
        pass
    
    @abstractmethod
    async def cleanup(self) -> bool:
        """
        Clean up and restore normal operation.
        
        Returns:
            bool: True if cleanup was successful
        """
        pass
    
    async def safety_check(self) -> bool:
        """
        Perform safety checks before executing chaos.
        
        Returns:
            bool: True if it's safe to proceed
        """
        if not self.config.safety_checks:
            return True
            
        # Default safety checks
        try:
            # Check if system is already under stress
            load_metrics = await self.get_system_load()
            if load_metrics.get('cpu_usage', 0) > 80:
                logger.warning("High CPU usage detected, skipping chaos scenario")
                return False
                
            if load_metrics.get('memory_usage', 0) > 85:
                logger.warning("High memory usage detected, skipping chaos scenario")
                return False
                
            return True
        except Exception as e:
            logger.error(f"Safety check failed: {e}")
            return False
    
    async def get_system_load(self) -> Dict[str, float]:
        """Get current system load metrics."""
        # Implementation depends on monitoring system
        return {'cpu_usage': 0.0, 'memory_usage': 0.0}
    
    def add_rollback_handler(self, handler):
        """Add a rollback handler for emergency recovery."""
        self._rollback_handlers.append(handler)
    
    async def emergency_rollback(self):
        """Execute emergency rollback procedures."""
        logger.warning(f"Executing emergency rollback for scenario {self.scenario_id}")
        
        for handler in reversed(self._rollback_handlers):
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler()
                else:
                    handler()
            except Exception as e:
                logger.error(f"Rollback handler failed: {e}")
    
    async def run(self) -> ScenarioResult:
        """
        Execute the complete chaos scenario.
        
        Returns:
            ScenarioResult: Result of the scenario execution
        """
        try:
            self.result.status = ScenarioStatus.RUNNING
            self.result.start_time = datetime.now()
            
            logger.info(f"Starting chaos scenario: {self.config.name}")
            
            # Perform safety checks
            if not await self.safety_check():
                self.result.status = ScenarioStatus.FAILED
                self.result.error_messages.append("Safety checks failed")
                return self.result
            
            # Setup phase
            if not await self.setup():
                self.result.status = ScenarioStatus.FAILED
                self.result.error_messages.append("Setup phase failed")
                return self.result
            
            # Execute chaos (if not dry run)
            if not self.config.dry_run:
                chaos_success = await self.execute_chaos()
                if not chaos_success:
                    self.result.status = ScenarioStatus.FAILED
                    self.result.error_messages.append("Chaos execution failed")
                    await self.cleanup()
                    return self.result
            
            # Monitor impact
            start_monitor = time.time()
            monitoring_duration = self.config.duration.total_seconds()
            
            while time.time() - start_monitor < monitoring_duration and not self._cancelled:
                impact_metrics = await self.monitor_impact()
                self.result.metrics.update(impact_metrics)
                
                # Check for degradation
                if self._detect_degradation(impact_metrics):
                    self.result.degradation_detected = True
                    self.result.observations.append(
                        f"System degradation detected at {datetime.now()}"
                    )
                
                await asyncio.sleep(1)  # Monitor every second
            
            # Cleanup phase
            cleanup_start = time.time()
            cleanup_success = await self.cleanup()
            
            if cleanup_success:
                # Monitor recovery
                recovery_start = time.time()
                while time.time() - recovery_start < self.config.rollback_timeout.total_seconds():
                    recovery_metrics = await self.monitor_impact()
                    if self._detect_recovery(recovery_metrics):
                        self.result.system_recovered = True
                        self.result.recovery_time = timedelta(seconds=time.time() - recovery_start)
                        break
                    await asyncio.sleep(1)
            
            self.result.status = ScenarioStatus.COMPLETED if cleanup_success else ScenarioStatus.FAILED
            
        except Exception as e:
            logger.error(f"Chaos scenario failed: {e}")
            self.result.status = ScenarioStatus.FAILED
            self.result.error_messages.append(str(e))
            
            # Attempt emergency rollback
            try:
                await self.emergency_rollback()
            except Exception as rollback_error:
                logger.error(f"Emergency rollback failed: {rollback_error}")
        
        finally:
            self.result.end_time = datetime.now()
            self.result.duration = self.result.end_time - self.result.start_time
            
        return self.result
    
    def _detect_degradation(self, metrics: Dict[str, Any]) -> bool:
        """Detect if system degradation occurred."""
        # Default degradation detection logic
        response_time = metrics.get('response_time', 0)
        error_rate = metrics.get('error_rate', 0)
        
        return response_time > 5000 or error_rate > 0.1  # 5s response time or 10% error rate
    
    def _detect_recovery(self, metrics: Dict[str, Any]) -> bool:
        """Detect if system has recovered."""
        # Default recovery detection logic
        response_time = metrics.get('response_time', 0)
        error_rate = metrics.get('error_rate', 0)
        
        return response_time < 1000 and error_rate < 0.01  # Normal response time and error rate
    
    def cancel(self):
        """Cancel the running scenario."""
        self._cancelled = True
        self.result.status = ScenarioStatus.CANCELLED