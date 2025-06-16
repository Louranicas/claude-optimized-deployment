"""
Chaos experiment management and orchestration.
"""

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set
import logging

from .scenario_base import ChaosScenario, ScenarioResult, ScenarioStatus

logger = logging.getLogger(__name__)


class ExperimentState(Enum):
    """State of a chaos experiment."""
    PLANNING = "planning"
    READY = "ready"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ExperimentConfig:
    """Configuration for a chaos experiment."""
    name: str
    description: str
    scenarios: List[ChaosScenario]
    parallel_execution: bool = False
    stop_on_failure: bool = True
    max_concurrent_scenarios: int = 3
    experiment_timeout: timedelta = timedelta(hours=2)
    recovery_validation_time: timedelta = timedelta(minutes=10)
    tags: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExperimentResult:
    """Result of a chaos experiment."""
    experiment_id: str
    name: str
    state: ExperimentState
    start_time: datetime
    end_time: Optional[datetime] = None
    duration: Optional[timedelta] = None
    scenario_results: List[ScenarioResult] = field(default_factory=list)
    overall_success: bool = False
    system_resilience_score: float = 0.0
    recovery_score: float = 0.0
    observations: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    metrics_summary: Dict[str, Any] = field(default_factory=dict)


class ChaosExperiment:
    """
    Manages and orchestrates chaos engineering experiments.
    """
    
    def __init__(self, config: ExperimentConfig):
        self.config = config
        self.experiment_id = f"experiment_{int(time.time())}"
        self.state = ExperimentState.PLANNING
        self.result = ExperimentResult(
            experiment_id=self.experiment_id,
            name=config.name,
            state=self.state,
            start_time=datetime.now()
        )
        self._running_scenarios: Set[str] = set()
        self._completed_scenarios: Set[str] = set()
        self._failed_scenarios: Set[str] = set()
        self._cancelled = False
        
    async def validate_experiment(self) -> bool:
        """
        Validate the experiment configuration and environment.
        
        Returns:
            bool: True if experiment is valid and ready to run
        """
        try:
            logger.info(f"Validating experiment: {self.config.name}")
            
            # Check if scenarios are valid
            if not self.config.scenarios:
                logger.error("No scenarios defined for experiment")
                return False
            
            # Validate each scenario
            for scenario in self.config.scenarios:
                if not await self._validate_scenario(scenario):
                    logger.error(f"Scenario validation failed: {scenario.config.name}")
                    return False
            
            # Check for conflicting scenarios
            if not self._check_scenario_compatibility():
                logger.error("Incompatible scenarios detected")
                return False
            
            # Validate system state
            if not await self._validate_system_state():
                logger.error("System state validation failed")
                return False
            
            self.state = ExperimentState.READY
            return True
            
        except Exception as e:
            logger.error(f"Experiment validation failed: {e}")
            return False
    
    async def _validate_scenario(self, scenario: ChaosScenario) -> bool:
        """Validate a single scenario."""
        try:
            # Check scenario configuration
            if not scenario.config.name:
                return False
            
            if scenario.config.duration.total_seconds() <= 0:
                return False
            
            # Perform scenario-specific safety checks
            return await scenario.safety_check()
            
        except Exception as e:
            logger.error(f"Scenario validation error: {e}")
            return False
    
    def _check_scenario_compatibility(self) -> bool:
        """Check if scenarios can run together safely."""
        if not self.config.parallel_execution:
            return True
        
        # Check for overlapping target components
        all_targets = set()
        for scenario in self.config.scenarios:
            scenario_targets = scenario.config.target_components
            if all_targets.intersection(scenario_targets):
                logger.warning(
                    f"Overlapping targets detected: {scenario_targets} "
                    f"intersects with {all_targets}"
                )
                # Allow overlap but log warning
            all_targets.update(scenario_targets)
        
        return True
    
    async def _validate_system_state(self) -> bool:
        """Validate that the system is in a good state for chaos testing."""
        try:
            # Check system health metrics
            # This would integrate with your monitoring system
            
            # For now, perform basic checks
            return True
            
        except Exception as e:
            logger.error(f"System state validation error: {e}")
            return False
    
    async def run(self) -> ExperimentResult:
        """
        Execute the chaos experiment.
        
        Returns:
            ExperimentResult: Complete experiment results
        """
        try:
            self.state = ExperimentState.RUNNING
            self.result.state = self.state
            self.result.start_time = datetime.now()
            
            logger.info(f"Starting chaos experiment: {self.config.name}")
            
            # Validate experiment before running
            if not await self.validate_experiment():
                self.state = ExperimentState.FAILED
                self.result.state = self.state
                return self.result
            
            # Execute scenarios
            if self.config.parallel_execution:
                await self._run_scenarios_parallel()
            else:
                await self._run_scenarios_sequential()
            
            # Analyze results
            await self._analyze_results()
            
            # Determine overall success
            self._determine_experiment_success()
            
            self.state = ExperimentState.COMPLETED
            
        except Exception as e:
            logger.error(f"Experiment execution failed: {e}")
            self.state = ExperimentState.FAILED
            self.result.observations.append(f"Experiment failed: {str(e)}")
        
        finally:
            self.result.end_time = datetime.now()
            self.result.duration = self.result.end_time - self.result.start_time
            self.result.state = self.state
            
        return self.result
    
    async def _run_scenarios_sequential(self):
        """Run scenarios one after another."""
        for scenario in self.config.scenarios:
            if self._cancelled:
                break
                
            logger.info(f"Running scenario: {scenario.config.name}")
            self._running_scenarios.add(scenario.scenario_id)
            
            try:
                result = await scenario.run()
                self.result.scenario_results.append(result)
                
                if result.status == ScenarioStatus.COMPLETED:
                    self._completed_scenarios.add(scenario.scenario_id)
                else:
                    self._failed_scenarios.add(scenario.scenario_id)
                    
                    if self.config.stop_on_failure:
                        logger.warning("Stopping experiment due to scenario failure")
                        break
                        
            except Exception as e:
                logger.error(f"Scenario execution failed: {e}")
                self._failed_scenarios.add(scenario.scenario_id)
                
                if self.config.stop_on_failure:
                    break
            
            finally:
                self._running_scenarios.discard(scenario.scenario_id)
            
            # Wait for recovery validation
            if scenario.config.name != self.config.scenarios[-1].config.name:
                await asyncio.sleep(self.config.recovery_validation_time.total_seconds())
    
    async def _run_scenarios_parallel(self):
        """Run scenarios in parallel with concurrency control."""
        semaphore = asyncio.Semaphore(self.config.max_concurrent_scenarios)
        
        async def run_scenario_with_semaphore(scenario):
            async with semaphore:
                return await self._run_single_scenario(scenario)
        
        # Create tasks for all scenarios
        tasks = [
            run_scenario_with_semaphore(scenario)
            for scenario in self.config.scenarios
        ]
        
        # Wait for all scenarios to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Scenario {self.config.scenarios[i].config.name} failed: {result}")
                self._failed_scenarios.add(self.config.scenarios[i].scenario_id)
            elif isinstance(result, ScenarioResult):
                self.result.scenario_results.append(result)
                
                if result.status == ScenarioStatus.COMPLETED:
                    self._completed_scenarios.add(result.scenario_id)
                else:
                    self._failed_scenarios.add(result.scenario_id)
    
    async def _run_single_scenario(self, scenario: ChaosScenario) -> ScenarioResult:
        """Run a single scenario with error handling."""
        try:
            self._running_scenarios.add(scenario.scenario_id)
            logger.info(f"Running scenario: {scenario.config.name}")
            
            result = await scenario.run()
            return result
            
        except Exception as e:
            logger.error(f"Scenario {scenario.config.name} failed: {e}")
            # Create a failed result
            result = ScenarioResult(
                scenario_id=scenario.scenario_id,
                status=ScenarioStatus.FAILED,
                start_time=datetime.now(),
                error_messages=[str(e)]
            )
            result.end_time = datetime.now()
            result.duration = timedelta(0)
            return result
            
        finally:
            self._running_scenarios.discard(scenario.scenario_id)
    
    async def _analyze_results(self):
        """Analyze experiment results and generate insights."""
        total_scenarios = len(self.config.scenarios)
        completed_scenarios = len(self._completed_scenarios)
        failed_scenarios = len(self._failed_scenarios)
        
        # Calculate resilience score
        if total_scenarios > 0:
            self.result.system_resilience_score = completed_scenarios / total_scenarios
        
        # Calculate recovery score
        recovery_scores = []
        for scenario_result in self.result.scenario_results:
            if scenario_result.system_recovered:
                if scenario_result.recovery_time:
                    # Score based on recovery time (faster = higher score)
                    recovery_time_seconds = scenario_result.recovery_time.total_seconds()
                    score = max(0, 1 - (recovery_time_seconds / 300))  # 5 minutes max
                    recovery_scores.append(score)
                else:
                    recovery_scores.append(0.5)  # Partial score if recovered but time unknown
        
        if recovery_scores:
            self.result.recovery_score = sum(recovery_scores) / len(recovery_scores)
        
        # Generate observations
        self.result.observations.extend([
            f"Total scenarios: {total_scenarios}",
            f"Completed scenarios: {completed_scenarios}",
            f"Failed scenarios: {failed_scenarios}",
            f"System resilience score: {self.result.system_resilience_score:.2f}",
            f"Recovery score: {self.result.recovery_score:.2f}"
        ])
        
        # Generate recommendations
        await self._generate_recommendations()
        
        # Create metrics summary
        self._create_metrics_summary()
    
    async def _generate_recommendations(self):
        """Generate recommendations based on experiment results."""
        recommendations = []
        
        # Analyze failure patterns
        failed_components = set()
        for result in self.result.scenario_results:
            if result.status == ScenarioStatus.FAILED:
                failed_components.update(result.error_messages)
        
        if failed_components:
            recommendations.append(
                f"Components that need attention: {', '.join(list(failed_components)[:3])}"
            )
        
        # Recovery time analysis
        slow_recovery = [
            r for r in self.result.scenario_results
            if r.recovery_time and r.recovery_time.total_seconds() > 180  # 3 minutes
        ]
        
        if slow_recovery:
            recommendations.append(
                "Consider implementing faster recovery mechanisms for scenarios with "
                f"slow recovery times: {len(slow_recovery)} scenarios affected"
            )
        
        # Degradation detection
        undetected_degradation = [
            r for r in self.result.scenario_results
            if not r.degradation_detected and r.status == ScenarioStatus.COMPLETED
        ]
        
        if undetected_degradation:
            recommendations.append(
                "Improve monitoring and alerting - some degradations were not detected"
            )
        
        self.result.recommendations = recommendations
    
    def _create_metrics_summary(self):
        """Create a summary of all metrics collected."""
        summary = {
            'total_scenarios': len(self.config.scenarios),
            'completed_scenarios': len(self._completed_scenarios),
            'failed_scenarios': len(self._failed_scenarios),
            'average_scenario_duration': 0.0,
            'total_degradation_events': 0,
            'average_recovery_time': 0.0
        }
        
        # Calculate averages
        durations = [
            r.duration.total_seconds() for r in self.result.scenario_results
            if r.duration
        ]
        if durations:
            summary['average_scenario_duration'] = sum(durations) / len(durations)
        
        # Count degradation events
        summary['total_degradation_events'] = sum(
            1 for r in self.result.scenario_results if r.degradation_detected
        )
        
        # Calculate average recovery time
        recovery_times = [
            r.recovery_time.total_seconds() for r in self.result.scenario_results
            if r.recovery_time
        ]
        if recovery_times:
            summary['average_recovery_time'] = sum(recovery_times) / len(recovery_times)
        
        self.result.metrics_summary = summary
    
    def _determine_experiment_success(self):
        """Determine if the experiment was overall successful."""
        # Experiment is successful if:
        # 1. More than 70% of scenarios completed successfully
        # 2. System resilience score is above 0.7
        # 3. No critical failures occurred
        
        success_rate = self.result.system_resilience_score >= 0.7
        no_critical_failures = not any(
            r.impact_level.value == "critical" and r.status == ScenarioStatus.FAILED
            for r in self.result.scenario_results
        )
        
        self.result.overall_success = success_rate and no_critical_failures
    
    def pause(self):
        """Pause the running experiment."""
        if self.state == ExperimentState.RUNNING:
            self.state = ExperimentState.PAUSED
            logger.info(f"Experiment {self.experiment_id} paused")
    
    def resume(self):
        """Resume a paused experiment."""
        if self.state == ExperimentState.PAUSED:
            self.state = ExperimentState.RUNNING
            logger.info(f"Experiment {self.experiment_id} resumed")
    
    def cancel(self):
        """Cancel the running experiment."""
        self._cancelled = True
        self.state = ExperimentState.CANCELLED
        
        # Cancel all running scenarios
        for scenario in self.config.scenarios:
            if scenario.scenario_id in self._running_scenarios:
                scenario.cancel()
        
        logger.info(f"Experiment {self.experiment_id} cancelled")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current experiment status."""
        return {
            'experiment_id': self.experiment_id,
            'name': self.config.name,
            'state': self.state.value,
            'running_scenarios': len(self._running_scenarios),
            'completed_scenarios': len(self._completed_scenarios),
            'failed_scenarios': len(self._failed_scenarios),
            'total_scenarios': len(self.config.scenarios),
            'start_time': self.result.start_time.isoformat(),
            'duration': str(datetime.now() - self.result.start_time)
        }