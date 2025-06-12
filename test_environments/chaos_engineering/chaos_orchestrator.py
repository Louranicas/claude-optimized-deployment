"""
Chaos Engineering Orchestrator

Central coordination system for chaos experiments, managing experiment lifecycle,
safety mechanisms, and expert-driven scenario selection.
"""

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, Set
from datetime import datetime, timedelta
import json

from .failure_injector import FailureInjector
from .resilience_validator import ResilienceValidator
from .breaking_point_analyzer import BreakingPointAnalyzer
from .recovery_measurer import RecoveryMeasurer
from .safety.safety_controller import SafetyController

logger = logging.getLogger(__name__)


class ExperimentState(Enum):
    """States of chaos experiments"""
    PLANNING = "planning"
    READY = "ready"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    EMERGENCY_STOPPED = "emergency_stopped"


class ExperimentType(Enum):
    """Types of chaos experiments"""
    SERVICE_CHAOS = "service_chaos"
    NETWORK_CHAOS = "network_chaos"
    RESOURCE_CHAOS = "resource_chaos"
    DATA_CHAOS = "data_chaos"
    INFRASTRUCTURE_CHAOS = "infrastructure_chaos"
    CASCADE_FAILURE = "cascade_failure"
    BREAKING_POINT = "breaking_point"
    RESILIENCE_TEST = "resilience_test"


@dataclass
class ChaosExperiment:
    """Chaos experiment definition"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    experiment_type: ExperimentType = ExperimentType.SERVICE_CHAOS
    state: ExperimentState = ExperimentState.PLANNING
    
    # Experiment configuration
    target_services: List[str] = field(default_factory=list)
    failure_scenarios: List[Dict[str, Any]] = field(default_factory=list)
    duration_seconds: int = 300
    blast_radius: float = 0.1  # Percentage of system to affect
    
    # Safety and monitoring
    health_checks: List[str] = field(default_factory=list)
    rollback_triggers: List[str] = field(default_factory=list)
    max_failure_rate: float = 0.05  # 5% max failure rate
    
    # Results and metrics
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    results: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, Any] = field(default_factory=dict)
    
    # Expert guidance
    expert_recommendations: List[str] = field(default_factory=list)
    adaptive_strategy: bool = True


@dataclass
class ChaosMetrics:
    """Chaos experiment metrics and measurements"""
    experiment_id: str
    mttd_seconds: float = 0.0  # Mean Time To Detection
    mttr_seconds: float = 0.0  # Mean Time To Recovery
    failure_rate: float = 0.0
    availability_impact: float = 0.0
    performance_degradation: float = 0.0
    recovery_effectiveness: float = 0.0
    resilience_score: float = 0.0
    
    # Breaking point metrics
    capacity_limit: Optional[float] = None
    performance_cliff: Optional[float] = None
    failure_threshold: Optional[float] = None


class ChaosOrchestrator:
    """
    Central chaos engineering orchestrator for coordinating experiments,
    managing safety, and providing expert-driven chaos testing.
    """
    
    def __init__(self, expert_manager=None):
        self.expert_manager = expert_manager
        self.failure_injector = FailureInjector()
        self.resilience_validator = ResilienceValidator()
        self.breaking_point_analyzer = BreakingPointAnalyzer()
        self.recovery_measurer = RecoveryMeasurer()
        self.safety_controller = SafetyController()
        
        # Experiment management
        self.experiments: Dict[str, ChaosExperiment] = {}
        self.active_experiments: Set[str] = set()
        self.experiment_history: List[ChaosExperiment] = []
        
        # Safety and monitoring
        self.safety_checks_enabled = True
        self.emergency_stop_triggers: List[Callable] = []
        self.health_monitors: Dict[str, Callable] = {}
        
        # Expert integration
        self.expert_consultation_enabled = True
        self.adaptive_chaos_enabled = True
        
        # Metrics and analytics
        self.metrics_store: Dict[str, ChaosMetrics] = {}
        self.global_resilience_score = 0.0
        
        logger.info("Chaos Orchestrator initialized")
    
    async def create_experiment(self, experiment_config: Dict[str, Any]) -> ChaosExperiment:
        """Create and plan a new chaos experiment"""
        experiment = ChaosExperiment(
            name=experiment_config.get("name", f"chaos_experiment_{int(time.time())}"),
            description=experiment_config.get("description", ""),
            experiment_type=ExperimentType(experiment_config.get("type", "service_chaos")),
            target_services=experiment_config.get("target_services", []),
            failure_scenarios=experiment_config.get("failure_scenarios", []),
            duration_seconds=experiment_config.get("duration_seconds", 300),
            blast_radius=experiment_config.get("blast_radius", 0.1),
            health_checks=experiment_config.get("health_checks", []),
            rollback_triggers=experiment_config.get("rollback_triggers", []),
            max_failure_rate=experiment_config.get("max_failure_rate", 0.05)
        )
        
        # Expert consultation for experiment planning
        if self.expert_consultation_enabled and self.expert_manager:
            expert_recommendations = await self._get_expert_recommendations(experiment)
            experiment.expert_recommendations = expert_recommendations
            
            # Apply expert recommendations
            experiment = await self._apply_expert_recommendations(experiment, expert_recommendations)
        
        # Safety validation
        safety_validation = await self.safety_controller.validate_experiment(experiment)
        if not safety_validation["safe"]:
            raise ValueError(f"Experiment failed safety validation: {safety_validation['reasons']}")
        
        experiment.state = ExperimentState.READY
        self.experiments[experiment.id] = experiment
        
        logger.info(f"Created chaos experiment: {experiment.name} ({experiment.id})")
        return experiment
    
    async def run_experiment(self, experiment_id: str) -> ChaosMetrics:
        """Execute a chaos experiment with full orchestration and monitoring"""
        experiment = self.experiments.get(experiment_id)
        if not experiment:
            raise ValueError(f"Experiment {experiment_id} not found")
        
        if experiment.state != ExperimentState.READY:
            raise ValueError(f"Experiment {experiment_id} is not ready (state: {experiment.state})")
        
        logger.info(f"Starting chaos experiment: {experiment.name}")
        
        try:
            # Pre-experiment safety checks
            await self._pre_experiment_safety_checks(experiment)
            
            # Start experiment
            experiment.state = ExperimentState.RUNNING
            experiment.start_time = datetime.now()
            self.active_experiments.add(experiment_id)
            
            # Initialize metrics collection
            metrics = ChaosMetrics(experiment_id=experiment_id)
            
            # Start monitoring and safety systems
            monitoring_task = asyncio.create_task(self._monitor_experiment(experiment))
            safety_task = asyncio.create_task(self._safety_monitoring(experiment))
            
            # Execute failure scenarios
            failure_results = []
            for scenario in experiment.failure_scenarios:
                scenario_result = await self._execute_failure_scenario(experiment, scenario)
                failure_results.append(scenario_result)
                
                # Check for emergency stop conditions
                if await self._check_emergency_stop_conditions(experiment):
                    logger.warning(f"Emergency stop triggered for experiment {experiment_id}")
                    break
            
            # Measure resilience and recovery
            resilience_metrics = await self._measure_resilience(experiment)
            recovery_metrics = await self._measure_recovery(experiment)
            
            # Update metrics
            metrics.mttd_seconds = resilience_metrics.get("mttd_seconds", 0.0)
            metrics.mttr_seconds = recovery_metrics.get("mttr_seconds", 0.0)
            metrics.failure_rate = resilience_metrics.get("failure_rate", 0.0)
            metrics.availability_impact = resilience_metrics.get("availability_impact", 0.0)
            metrics.performance_degradation = resilience_metrics.get("performance_degradation", 0.0)
            metrics.recovery_effectiveness = recovery_metrics.get("effectiveness", 0.0)
            metrics.resilience_score = await self._calculate_resilience_score(metrics)
            
            # Breaking point analysis if requested
            if experiment.experiment_type == ExperimentType.BREAKING_POINT:
                breaking_point_metrics = await self._analyze_breaking_points(experiment)
                metrics.capacity_limit = breaking_point_metrics.get("capacity_limit")
                metrics.performance_cliff = breaking_point_metrics.get("performance_cliff")
                metrics.failure_threshold = breaking_point_metrics.get("failure_threshold")
            
            # Complete experiment
            experiment.state = ExperimentState.COMPLETED
            experiment.end_time = datetime.now()
            experiment.results = {
                "failure_results": failure_results,
                "resilience_metrics": resilience_metrics,
                "recovery_metrics": recovery_metrics
            }
            experiment.metrics = metrics.__dict__
            
            # Stop monitoring tasks
            monitoring_task.cancel()
            safety_task.cancel()
            
            # Post-experiment cleanup and validation
            await self._post_experiment_cleanup(experiment)
            
            # Store metrics
            self.metrics_store[experiment_id] = metrics
            self.active_experiments.discard(experiment_id)
            self.experiment_history.append(experiment)
            
            # Expert analysis and recommendations
            if self.expert_consultation_enabled and self.expert_manager:
                expert_analysis = await self._get_expert_analysis(experiment, metrics)
                experiment.results["expert_analysis"] = expert_analysis
            
            logger.info(f"Completed chaos experiment: {experiment.name}")
            return metrics
            
        except Exception as e:
            experiment.state = ExperimentState.FAILED
            experiment.end_time = datetime.now()
            self.active_experiments.discard(experiment_id)
            
            # Emergency cleanup
            await self._emergency_cleanup(experiment)
            
            logger.error(f"Chaos experiment failed: {experiment.name} - {str(e)}")
            raise
    
    async def emergency_stop_experiment(self, experiment_id: str) -> bool:
        """Emergency stop a running experiment"""
        experiment = self.experiments.get(experiment_id)
        if not experiment:
            return False
        
        if experiment.state != ExperimentState.RUNNING:
            return False
        
        logger.warning(f"Emergency stopping experiment: {experiment.name}")
        
        experiment.state = ExperimentState.EMERGENCY_STOPPED
        experiment.end_time = datetime.now()
        self.active_experiments.discard(experiment_id)
        
        # Emergency cleanup and recovery
        await self._emergency_cleanup(experiment)
        
        return True
    
    async def pause_experiment(self, experiment_id: str) -> bool:
        """Pause a running experiment"""
        experiment = self.experiments.get(experiment_id)
        if not experiment or experiment.state != ExperimentState.RUNNING:
            return False
        
        experiment.state = ExperimentState.PAUSED
        logger.info(f"Paused experiment: {experiment.name}")
        return True
    
    async def resume_experiment(self, experiment_id: str) -> bool:
        """Resume a paused experiment"""
        experiment = self.experiments.get(experiment_id)
        if not experiment or experiment.state != ExperimentState.PAUSED:
            return False
        
        experiment.state = ExperimentState.RUNNING
        logger.info(f"Resumed experiment: {experiment.name}")
        return True
    
    async def get_experiment_status(self, experiment_id: str) -> Dict[str, Any]:
        """Get detailed status of an experiment"""
        experiment = self.experiments.get(experiment_id)
        if not experiment:
            return {"error": "Experiment not found"}
        
        metrics = self.metrics_store.get(experiment_id)
        
        return {
            "experiment": {
                "id": experiment.id,
                "name": experiment.name,
                "state": experiment.state.value,
                "type": experiment.experiment_type.value,
                "start_time": experiment.start_time.isoformat() if experiment.start_time else None,
                "end_time": experiment.end_time.isoformat() if experiment.end_time else None,
                "duration": (experiment.end_time - experiment.start_time).total_seconds() 
                           if experiment.start_time and experiment.end_time else None
            },
            "metrics": metrics.__dict__ if metrics else None,
            "results": experiment.results,
            "safety_status": await self.safety_controller.get_safety_status(experiment_id)
        }
    
    async def get_global_resilience_metrics(self) -> Dict[str, Any]:
        """Get global system resilience metrics across all experiments"""
        if not self.metrics_store:
            return {"resilience_score": 0.0, "total_experiments": 0}
        
        total_experiments = len(self.metrics_store)
        avg_resilience_score = sum(m.resilience_score for m in self.metrics_store.values()) / total_experiments
        avg_mttd = sum(m.mttd_seconds for m in self.metrics_store.values()) / total_experiments
        avg_mttr = sum(m.mttr_seconds for m in self.metrics_store.values()) / total_experiments
        
        return {
            "resilience_score": avg_resilience_score,
            "total_experiments": total_experiments,
            "avg_mttd_seconds": avg_mttd,
            "avg_mttr_seconds": avg_mttr,
            "experiments_by_type": self._get_experiment_type_distribution(),
            "success_rate": len([e for e in self.experiment_history if e.state == ExperimentState.COMPLETED]) / total_experiments
        }
    
    # Expert integration methods
    async def _get_expert_recommendations(self, experiment: ChaosExperiment) -> List[str]:
        """Get expert recommendations for experiment design"""
        if not self.expert_manager:
            return []
        
        query = f"""
        Analyze this chaos engineering experiment and provide recommendations:
        
        Experiment Type: {experiment.experiment_type.value}
        Target Services: {experiment.target_services}
        Failure Scenarios: {experiment.failure_scenarios}
        Duration: {experiment.duration_seconds} seconds
        Blast Radius: {experiment.blast_radius}
        
        Please provide specific recommendations for:
        1. Optimal failure scenarios for maximum learning
        2. Safety considerations and blast radius optimization
        3. Monitoring and detection strategies
        4. Recovery validation approaches
        5. Breaking point identification methods
        """
        
        try:
            response = await self.expert_manager.query_experts(
                query=query,
                expertise_areas=["reliability", "chaos_engineering", "system_architecture"]
            )
            return [r.content for r in response.expert_responses]
        except Exception as e:
            logger.warning(f"Failed to get expert recommendations: {e}")
            return []
    
    async def _apply_expert_recommendations(self, experiment: ChaosExperiment, recommendations: List[str]) -> ChaosExperiment:
        """Apply expert recommendations to experiment configuration"""
        # This would analyze recommendations and modify experiment configuration
        # For now, just store them for reference
        experiment.expert_recommendations = recommendations
        return experiment
    
    async def _get_expert_analysis(self, experiment: ChaosExperiment, metrics: ChaosMetrics) -> Dict[str, Any]:
        """Get expert analysis of experiment results"""
        if not self.expert_manager:
            return {}
        
        query = f"""
        Analyze these chaos engineering experiment results:
        
        Experiment: {experiment.name}
        Type: {experiment.experiment_type.value}
        Duration: {(experiment.end_time - experiment.start_time).total_seconds() if experiment.start_time and experiment.end_time else 0} seconds
        
        Metrics:
        - MTTD: {metrics.mttd_seconds} seconds
        - MTTR: {metrics.mttr_seconds} seconds
        - Failure Rate: {metrics.failure_rate}
        - Availability Impact: {metrics.availability_impact}
        - Recovery Effectiveness: {metrics.recovery_effectiveness}
        - Resilience Score: {metrics.resilience_score}
        
        Results: {experiment.results}
        
        Please provide:
        1. Analysis of system resilience strengths and weaknesses
        2. Recommendations for improving recovery mechanisms
        3. Suggested follow-up experiments
        4. Risk assessment and mitigation strategies
        """
        
        try:
            response = await self.expert_manager.query_experts(
                query=query,
                expertise_areas=["reliability", "chaos_engineering", "performance"]
            )
            return {
                "expert_insights": [r.content for r in response.expert_responses],
                "confidence_score": response.confidence_score,
                "recommendations": response.recommendations
            }
        except Exception as e:
            logger.warning(f"Failed to get expert analysis: {e}")
            return {}
    
    # Safety and monitoring methods
    async def _pre_experiment_safety_checks(self, experiment: ChaosExperiment):
        """Perform safety checks before starting experiment"""
        safety_result = await self.safety_controller.pre_experiment_check(experiment)
        if not safety_result["safe"]:
            raise ValueError(f"Pre-experiment safety check failed: {safety_result['reasons']}")
    
    async def _monitor_experiment(self, experiment: ChaosExperiment):
        """Monitor experiment progress and health"""
        while experiment.state == ExperimentState.RUNNING:
            # Check system health
            health_status = await self._check_system_health(experiment)
            if not health_status["healthy"]:
                logger.warning(f"Health check failed for experiment {experiment.id}: {health_status['issues']}")
            
            # Update metrics
            await self._update_real_time_metrics(experiment)
            
            await asyncio.sleep(5)  # Check every 5 seconds
    
    async def _safety_monitoring(self, experiment: ChaosExperiment):
        """Continuous safety monitoring during experiment"""
        while experiment.state == ExperimentState.RUNNING:
            safety_status = await self.safety_controller.continuous_safety_check(experiment)
            if not safety_status["safe"]:
                logger.error(f"Safety violation detected for experiment {experiment.id}: {safety_status['violations']}")
                await self.emergency_stop_experiment(experiment.id)
                break
            
            await asyncio.sleep(2)  # Check every 2 seconds
    
    async def _check_emergency_stop_conditions(self, experiment: ChaosExperiment) -> bool:
        """Check if emergency stop conditions are met"""
        # Check failure rate
        current_metrics = await self._get_current_metrics(experiment)
        if current_metrics.get("failure_rate", 0) > experiment.max_failure_rate:
            return True
        
        # Check custom emergency stop triggers
        for trigger in self.emergency_stop_triggers:
            if await trigger(experiment):
                return True
        
        return False
    
    # Implementation methods for failure scenarios and measurements
    async def _execute_failure_scenario(self, experiment: ChaosExperiment, scenario: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a specific failure scenario"""
        scenario_type = scenario.get("type")
        scenario_config = scenario.get("config", {})
        
        start_time = time.time()
        
        try:
            if scenario_type == "service_failure":
                result = await self.failure_injector.inject_service_failure(
                    service=scenario_config.get("service"),
                    failure_type=scenario_config.get("failure_type"),
                    duration=scenario_config.get("duration", 60)
                )
            elif scenario_type == "network_partition":
                result = await self.failure_injector.inject_network_partition(
                    services=scenario_config.get("services", []),
                    partition_type=scenario_config.get("partition_type"),
                    duration=scenario_config.get("duration", 60)
                )
            elif scenario_type == "resource_exhaustion":
                result = await self.failure_injector.inject_resource_exhaustion(
                    resource_type=scenario_config.get("resource_type"),
                    intensity=scenario_config.get("intensity", 0.8),
                    duration=scenario_config.get("duration", 60)
                )
            else:
                result = {"error": f"Unknown scenario type: {scenario_type}"}
            
            execution_time = time.time() - start_time
            return {
                "scenario": scenario,
                "result": result,
                "execution_time": execution_time,
                "success": "error" not in result
            }
            
        except Exception as e:
            return {
                "scenario": scenario,
                "result": {"error": str(e)},
                "execution_time": time.time() - start_time,
                "success": False
            }
    
    async def _measure_resilience(self, experiment: ChaosExperiment) -> Dict[str, Any]:
        """Measure system resilience during experiment"""
        return await self.resilience_validator.measure_resilience(
            experiment.target_services,
            experiment.start_time,
            experiment.end_time or datetime.now()
        )
    
    async def _measure_recovery(self, experiment: ChaosExperiment) -> Dict[str, Any]:
        """Measure recovery effectiveness and timing"""
        return await self.recovery_measurer.measure_recovery(
            experiment.target_services,
            experiment.failure_scenarios,
            experiment.start_time,
            experiment.end_time or datetime.now()
        )
    
    async def _analyze_breaking_points(self, experiment: ChaosExperiment) -> Dict[str, Any]:
        """Analyze system breaking points and limits"""
        return await self.breaking_point_analyzer.analyze_breaking_points(
            experiment.target_services,
            experiment.failure_scenarios
        )
    
    async def _calculate_resilience_score(self, metrics: ChaosMetrics) -> float:
        """Calculate overall resilience score"""
        # Weighted score based on multiple factors
        mttd_score = max(0, 1 - (metrics.mttd_seconds / 300))  # Normalize to 5 minutes
        mttr_score = max(0, 1 - (metrics.mttr_seconds / 600))  # Normalize to 10 minutes
        availability_score = max(0, 1 - metrics.availability_impact)
        recovery_score = metrics.recovery_effectiveness
        
        # Weighted average
        resilience_score = (
            mttd_score * 0.25 +
            mttr_score * 0.35 +
            availability_score * 0.25 +
            recovery_score * 0.15
        )
        
        return min(1.0, max(0.0, resilience_score))
    
    # Utility methods
    async def _check_system_health(self, experiment: ChaosExperiment) -> Dict[str, Any]:
        """Check overall system health"""
        # Implementation would check various health indicators
        return {"healthy": True, "issues": []}
    
    async def _update_real_time_metrics(self, experiment: ChaosExperiment):
        """Update real-time experiment metrics"""
        # Implementation would update metrics in real-time
        pass
    
    async def _get_current_metrics(self, experiment: ChaosExperiment) -> Dict[str, Any]:
        """Get current experiment metrics"""
        # Implementation would return current metrics
        return {"failure_rate": 0.0}
    
    async def _post_experiment_cleanup(self, experiment: ChaosExperiment):
        """Clean up after experiment completion"""
        # Ensure all injected failures are cleaned up
        await self.failure_injector.cleanup_all_failures(experiment.id)
        
        # Validate system recovery
        recovery_status = await self.resilience_validator.validate_full_recovery(experiment.target_services)
        if not recovery_status["recovered"]:
            logger.warning(f"System not fully recovered after experiment {experiment.id}")
    
    async def _emergency_cleanup(self, experiment: ChaosExperiment):
        """Emergency cleanup and recovery procedures"""
        logger.warning(f"Performing emergency cleanup for experiment {experiment.id}")
        
        # Force cleanup all failures
        await self.failure_injector.emergency_cleanup(experiment.id)
        
        # Trigger emergency recovery procedures
        await self.safety_controller.emergency_recovery(experiment)
    
    def _get_experiment_type_distribution(self) -> Dict[str, int]:
        """Get distribution of experiments by type"""
        distribution = {}
        for experiment in self.experiment_history:
            exp_type = experiment.experiment_type.value
            distribution[exp_type] = distribution.get(exp_type, 0) + 1
        return distribution
    
    def add_emergency_stop_trigger(self, trigger: Callable):
        """Add custom emergency stop trigger"""
        self.emergency_stop_triggers.append(trigger)
    
    def add_health_monitor(self, name: str, monitor: Callable):
        """Add custom health monitor"""
        self.health_monitors[name] = monitor