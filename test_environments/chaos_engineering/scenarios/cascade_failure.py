"""
Cascade Failure Scenario

Tests system resilience against cascading failures where one failure triggers others.
Validates circuit breakers, bulkheads, and failure isolation mechanisms.
"""

import asyncio
import logging
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


class CascadePattern(Enum):
    """Types of cascade failure patterns"""
    LINEAR_CASCADE = "linear_cascade"        # A -> B -> C chain
    TREE_CASCADE = "tree_cascade"           # A -> {B, C} -> {D, E, F}
    NETWORK_CASCADE = "network_cascade"     # Complex interdependency cascade
    DEPENDENCY_CASCADE = "dependency_cascade"  # Upstream dependency failure
    LOAD_REDISTRIBUTION = "load_redistribution"  # Failure causes load redistribution


@dataclass
class CascadeStage:
    """Individual stage in cascade failure"""
    stage_number: int
    trigger_service: str
    affected_services: List[str]
    failure_type: str
    delay_seconds: float = 0.0
    propagation_probability: float = 1.0
    impact_severity: float = 1.0
    containment_mechanisms: List[str] = field(default_factory=list)


@dataclass
class CascadeFailureConfig:
    """Configuration for cascade failure scenario"""
    pattern: CascadePattern
    initial_service: str
    target_services: List[str]
    max_cascade_depth: int = 3
    stage_delay_seconds: float = 30.0
    propagation_probability: float = 0.8
    containment_test: bool = True
    recovery_test: bool = True


class CascadeFailureScenario:
    """
    Cascade failure scenario for testing system resilience against
    failures that propagate through service dependencies.
    """
    
    def __init__(self, failure_injector=None, resilience_validator=None):
        self.failure_injector = failure_injector
        self.resilience_validator = resilience_validator
        
        # Scenario tracking
        self.active_cascades: Dict[str, Dict[str, Any]] = {}
        self.cascade_history: List[Dict[str, Any]] = []
        
        # Service dependency mapping
        self.service_dependencies: Dict[str, List[str]] = {}
        
        logger.info("Cascade Failure Scenario initialized")
    
    async def execute_cascade_failure(self, config: CascadeFailureConfig) -> Dict[str, Any]:
        """Execute cascade failure scenario"""
        logger.info(f"Executing {config.pattern.value} cascade failure from {config.initial_service}")
        
        scenario_id = f"cascade_{int(datetime.now().timestamp())}"
        start_time = datetime.now()
        
        # Plan cascade stages
        cascade_stages = await self._plan_cascade_stages(config)
        
        # Initialize tracking
        cascade_tracking = {
            "scenario_id": scenario_id,
            "config": config.__dict__,
            "stages": [stage.__dict__ for stage in cascade_stages],
            "start_time": start_time,
            "stage_results": [],
            "containment_results": [],
            "recovery_results": []
        }
        
        self.active_cascades[scenario_id] = cascade_tracking
        
        try:
            # Execute cascade stages
            for stage in cascade_stages:
                stage_result = await self._execute_cascade_stage(stage, config)
                cascade_tracking["stage_results"].append(stage_result)
                
                # Check for cascade containment
                if config.containment_test:
                    containment_result = await self._test_cascade_containment(stage, config)
                    cascade_tracking["containment_results"].append(containment_result)
                    
                    # If well-contained, potentially stop cascade
                    if containment_result.get("well_contained", False):
                        logger.info(f"Cascade well-contained at stage {stage.stage_number}")
                        break
                
                # Wait for propagation delay
                if stage.delay_seconds > 0:
                    await asyncio.sleep(stage.delay_seconds)
            
            # Test recovery mechanisms
            if config.recovery_test:
                recovery_result = await self._test_cascade_recovery(cascade_stages, config)
                cascade_tracking["recovery_results"].append(recovery_result)
            
            # Complete cascade tracking
            cascade_tracking["end_time"] = datetime.now()
            cascade_tracking["total_duration"] = (cascade_tracking["end_time"] - start_time).total_seconds()
            
            # Analyze cascade effectiveness
            analysis_result = await self._analyze_cascade_results(cascade_tracking)
            cascade_tracking["analysis"] = analysis_result
            
            # Move to history
            self.cascade_history.append(cascade_tracking)
            del self.active_cascades[scenario_id]
            
            return {
                "scenario_id": scenario_id,
                "success": True,
                "cascade_results": cascade_tracking,
                "containment_effectiveness": analysis_result.get("containment_score", 0.0),
                "recovery_effectiveness": analysis_result.get("recovery_score", 0.0),
                "total_services_affected": len(set().union(*[stage.affected_services for stage in cascade_stages]))
            }
            
        except Exception as e:
            logger.error(f"Cascade failure scenario failed: {e}")
            cascade_tracking["error"] = str(e)
            cascade_tracking["end_time"] = datetime.now()
            
            # Cleanup on failure
            await self._cleanup_cascade_failure(scenario_id)
            
            return {
                "scenario_id": scenario_id,
                "success": False,
                "error": str(e),
                "partial_results": cascade_tracking
            }
    
    async def execute_linear_cascade(self, services: List[str], delay_seconds: float = 30.0) -> Dict[str, Any]:
        """Execute linear cascade failure (A -> B -> C)"""
        config = CascadeFailureConfig(
            pattern=CascadePattern.LINEAR_CASCADE,
            initial_service=services[0],
            target_services=services,
            stage_delay_seconds=delay_seconds
        )
        
        return await self.execute_cascade_failure(config)
    
    async def execute_tree_cascade(self, root_service: str, service_groups: List[List[str]],
                                 delay_seconds: float = 30.0) -> Dict[str, Any]:
        """Execute tree cascade failure (1 -> many -> many more)"""
        all_services = [root_service] + [service for group in service_groups for service in group]
        
        config = CascadeFailureConfig(
            pattern=CascadePattern.TREE_CASCADE,
            initial_service=root_service,
            target_services=all_services,
            stage_delay_seconds=delay_seconds
        )
        
        return await self.execute_cascade_failure(config)
    
    async def execute_dependency_cascade(self, upstream_service: str, downstream_services: List[str],
                                       delay_seconds: float = 30.0) -> Dict[str, Any]:
        """Execute dependency cascade failure (upstream -> downstream)"""
        config = CascadeFailureConfig(
            pattern=CascadePattern.DEPENDENCY_CASCADE,
            initial_service=upstream_service,
            target_services=[upstream_service] + downstream_services,
            stage_delay_seconds=delay_seconds
        )
        
        return await self.execute_cascade_failure(config)
    
    async def test_cascade_containment(self, services: List[str], isolation_mechanisms: List[str]) -> Dict[str, Any]:
        """Test effectiveness of cascade containment mechanisms"""
        logger.info(f"Testing cascade containment for {len(services)} services")
        
        containment_results = {}
        
        for mechanism in isolation_mechanisms:
            try:
                # Enable containment mechanism
                await self._enable_containment_mechanism(mechanism, services)
                
                # Execute controlled cascade
                cascade_result = await self.execute_linear_cascade(services[:3])  # Limit to 3 services
                
                # Measure containment effectiveness
                containment_effectiveness = await self._measure_containment_effectiveness(
                    cascade_result, mechanism, services
                )
                
                containment_results[mechanism] = {
                    "cascade_result": cascade_result,
                    "containment_effectiveness": containment_effectiveness,
                    "services_affected": cascade_result.get("total_services_affected", 0),
                    "containment_score": containment_effectiveness.get("score", 0.0)
                }
                
                # Disable mechanism for next test
                await self._disable_containment_mechanism(mechanism, services)
                
            except Exception as e:
                logger.error(f"Containment test for {mechanism} failed: {e}")
                containment_results[mechanism] = {"error": str(e)}
        
        # Analyze overall containment
        overall_analysis = self._analyze_containment_results(containment_results)
        
        return {
            "containment_mechanisms_tested": isolation_mechanisms,
            "containment_results": containment_results,
            "overall_analysis": overall_analysis,
            "most_effective_mechanism": overall_analysis.get("best_mechanism"),
            "average_containment_score": overall_analysis.get("average_score", 0.0)
        }
    
    async def simulate_load_redistribution_cascade(self, services: List[str], 
                                                 initial_load_multiplier: float = 2.0) -> Dict[str, Any]:
        """Simulate cascade failure due to load redistribution"""
        logger.info(f"Simulating load redistribution cascade for {len(services)} services")
        
        scenario_start = datetime.now()
        redistribution_stages = []
        
        # Start with initial service failure
        initial_service = services[0]
        remaining_services = services[1:]
        
        # Stage 1: Initial service failure
        stage1_result = await self._inject_service_failure(initial_service, "service_crash")
        redistribution_stages.append({
            "stage": 1,
            "action": "initial_failure",
            "service": initial_service,
            "result": stage1_result
        })
        
        # Stage 2: Load redistribution to remaining services
        current_load_multiplier = initial_load_multiplier
        
        for i, service in enumerate(remaining_services):
            # Calculate load increase due to redistribution
            redistributed_load = current_load_multiplier * (1 + i * 0.3)  # Increasing load pressure
            
            # Apply increased load
            load_result = await self._apply_redistributed_load(service, redistributed_load)
            
            # Check if service fails under load
            service_health = await self._check_service_under_load(service, redistributed_load)
            
            stage_result = {
                "stage": i + 2,
                "action": "load_redistribution",
                "service": service,
                "load_multiplier": redistributed_load,
                "load_result": load_result,
                "service_health": service_health,
                "failed": not service_health.get("healthy", True)
            }
            
            redistribution_stages.append(stage_result)
            
            # If service fails, increase load on remaining services
            if stage_result["failed"]:
                current_load_multiplier *= 1.5  # 50% increase for remaining services
                logger.warning(f"Service {service} failed under redistributed load, increasing pressure on remaining services")
            
            # Allow time for load effects
            await asyncio.sleep(15)
        
        # Analyze redistribution cascade
        analysis = await self._analyze_load_redistribution_cascade(redistribution_stages)
        
        return {
            "scenario_type": "load_redistribution_cascade",
            "initial_load_multiplier": initial_load_multiplier,
            "total_stages": len(redistribution_stages),
            "redistribution_stages": redistribution_stages,
            "cascade_analysis": analysis,
            "total_failures": sum(1 for stage in redistribution_stages if stage.get("failed", False)),
            "cascade_stopped": analysis.get("cascade_contained", False),
            "duration_seconds": (datetime.now() - scenario_start).total_seconds()
        }
    
    # Internal cascade planning and execution methods
    async def _plan_cascade_stages(self, config: CascadeFailureConfig) -> List[CascadeStage]:
        """Plan cascade stages based on configuration"""
        stages = []
        
        if config.pattern == CascadePattern.LINEAR_CASCADE:
            stages = self._plan_linear_cascade_stages(config)
        elif config.pattern == CascadePattern.TREE_CASCADE:
            stages = self._plan_tree_cascade_stages(config)
        elif config.pattern == CascadePattern.DEPENDENCY_CASCADE:
            stages = self._plan_dependency_cascade_stages(config)
        elif config.pattern == CascadePattern.NETWORK_CASCADE:
            stages = self._plan_network_cascade_stages(config)
        elif config.pattern == CascadePattern.LOAD_REDISTRIBUTION:
            stages = self._plan_load_redistribution_stages(config)
        
        return stages
    
    def _plan_linear_cascade_stages(self, config: CascadeFailureConfig) -> List[CascadeStage]:
        """Plan linear cascade stages"""
        stages = []
        services = config.target_services
        
        for i, service in enumerate(services[:config.max_cascade_depth]):
            stage = CascadeStage(
                stage_number=i + 1,
                trigger_service=service,
                affected_services=[service],
                failure_type="service_crash",
                delay_seconds=config.stage_delay_seconds if i > 0 else 0,
                propagation_probability=config.propagation_probability,
                containment_mechanisms=["circuit_breaker", "bulkhead"]
            )
            stages.append(stage)
        
        return stages
    
    def _plan_tree_cascade_stages(self, config: CascadeFailureConfig) -> List[CascadeStage]:
        """Plan tree cascade stages"""
        stages = []
        services = config.target_services
        
        # Stage 1: Root failure
        stages.append(CascadeStage(
            stage_number=1,
            trigger_service=config.initial_service,
            affected_services=[config.initial_service],
            failure_type="service_crash",
            delay_seconds=0,
            propagation_probability=1.0
        ))
        
        # Stage 2: First level propagation
        if len(services) > 1:
            first_level = services[1:min(4, len(services))]  # Up to 3 services
            stages.append(CascadeStage(
                stage_number=2,
                trigger_service=config.initial_service,
                affected_services=first_level,
                failure_type="service_slowdown",
                delay_seconds=config.stage_delay_seconds,
                propagation_probability=config.propagation_probability
            ))
        
        # Stage 3: Second level propagation
        if len(services) > 4:
            second_level = services[4:min(8, len(services))]
            stages.append(CascadeStage(
                stage_number=3,
                trigger_service=first_level[0] if first_level else config.initial_service,
                affected_services=second_level,
                failure_type="service_overload",
                delay_seconds=config.stage_delay_seconds,
                propagation_probability=config.propagation_probability * 0.7  # Reduced probability
            ))
        
        return stages
    
    def _plan_dependency_cascade_stages(self, config: CascadeFailureConfig) -> List[CascadeStage]:
        """Plan dependency cascade stages"""
        stages = []
        
        # Stage 1: Upstream service failure
        stages.append(CascadeStage(
            stage_number=1,
            trigger_service=config.initial_service,
            affected_services=[config.initial_service],
            failure_type="service_crash",
            delay_seconds=0,
            propagation_probability=1.0
        ))
        
        # Stage 2: Downstream services affected by dependency failure
        downstream_services = [s for s in config.target_services if s != config.initial_service]
        if downstream_services:
            stages.append(CascadeStage(
                stage_number=2,
                trigger_service=config.initial_service,
                affected_services=downstream_services,
                failure_type="dependency_timeout",
                delay_seconds=config.stage_delay_seconds,
                propagation_probability=config.propagation_probability
            ))
        
        return stages
    
    def _plan_network_cascade_stages(self, config: CascadeFailureConfig) -> List[CascadeStage]:
        """Plan network cascade stages"""
        stages = []
        services = config.target_services
        
        # Random cascade pattern based on network connectivity
        remaining_services = services.copy()
        current_stage = 1
        
        while remaining_services and current_stage <= config.max_cascade_depth:
            # Select random number of services for this stage
            stage_size = min(random.randint(1, 3), len(remaining_services))
            stage_services = random.sample(remaining_services, stage_size)
            
            stages.append(CascadeStage(
                stage_number=current_stage,
                trigger_service=stage_services[0],
                affected_services=stage_services,
                failure_type=random.choice(["service_crash", "network_partition", "service_slowdown"]),
                delay_seconds=config.stage_delay_seconds if current_stage > 1 else 0,
                propagation_probability=config.propagation_probability * (0.9 ** (current_stage - 1))
            ))
            
            # Remove affected services from remaining
            for service in stage_services:
                remaining_services.remove(service)
            
            current_stage += 1
        
        return stages
    
    def _plan_load_redistribution_stages(self, config: CascadeFailureConfig) -> List[CascadeStage]:
        """Plan load redistribution cascade stages"""
        stages = []
        services = config.target_services
        
        # Initial failure creates load redistribution
        for i, service in enumerate(services):
            if i == 0:
                failure_type = "service_crash"  # Initial trigger
                load_impact = 1.0
            else:
                failure_type = "service_overload"  # Load redistribution effect
                load_impact = 1.0 + (i * 0.3)  # Increasing load pressure
            
            stages.append(CascadeStage(
                stage_number=i + 1,
                trigger_service=services[0],  # Original failure triggers all
                affected_services=[service],
                failure_type=failure_type,
                delay_seconds=config.stage_delay_seconds if i > 0 else 0,
                propagation_probability=config.propagation_probability,
                impact_severity=load_impact
            ))
        
        return stages
    
    async def _execute_cascade_stage(self, stage: CascadeStage, config: CascadeFailureConfig) -> Dict[str, Any]:
        """Execute individual cascade stage"""
        logger.info(f"Executing cascade stage {stage.stage_number}: {stage.failure_type} on {stage.affected_services}")
        
        stage_start = datetime.now()
        stage_results = {}
        
        # Check propagation probability
        if random.random() > stage.propagation_probability:
            logger.info(f"Stage {stage.stage_number} did not propagate (probability: {stage.propagation_probability})")
            return {
                "stage_number": stage.stage_number,
                "propagated": False,
                "reason": "probability_check_failed",
                "timestamp": stage_start.isoformat()
            }
        
        # Execute failure injection for each affected service
        for service in stage.affected_services:
            try:
                if self.failure_injector:
                    if stage.failure_type == "service_crash":
                        result = await self.failure_injector.inject_service_failure(
                            service, "service_crash", duration=300
                        )
                    elif stage.failure_type == "service_slowdown":
                        result = await self.failure_injector.inject_service_failure(
                            service, "service_slowdown", duration=300, 
                            parameters={"slowdown_factor": 0.3}
                        )
                    elif stage.failure_type == "service_overload":
                        result = await self.failure_injector.inject_service_failure(
                            service, "service_overload", duration=300,
                            parameters={"requests_per_second": 1000 * stage.impact_severity}
                        )
                    elif stage.failure_type == "dependency_timeout":
                        result = await self.failure_injector.inject_service_failure(
                            service, "api_timeout", duration=300,
                            parameters={"timeout_delay": 30}
                        )
                    else:
                        result = {"simulated": True, "failure_type": stage.failure_type}
                else:
                    # Simulation mode
                    result = {"simulated": True, "failure_type": stage.failure_type}
                
                stage_results[service] = result
                
            except Exception as e:
                logger.error(f"Failed to inject {stage.failure_type} into {service}: {e}")
                stage_results[service] = {"error": str(e)}
        
        # Measure immediate impact
        impact_metrics = await self._measure_stage_impact(stage, config)
        
        return {
            "stage_number": stage.stage_number,
            "propagated": True,
            "affected_services": stage.affected_services,
            "failure_type": stage.failure_type,
            "injection_results": stage_results,
            "impact_metrics": impact_metrics,
            "execution_time": (datetime.now() - stage_start).total_seconds(),
            "timestamp": stage_start.isoformat()
        }
    
    async def _test_cascade_containment(self, stage: CascadeStage, config: CascadeFailureConfig) -> Dict[str, Any]:
        """Test cascade containment mechanisms"""
        containment_results = {}
        
        for mechanism in stage.containment_mechanisms:
            try:
                effectiveness = await self._check_containment_mechanism_effectiveness(
                    mechanism, stage.affected_services
                )
                containment_results[mechanism] = effectiveness
                
            except Exception as e:
                containment_results[mechanism] = {"error": str(e)}
        
        # Determine if cascade is well-contained
        avg_effectiveness = sum(
            r.get("effectiveness", 0) for r in containment_results.values() 
            if isinstance(r, dict) and "effectiveness" in r
        ) / len(containment_results) if containment_results else 0
        
        well_contained = avg_effectiveness > 0.8  # 80% effectiveness threshold
        
        return {
            "stage_number": stage.stage_number,
            "containment_mechanisms": containment_results,
            "average_effectiveness": avg_effectiveness,
            "well_contained": well_contained,
            "containment_score": avg_effectiveness
        }
    
    async def _test_cascade_recovery(self, stages: List[CascadeStage], config: CascadeFailureConfig) -> Dict[str, Any]:
        """Test recovery from cascade failure"""
        logger.info("Testing cascade recovery mechanisms")
        
        recovery_start = datetime.now()
        
        # Collect all affected services
        all_affected_services = set()
        for stage in stages:
            all_affected_services.update(stage.affected_services)
        
        # Test recovery mechanisms
        recovery_results = {}
        
        for service in all_affected_services:
            try:
                if self.resilience_validator:
                    recovery_result = await self.resilience_validator.validate_recovery_mechanisms(
                        service, recovery_start
                    )
                else:
                    # Simulation
                    recovery_result = {
                        "recovered": True,
                        "recovery_time": 120,  # 2 minutes
                        "mechanisms_used": ["auto_restart", "circuit_breaker"]
                    }
                
                recovery_results[service] = recovery_result
                
            except Exception as e:
                recovery_results[service] = {"error": str(e)}
        
        # Calculate overall recovery effectiveness
        successful_recoveries = sum(
            1 for result in recovery_results.values() 
            if isinstance(result, dict) and result.get("recovered", False)
        )
        
        recovery_rate = successful_recoveries / len(all_affected_services) if all_affected_services else 0
        
        return {
            "total_affected_services": len(all_affected_services),
            "recovery_results": recovery_results,
            "successful_recoveries": successful_recoveries,
            "recovery_rate": recovery_rate,
            "recovery_duration": (datetime.now() - recovery_start).total_seconds()
        }
    
    # Analysis and measurement methods
    async def _analyze_cascade_results(self, cascade_tracking: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze cascade failure results"""
        stage_results = cascade_tracking.get("stage_results", [])
        containment_results = cascade_tracking.get("containment_results", [])
        recovery_results = cascade_tracking.get("recovery_results", [])
        
        # Calculate cascade propagation
        total_stages = len(stage_results)
        propagated_stages = sum(1 for stage in stage_results if stage.get("propagated", False))
        propagation_rate = propagated_stages / total_stages if total_stages > 0 else 0
        
        # Calculate containment effectiveness
        containment_scores = [
            result.get("containment_score", 0) for result in containment_results
        ]
        avg_containment_score = sum(containment_scores) / len(containment_scores) if containment_scores else 0
        
        # Calculate recovery effectiveness
        recovery_rates = [
            result.get("recovery_rate", 0) for result in recovery_results
        ]
        avg_recovery_rate = sum(recovery_rates) / len(recovery_rates) if recovery_rates else 0
        
        # Overall resilience score
        resilience_score = (avg_containment_score * 0.6 + avg_recovery_rate * 0.4)
        
        return {
            "total_stages": total_stages,
            "propagated_stages": propagated_stages,
            "propagation_rate": propagation_rate,
            "containment_score": avg_containment_score,
            "recovery_score": avg_recovery_rate,
            "overall_resilience_score": resilience_score,
            "cascade_severity": propagation_rate,  # Higher propagation = higher severity
            "system_resilience": "high" if resilience_score > 0.8 else "medium" if resilience_score > 0.5 else "low"
        }
    
    async def _measure_stage_impact(self, stage: CascadeStage, config: CascadeFailureConfig) -> Dict[str, Any]:
        """Measure impact of cascade stage"""
        impact_metrics = {
            "services_affected": len(stage.affected_services),
            "failure_type": stage.failure_type,
            "impact_severity": stage.impact_severity
        }
        
        # Measure system-wide impact
        if self.resilience_validator:
            try:
                system_metrics = await self.resilience_validator.measure_resilience(
                    stage.affected_services, stage_start_time := datetime.now() - timedelta(seconds=30), datetime.now()
                )
                impact_metrics.update(system_metrics)
            except Exception as e:
                impact_metrics["measurement_error"] = str(e)
        
        return impact_metrics
    
    # Helper methods for load redistribution
    async def _inject_service_failure(self, service: str, failure_type: str) -> Dict[str, Any]:
        """Inject service failure"""
        if self.failure_injector:
            return await self.failure_injector.inject_service_failure(service, failure_type)
        else:
            return {"simulated": True, "service": service, "failure_type": failure_type}
    
    async def _apply_redistributed_load(self, service: str, load_multiplier: float) -> Dict[str, Any]:
        """Apply redistributed load to service"""
        return {
            "service": service,
            "load_multiplier": load_multiplier,
            "load_applied": True,
            "timestamp": datetime.now().isoformat()
        }
    
    async def _check_service_under_load(self, service: str, load_multiplier: float) -> Dict[str, Any]:
        """Check service health under increased load"""
        # Simulate service degradation under load
        failure_threshold = 3.0  # Service fails at 3x load
        degradation_threshold = 2.0  # Service degrades at 2x load
        
        if load_multiplier >= failure_threshold:
            return {"healthy": False, "status": "failed", "load_multiplier": load_multiplier}
        elif load_multiplier >= degradation_threshold:
            return {"healthy": True, "status": "degraded", "load_multiplier": load_multiplier}
        else:
            return {"healthy": True, "status": "normal", "load_multiplier": load_multiplier}
    
    async def _analyze_load_redistribution_cascade(self, stages: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze load redistribution cascade results"""
        total_services = len(stages)
        failed_services = sum(1 for stage in stages if stage.get("failed", False))
        
        # Calculate cascade containment
        if failed_services == 0:
            containment = "complete"
        elif failed_services == 1:
            containment = "excellent"
        elif failed_services <= total_services // 2:
            containment = "good"
        else:
            containment = "poor"
        
        return {
            "total_services": total_services,
            "failed_services": failed_services,
            "failure_rate": failed_services / total_services,
            "containment_level": containment,
            "cascade_contained": failed_services <= 1,
            "load_handling_effectiveness": 1.0 - (failed_services / total_services)
        }
    
    # Containment mechanism methods
    async def _enable_containment_mechanism(self, mechanism: str, services: List[str]):
        """Enable containment mechanism"""
        logger.info(f"Enabling {mechanism} for services: {services}")
    
    async def _disable_containment_mechanism(self, mechanism: str, services: List[str]):
        """Disable containment mechanism"""
        logger.info(f"Disabling {mechanism} for services: {services}")
    
    async def _check_containment_mechanism_effectiveness(self, mechanism: str, services: List[str]) -> Dict[str, Any]:
        """Check effectiveness of containment mechanism"""
        # Simulate effectiveness based on mechanism type
        effectiveness_map = {
            "circuit_breaker": 0.85,
            "bulkhead": 0.75,
            "rate_limiting": 0.65,
            "timeout": 0.70,
            "retry_circuit": 0.80
        }
        
        effectiveness = effectiveness_map.get(mechanism, 0.5)
        
        return {
            "mechanism": mechanism,
            "effectiveness": effectiveness,
            "services_protected": len(services),
            "protection_level": "high" if effectiveness > 0.8 else "medium" if effectiveness > 0.6 else "low"
        }
    
    async def _measure_containment_effectiveness(self, cascade_result: Dict[str, Any], 
                                               mechanism: str, all_services: List[str]) -> Dict[str, Any]:
        """Measure containment effectiveness"""
        total_services = len(all_services)
        affected_services = cascade_result.get("total_services_affected", total_services)
        
        containment_rate = 1.0 - (affected_services / total_services)
        
        return {
            "mechanism": mechanism,
            "total_services": total_services,
            "affected_services": affected_services,
            "containment_rate": containment_rate,
            "score": containment_rate,
            "effectiveness_level": "high" if containment_rate > 0.8 else "medium" if containment_rate > 0.5 else "low"
        }
    
    def _analyze_containment_results(self, containment_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze overall containment results"""
        if not containment_results:
            return {"average_score": 0.0}
        
        valid_results = {k: v for k, v in containment_results.items() if isinstance(v, dict) and "containment_score" in v}
        
        if not valid_results:
            return {"average_score": 0.0}
        
        scores = [result["containment_score"] for result in valid_results.values()]
        average_score = sum(scores) / len(scores)
        
        best_mechanism = max(valid_results.items(), key=lambda x: x[1]["containment_score"])[0]
        
        return {
            "average_score": average_score,
            "best_mechanism": best_mechanism,
            "mechanism_scores": {k: v["containment_score"] for k, v in valid_results.items()},
            "overall_effectiveness": "high" if average_score > 0.8 else "medium" if average_score > 0.5 else "low"
        }
    
    async def _cleanup_cascade_failure(self, scenario_id: str):
        """Cleanup cascade failure scenario"""
        logger.info(f"Cleaning up cascade failure scenario {scenario_id}")
        
        if scenario_id in self.active_cascades:
            del self.active_cascades[scenario_id]
    
    def get_cascade_history(self) -> List[Dict[str, Any]]:
        """Get history of cascade failure scenarios"""
        return self.cascade_history
    
    def get_active_cascades(self) -> Dict[str, Dict[str, Any]]:
        """Get currently active cascade scenarios"""
        return self.active_cascades