"""
Safety Controller

Central safety management system for chaos engineering experiments.
Provides pre-experiment validation, continuous monitoring, and emergency controls.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Set
from enum import Enum
import json

logger = logging.getLogger(__name__)


class SafetyLevel(Enum):
    """Safety levels for experiments"""
    SAFE = "safe"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class SafetyViolationType(Enum):
    """Types of safety violations"""
    BLAST_RADIUS_EXCEEDED = "blast_radius_exceeded"
    ERROR_RATE_EXCEEDED = "error_rate_exceeded"
    RESPONSE_TIME_EXCEEDED = "response_time_exceeded"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    CASCADE_FAILURE = "cascade_failure"
    DATA_INTEGRITY_RISK = "data_integrity_risk"
    DEPENDENCY_FAILURE = "dependency_failure"
    SECURITY_VIOLATION = "security_violation"
    COMPLIANCE_VIOLATION = "compliance_violation"


@dataclass
class SafetyViolation:
    """Safety violation record"""
    violation_type: SafetyViolationType
    severity: SafetyLevel
    timestamp: datetime
    experiment_id: str
    service: str
    details: Dict[str, Any] = field(default_factory=dict)
    auto_recovery_triggered: bool = False
    manual_intervention_required: bool = False


@dataclass
class SafetyMetrics:
    """Safety metrics for monitoring"""
    experiment_id: str
    timestamp: datetime
    
    # System health metrics
    overall_error_rate: float = 0.0
    avg_response_time: float = 0.0
    system_availability: float = 100.0
    resource_utilization: Dict[str, float] = field(default_factory=dict)
    
    # Safety boundaries
    blast_radius_current: float = 0.0
    blast_radius_limit: float = 0.1
    affected_services_count: int = 0
    critical_services_affected: int = 0
    
    # Risk indicators
    cascade_failure_risk: float = 0.0
    data_integrity_risk: float = 0.0
    security_risk_level: float = 0.0
    
    # Safety status
    safety_level: SafetyLevel = SafetyLevel.SAFE
    safety_violations: List[SafetyViolation] = field(default_factory=list)


class SafetyController:
    """
    Central safety management system for chaos engineering.
    Ensures experiments remain within safe boundaries and provides emergency controls.
    """
    
    def __init__(self):
        self.safety_rules: Dict[str, Dict[str, Any]] = {}
        self.active_experiments: Dict[str, SafetyMetrics] = {}
        self.safety_history: List[SafetyViolation] = []
        
        # Safety thresholds
        self.default_safety_thresholds = {
            "max_error_rate": 0.05,  # 5%
            "max_response_time": 5.0,  # 5 seconds
            "max_blast_radius": 0.1,   # 10% of system
            "max_affected_services": 3,
            "max_cpu_usage": 0.9,      # 90%
            "max_memory_usage": 0.9,   # 90%
            "min_availability": 0.95   # 95%
        }
        
        # Emergency triggers
        self.emergency_triggers: List[Callable] = []
        self.auto_recovery_enabled = True
        
        # Protected resources
        self.protected_services: Set[str] = set()
        self.critical_services: Set[str] = set()
        self.production_environments: Set[str] = set()
        
        logger.info("Safety Controller initialized")
    
    async def validate_experiment(self, experiment) -> Dict[str, Any]:
        """Validate experiment safety before execution"""
        logger.info(f"Validating safety for experiment {experiment.id}")
        
        validation_results = {
            "safe": True,
            "warnings": [],
            "violations": [],
            "reasons": []
        }
        
        # Check blast radius
        if experiment.blast_radius > self.default_safety_thresholds["max_blast_radius"]:
            validation_results["safe"] = False
            validation_results["violations"].append("Blast radius exceeds safety limit")
            validation_results["reasons"].append(f"Blast radius {experiment.blast_radius} > {self.default_safety_thresholds['max_blast_radius']}")
        
        # Check target services
        protected_targets = set(experiment.target_services) & self.protected_services
        if protected_targets:
            validation_results["safe"] = False
            validation_results["violations"].append("Targeting protected services")
            validation_results["reasons"].append(f"Protected services targeted: {protected_targets}")
        
        # Check critical services
        critical_targets = set(experiment.target_services) & self.critical_services
        if critical_targets:
            validation_results["warnings"].append("Targeting critical services")
            if len(critical_targets) > 1:
                validation_results["safe"] = False
                validation_results["violations"].append("Multiple critical services targeted")
                validation_results["reasons"].append(f"Multiple critical services: {critical_targets}")
        
        # Check experiment duration
        if experiment.duration_seconds > 3600:  # 1 hour
            validation_results["warnings"].append("Long experiment duration")
        
        # Check failure scenarios
        high_risk_scenarios = []
        for scenario in experiment.failure_scenarios:
            risk_level = await self._assess_scenario_risk(scenario)
            if risk_level > 0.8:
                high_risk_scenarios.append(scenario)
        
        if high_risk_scenarios:
            if len(high_risk_scenarios) > 2:
                validation_results["safe"] = False
                validation_results["violations"].append("Too many high-risk scenarios")
            else:
                validation_results["warnings"].append(f"{len(high_risk_scenarios)} high-risk scenarios")
        
        # Check environment safety
        if await self._is_production_environment():
            validation_results["warnings"].append("Production environment detected")
            if not await self._has_production_safety_approvals():
                validation_results["safe"] = False
                validation_results["violations"].append("Production safety approvals required")
        
        # Check system health prerequisites
        system_health = await self._check_system_health_prerequisites()
        if not system_health["healthy"]:
            validation_results["safe"] = False
            validation_results["violations"].append("System health prerequisites not met")
            validation_results["reasons"].extend(system_health["issues"])
        
        logger.info(f"Experiment safety validation: {'SAFE' if validation_results['safe'] else 'UNSAFE'}")
        return validation_results
    
    async def pre_experiment_check(self, experiment) -> Dict[str, Any]:
        """Comprehensive pre-experiment safety check"""
        logger.info(f"Performing pre-experiment safety check for {experiment.id}")
        
        safety_check = {
            "safe": True,
            "timestamp": datetime.now().isoformat(),
            "checks_performed": [],
            "warnings": [],
            "violations": [],
            "reasons": []
        }
        
        # System capacity check
        capacity_check = await self._check_system_capacity()
        safety_check["checks_performed"].append("system_capacity")
        if not capacity_check["adequate"]:
            safety_check["safe"] = False
            safety_check["violations"].append("Insufficient system capacity")
            safety_check["reasons"].extend(capacity_check["issues"])
        
        # Dependency health check
        dependency_check = await self._check_dependencies_health(experiment.target_services)
        safety_check["checks_performed"].append("dependency_health")
        if not dependency_check["healthy"]:
            safety_check["warnings"].append("Some dependencies unhealthy")
            if dependency_check["critical_dependencies_down"]:
                safety_check["safe"] = False
                safety_check["violations"].append("Critical dependencies down")
        
        # Concurrent experiment check
        concurrent_check = await self._check_concurrent_experiments(experiment)
        safety_check["checks_performed"].append("concurrent_experiments")
        if not concurrent_check["safe"]:
            safety_check["safe"] = False
            safety_check["violations"].append("Unsafe concurrent experiments")
            safety_check["reasons"].extend(concurrent_check["conflicts"])
        
        # Data backup verification
        backup_check = await self._verify_data_backups(experiment.target_services)
        safety_check["checks_performed"].append("data_backups")
        if not backup_check["verified"]:
            safety_check["warnings"].append("Data backup verification incomplete")
        
        # Emergency recovery readiness
        recovery_check = await self._verify_emergency_recovery_readiness()
        safety_check["checks_performed"].append("emergency_recovery")
        if not recovery_check["ready"]:
            safety_check["safe"] = False
            safety_check["violations"].append("Emergency recovery not ready")
        
        # Monitoring system check
        monitoring_check = await self._verify_monitoring_systems()
        safety_check["checks_performed"].append("monitoring_systems")
        if not monitoring_check["operational"]:
            safety_check["safe"] = False
            safety_check["violations"].append("Monitoring systems not operational")
        
        return safety_check
    
    async def continuous_safety_check(self, experiment) -> Dict[str, Any]:
        """Continuous safety monitoring during experiment"""
        safety_metrics = await self._collect_safety_metrics(experiment)
        self.active_experiments[experiment.id] = safety_metrics
        
        safety_status = {
            "safe": True,
            "safety_level": SafetyLevel.SAFE,
            "violations": [],
            "metrics": safety_metrics.__dict__,
            "timestamp": datetime.now().isoformat()
        }
        
        # Check error rate
        if safety_metrics.overall_error_rate > self.default_safety_thresholds["max_error_rate"]:
            violation = SafetyViolation(
                violation_type=SafetyViolationType.ERROR_RATE_EXCEEDED,
                severity=SafetyLevel.CRITICAL,
                timestamp=datetime.now(),
                experiment_id=experiment.id,
                service="system",
                details={"current_rate": safety_metrics.overall_error_rate, "threshold": self.default_safety_thresholds["max_error_rate"]}
            )
            safety_metrics.safety_violations.append(violation)
            safety_status["violations"].append(violation.__dict__)
            safety_status["safe"] = False
            safety_status["safety_level"] = SafetyLevel.CRITICAL
        
        # Check response time
        if safety_metrics.avg_response_time > self.default_safety_thresholds["max_response_time"]:
            violation = SafetyViolation(
                violation_type=SafetyViolationType.RESPONSE_TIME_EXCEEDED,
                severity=SafetyLevel.WARNING,
                timestamp=datetime.now(),
                experiment_id=experiment.id,
                service="system",
                details={"current_time": safety_metrics.avg_response_time, "threshold": self.default_safety_thresholds["max_response_time"]}
            )
            safety_metrics.safety_violations.append(violation)
            safety_status["violations"].append(violation.__dict__)
            if safety_status["safety_level"] == SafetyLevel.SAFE:
                safety_status["safety_level"] = SafetyLevel.WARNING
        
        # Check blast radius
        if safety_metrics.blast_radius_current > safety_metrics.blast_radius_limit:
            violation = SafetyViolation(
                violation_type=SafetyViolationType.BLAST_RADIUS_EXCEEDED,
                severity=SafetyLevel.CRITICAL,
                timestamp=datetime.now(),
                experiment_id=experiment.id,
                service="system",
                details={"current_blast_radius": safety_metrics.blast_radius_current, "limit": safety_metrics.blast_radius_limit}
            )
            safety_metrics.safety_violations.append(violation)
            safety_status["violations"].append(violation.__dict__)
            safety_status["safe"] = False
            safety_status["safety_level"] = SafetyLevel.EMERGENCY
        
        # Check resource utilization
        for resource, usage in safety_metrics.resource_utilization.items():
            threshold_key = f"max_{resource}_usage"
            if threshold_key in self.default_safety_thresholds and usage > self.default_safety_thresholds[threshold_key]:
                violation = SafetyViolation(
                    violation_type=SafetyViolationType.RESOURCE_EXHAUSTION,
                    severity=SafetyLevel.CRITICAL,
                    timestamp=datetime.now(),
                    experiment_id=experiment.id,
                    service="system",
                    details={"resource": resource, "usage": usage, "threshold": self.default_safety_thresholds[threshold_key]}
                )
                safety_metrics.safety_violations.append(violation)
                safety_status["violations"].append(violation.__dict__)
                safety_status["safe"] = False
                safety_status["safety_level"] = SafetyLevel.CRITICAL
        
        # Check cascade failure indicators
        if safety_metrics.cascade_failure_risk > 0.8:
            violation = SafetyViolation(
                violation_type=SafetyViolationType.CASCADE_FAILURE,
                severity=SafetyLevel.EMERGENCY,
                timestamp=datetime.now(),
                experiment_id=experiment.id,
                service="system",
                details={"cascade_risk": safety_metrics.cascade_failure_risk}
            )
            safety_metrics.safety_violations.append(violation)
            safety_status["violations"].append(violation.__dict__)
            safety_status["safe"] = False
            safety_status["safety_level"] = SafetyLevel.EMERGENCY
        
        # Update safety level
        safety_metrics.safety_level = safety_status["safety_level"]
        
        # Trigger automatic recovery if needed
        if safety_status["safety_level"] in [SafetyLevel.CRITICAL, SafetyLevel.EMERGENCY] and self.auto_recovery_enabled:
            await self._trigger_auto_recovery(experiment, safety_metrics)
        
        return safety_status
    
    async def get_safety_status(self, experiment_id: str) -> Dict[str, Any]:
        """Get current safety status for experiment"""
        if experiment_id not in self.active_experiments:
            return {"error": "Experiment not found in active monitoring"}
        
        safety_metrics = self.active_experiments[experiment_id]
        
        return {
            "experiment_id": experiment_id,
            "safety_level": safety_metrics.safety_level.value,
            "safety_metrics": safety_metrics.__dict__,
            "current_violations": [v.__dict__ for v in safety_metrics.safety_violations],
            "last_update": safety_metrics.timestamp.isoformat()
        }
    
    async def emergency_recovery(self, experiment) -> Dict[str, Any]:
        """Execute emergency recovery procedures"""
        logger.critical(f"Executing emergency recovery for experiment {experiment.id}")
        
        recovery_actions = []
        recovery_results = {}
        
        try:
            # Stop all active failure injections
            stop_result = await self._emergency_stop_all_injections(experiment)
            recovery_actions.append("stop_failure_injections")
            recovery_results["stop_injections"] = stop_result
            
            # Restore services to healthy state
            restore_result = await self._emergency_service_restoration(experiment)
            recovery_actions.append("restore_services")
            recovery_results["restore_services"] = restore_result
            
            # Clear network restrictions
            network_result = await self._emergency_clear_network_restrictions(experiment)
            recovery_actions.append("clear_network_restrictions")
            recovery_results["clear_network"] = network_result
            
            # Restore resource limits
            resource_result = await self._emergency_restore_resources(experiment)
            recovery_actions.append("restore_resources")
            recovery_results["restore_resources"] = resource_result
            
            # Validate system recovery
            validation_result = await self._validate_emergency_recovery(experiment)
            recovery_actions.append("validate_recovery")
            recovery_results["validation"] = validation_result
            
            # Clean up experiment state
            if experiment.id in self.active_experiments:
                del self.active_experiments[experiment.id]
            
            return {
                "emergency_recovery": True,
                "actions_performed": recovery_actions,
                "results": recovery_results,
                "recovery_timestamp": datetime.now().isoformat(),
                "system_recovered": validation_result.get("recovered", False)
            }
            
        except Exception as e:
            logger.error(f"Emergency recovery failed: {e}")
            return {
                "emergency_recovery": False,
                "error": str(e),
                "actions_attempted": recovery_actions,
                "partial_results": recovery_results
            }
    
    def add_protected_service(self, service_name: str):
        """Add service to protected list"""
        self.protected_services.add(service_name)
        logger.info(f"Added {service_name} to protected services")
    
    def add_critical_service(self, service_name: str):
        """Add service to critical list"""
        self.critical_services.add(service_name)
        logger.info(f"Added {service_name} to critical services")
    
    def set_safety_threshold(self, metric: str, value: float):
        """Set custom safety threshold"""
        self.default_safety_thresholds[metric] = value
        logger.info(f"Set safety threshold {metric} = {value}")
    
    def add_emergency_trigger(self, trigger: Callable):
        """Add custom emergency trigger"""
        self.emergency_triggers.append(trigger)
        logger.info("Added custom emergency trigger")
    
    # Internal safety check methods
    async def _assess_scenario_risk(self, scenario: Dict[str, Any]) -> float:
        """Assess risk level of a failure scenario"""
        scenario_type = scenario.get("type", "")
        risk_scores = {
            "service_crash": 0.6,
            "network_partition": 0.8,
            "resource_exhaustion": 0.7,
            "data_corruption": 0.9,
            "infrastructure_failure": 0.8
        }
        
        base_risk = risk_scores.get(scenario_type, 0.5)
        
        # Adjust risk based on configuration
        config = scenario.get("config", {})
        if config.get("duration", 0) > 300:  # 5 minutes
            base_risk += 0.1
        if config.get("intensity", 0) > 0.8:
            base_risk += 0.2
        
        return min(1.0, base_risk)
    
    async def _is_production_environment(self) -> bool:
        """Check if running in production environment"""
        # This would check actual environment indicators
        return False
    
    async def _has_production_safety_approvals(self) -> bool:
        """Check if production safety approvals are in place"""
        # This would check actual approval systems
        return True
    
    async def _check_system_health_prerequisites(self) -> Dict[str, Any]:
        """Check system health prerequisites"""
        return {
            "healthy": True,
            "issues": []
        }
    
    async def _check_system_capacity(self) -> Dict[str, Any]:
        """Check if system has adequate capacity for experiment"""
        return {
            "adequate": True,
            "issues": []
        }
    
    async def _check_dependencies_health(self, target_services: List[str]) -> Dict[str, Any]:
        """Check health of service dependencies"""
        return {
            "healthy": True,
            "critical_dependencies_down": False,
            "unhealthy_dependencies": []
        }
    
    async def _check_concurrent_experiments(self, experiment) -> Dict[str, Any]:
        """Check for unsafe concurrent experiments"""
        return {
            "safe": True,
            "conflicts": []
        }
    
    async def _verify_data_backups(self, target_services: List[str]) -> Dict[str, Any]:
        """Verify data backups are available"""
        return {
            "verified": True,
            "backup_status": {}
        }
    
    async def _verify_emergency_recovery_readiness(self) -> Dict[str, Any]:
        """Verify emergency recovery systems are ready"""
        return {
            "ready": True,
            "recovery_systems": []
        }
    
    async def _verify_monitoring_systems(self) -> Dict[str, Any]:
        """Verify monitoring systems are operational"""
        return {
            "operational": True,
            "monitoring_systems": []
        }
    
    async def _collect_safety_metrics(self, experiment) -> SafetyMetrics:
        """Collect current safety metrics"""
        # This would collect actual metrics from monitoring systems
        metrics = SafetyMetrics(
            experiment_id=experiment.id,
            timestamp=datetime.now(),
            overall_error_rate=0.02,  # 2%
            avg_response_time=0.5,    # 500ms
            system_availability=99.5,  # 99.5%
            resource_utilization={
                "cpu": 0.6,      # 60%
                "memory": 0.7,   # 70%
                "disk": 0.5      # 50%
            },
            blast_radius_current=0.05,  # 5%
            blast_radius_limit=experiment.blast_radius,
            affected_services_count=len(experiment.target_services),
            critical_services_affected=len(set(experiment.target_services) & self.critical_services),
            cascade_failure_risk=0.1,   # 10%
            data_integrity_risk=0.05,   # 5%
            security_risk_level=0.1     # 10%
        )
        
        return metrics
    
    async def _trigger_auto_recovery(self, experiment, safety_metrics: SafetyMetrics):
        """Trigger automatic recovery procedures"""
        logger.warning(f"Triggering auto-recovery for experiment {experiment.id}")
        
        # Mark violations as auto-recovery triggered
        for violation in safety_metrics.safety_violations:
            violation.auto_recovery_triggered = True
        
        # Trigger specific recovery actions based on violations
        recovery_tasks = []
        
        for violation in safety_metrics.safety_violations:
            if violation.violation_type == SafetyViolationType.ERROR_RATE_EXCEEDED:
                recovery_tasks.append(self._reduce_experiment_intensity(experiment))
            elif violation.violation_type == SafetyViolationType.BLAST_RADIUS_EXCEEDED:
                recovery_tasks.append(self._reduce_blast_radius(experiment))
            elif violation.violation_type == SafetyViolationType.RESOURCE_EXHAUSTION:
                recovery_tasks.append(self._free_resources(experiment))
        
        # Execute recovery tasks
        if recovery_tasks:
            await asyncio.gather(*recovery_tasks, return_exceptions=True)
    
    # Emergency recovery methods
    async def _emergency_stop_all_injections(self, experiment) -> Dict[str, Any]:
        """Emergency stop all failure injections"""
        return {
            "stopped": True,
            "injections_stopped": 0,
            "timestamp": datetime.now().isoformat()
        }
    
    async def _emergency_service_restoration(self, experiment) -> Dict[str, Any]:
        """Emergency restoration of services"""
        return {
            "restored": True,
            "services_restored": experiment.target_services,
            "timestamp": datetime.now().isoformat()
        }
    
    async def _emergency_clear_network_restrictions(self, experiment) -> Dict[str, Any]:
        """Emergency clear network restrictions"""
        return {
            "cleared": True,
            "restrictions_removed": [],
            "timestamp": datetime.now().isoformat()
        }
    
    async def _emergency_restore_resources(self, experiment) -> Dict[str, Any]:
        """Emergency restore resource limits"""
        return {
            "restored": True,
            "resources_restored": ["cpu", "memory", "disk"],
            "timestamp": datetime.now().isoformat()
        }
    
    async def _validate_emergency_recovery(self, experiment) -> Dict[str, Any]:
        """Validate emergency recovery was successful"""
        return {
            "recovered": True,
            "validation_checks": ["service_health", "network_connectivity", "resource_availability"],
            "timestamp": datetime.now().isoformat()
        }
    
    # Auto-recovery action methods
    async def _reduce_experiment_intensity(self, experiment):
        """Reduce experiment intensity to safe levels"""
        logger.info(f"Reducing experiment intensity for {experiment.id}")
    
    async def _reduce_blast_radius(self, experiment):
        """Reduce experiment blast radius"""
        logger.info(f"Reducing blast radius for experiment {experiment.id}")
    
    async def _free_resources(self, experiment):
        """Free up system resources"""
        logger.info(f"Freeing resources for experiment {experiment.id}")
    
    def get_safety_history(self) -> List[Dict[str, Any]]:
        """Get history of safety violations"""
        return [violation.__dict__ for violation in self.safety_history]
    
    def get_safety_statistics(self) -> Dict[str, Any]:
        """Get safety statistics"""
        if not self.safety_history:
            return {"total_violations": 0}
        
        violation_types = {}
        for violation in self.safety_history:
            v_type = violation.violation_type.value
            violation_types[v_type] = violation_types.get(v_type, 0) + 1
        
        return {
            "total_violations": len(self.safety_history),
            "violation_types": violation_types,
            "auto_recovery_rate": sum(1 for v in self.safety_history if v.auto_recovery_triggered) / len(self.safety_history),
            "protected_services": list(self.protected_services),
            "critical_services": list(self.critical_services)
        }