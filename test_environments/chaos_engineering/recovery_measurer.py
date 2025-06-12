"""
Recovery Measurer

Measures recovery time, effectiveness, and patterns during chaos experiments.
Provides detailed analysis of recovery mechanisms and their performance.
"""

import asyncio
import logging
import time
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
import json

logger = logging.getLogger(__name__)


class RecoveryPhase(Enum):
    """Phases of recovery process"""
    DETECTION = "detection"
    RESPONSE = "response"
    STABILIZATION = "stabilization"
    VALIDATION = "validation"
    COMPLETION = "completion"


@dataclass
class RecoveryEvent:
    """Individual recovery event"""
    timestamp: datetime
    phase: RecoveryPhase
    event_type: str
    details: Dict[str, Any] = field(default_factory=dict)
    service: str = ""
    duration_ms: float = 0.0


@dataclass
class RecoveryMeasurement:
    """Comprehensive recovery measurement results"""
    service_name: str
    failure_start: datetime
    recovery_start: Optional[datetime] = None
    recovery_end: Optional[datetime] = None
    
    # Timing metrics
    detection_time_seconds: float = 0.0
    response_time_seconds: float = 0.0
    stabilization_time_seconds: float = 0.0
    total_recovery_time_seconds: float = 0.0
    
    # Effectiveness metrics
    recovery_success_rate: float = 0.0
    functionality_restoration: float = 0.0
    performance_restoration: float = 0.0
    data_integrity_maintained: bool = True
    
    # Recovery events
    recovery_events: List[RecoveryEvent] = field(default_factory=list)
    recovery_phases: Dict[str, float] = field(default_factory=dict)
    
    # Recovery mechanisms used
    mechanisms_triggered: List[str] = field(default_factory=list)
    automatic_recovery: bool = False
    manual_intervention: bool = False
    
    # Quality metrics
    recovery_effectiveness: float = 0.0
    recovery_quality_score: float = 0.0
    mean_time_to_recovery: float = 0.0


class RecoveryMeasurer:
    """
    Measures recovery time, effectiveness, and patterns during chaos experiments.
    Provides comprehensive analysis of system recovery capabilities.
    """
    
    def __init__(self):
        self.active_measurements: Dict[str, RecoveryMeasurement] = {}
        self.recovery_history: List[RecoveryMeasurement] = []
        
        # Measurement configuration
        self.sampling_interval = 1.0  # seconds
        self.recovery_timeout = 600  # 10 minutes maximum
        self.stability_threshold = 30  # seconds of stability required
        
        # Baseline metrics for comparison
        self.baseline_metrics: Dict[str, Dict[str, Any]] = {}
        
        logger.info("Recovery Measurer initialized")
    
    async def measure_recovery(self, services: List[str], failure_scenarios: List[Dict[str, Any]],
                             failure_start: datetime, measurement_end: datetime) -> Dict[str, Any]:
        """Measure recovery across multiple services and scenarios"""
        logger.info(f"Measuring recovery for {len(services)} services")
        
        # Start recovery measurements for all services
        measurement_tasks = []
        for service in services:
            task = asyncio.create_task(
                self._measure_service_recovery(service, failure_start, measurement_end)
            )
            measurement_tasks.append(task)
        
        # Wait for all measurements to complete
        recovery_results = await asyncio.gather(*measurement_tasks, return_exceptions=True)
        
        # Process results
        service_recovery_metrics = {}
        for i, service in enumerate(services):
            if isinstance(recovery_results[i], Exception):
                logger.error(f"Recovery measurement failed for {service}: {recovery_results[i]}")
                service_recovery_metrics[service] = None
            else:
                service_recovery_metrics[service] = recovery_results[i]
        
        # Calculate aggregate recovery metrics
        aggregate_metrics = self._calculate_aggregate_recovery_metrics(service_recovery_metrics)
        
        # Analyze recovery patterns
        recovery_patterns = self._analyze_recovery_patterns(service_recovery_metrics)
        
        return {
            "measurement_period": {
                "failure_start": failure_start.isoformat(),
                "measurement_end": measurement_end.isoformat(),
                "duration_seconds": (measurement_end - failure_start).total_seconds()
            },
            "service_recovery_metrics": {
                service: metrics.__dict__ if metrics else None
                for service, metrics in service_recovery_metrics.items()
            },
            "aggregate_metrics": aggregate_metrics,
            "recovery_patterns": recovery_patterns,
            "mttr_seconds": aggregate_metrics.get("mean_recovery_time", 0.0),
            "effectiveness": aggregate_metrics.get("overall_effectiveness", 0.0)
        }
    
    async def measure_recovery_time_distribution(self, service: str, failure_type: str,
                                               num_samples: int = 10) -> Dict[str, Any]:
        """Measure recovery time distribution across multiple failure injections"""
        logger.info(f"Measuring recovery time distribution for {service} with {num_samples} samples")
        
        recovery_times = []
        effectiveness_scores = []
        
        for sample_num in range(num_samples):
            try:
                # Inject failure
                failure_start = datetime.now()
                
                # Simulate failure injection
                await self._simulate_failure_injection(service, failure_type)
                
                # Measure recovery
                recovery_measurement = await self._measure_service_recovery(
                    service, failure_start, failure_start + timedelta(minutes=10)
                )
                
                if recovery_measurement and recovery_measurement.total_recovery_time_seconds > 0:
                    recovery_times.append(recovery_measurement.total_recovery_time_seconds)
                    effectiveness_scores.append(recovery_measurement.recovery_effectiveness)
                
                # Allow time between samples
                await asyncio.sleep(30)
                
            except Exception as e:
                logger.error(f"Recovery time sample {sample_num} failed: {e}")
        
        if not recovery_times:
            return {"error": "No successful recovery measurements"}
        
        # Calculate distribution statistics
        distribution_stats = {
            "mean_recovery_time": statistics.mean(recovery_times),
            "median_recovery_time": statistics.median(recovery_times),
            "min_recovery_time": min(recovery_times),
            "max_recovery_time": max(recovery_times),
            "std_dev_recovery_time": statistics.stdev(recovery_times) if len(recovery_times) > 1 else 0,
            "p95_recovery_time": self._calculate_percentile(recovery_times, 95),
            "p99_recovery_time": self._calculate_percentile(recovery_times, 99),
            "mean_effectiveness": statistics.mean(effectiveness_scores),
            "effectiveness_consistency": 1.0 - (statistics.stdev(effectiveness_scores) if len(effectiveness_scores) > 1 else 0)
        }
        
        return {
            "service": service,
            "failure_type": failure_type,
            "sample_count": len(recovery_times),
            "distribution_stats": distribution_stats,
            "raw_recovery_times": recovery_times,
            "effectiveness_scores": effectiveness_scores
        }
    
    async def analyze_recovery_bottlenecks(self, service: str, recovery_measurement: RecoveryMeasurement) -> Dict[str, Any]:
        """Analyze bottlenecks in the recovery process"""
        logger.info(f"Analyzing recovery bottlenecks for {service}")
        
        if not recovery_measurement or not recovery_measurement.recovery_events:
            return {"error": "No recovery events to analyze"}
        
        # Analyze phase durations
        phase_durations = {}
        phase_events = {}
        
        for event in recovery_measurement.recovery_events:
            phase = event.phase.value
            if phase not in phase_durations:
                phase_durations[phase] = []
                phase_events[phase] = []
            
            phase_durations[phase].append(event.duration_ms)
            phase_events[phase].append(event)
        
        # Identify bottlenecks
        bottlenecks = []
        for phase, durations in phase_durations.items():
            if durations:
                avg_duration = statistics.mean(durations)
                max_duration = max(durations)
                
                # Consider a phase a bottleneck if it takes more than 30% of total time
                if avg_duration > recovery_measurement.total_recovery_time_seconds * 0.3 * 1000:
                    bottlenecks.append({
                        "phase": phase,
                        "avg_duration_ms": avg_duration,
                        "max_duration_ms": max_duration,
                        "event_count": len(durations),
                        "bottleneck_severity": min(1.0, avg_duration / (recovery_measurement.total_recovery_time_seconds * 1000))
                    })
        
        # Analyze recovery mechanism effectiveness
        mechanism_analysis = self._analyze_recovery_mechanisms(recovery_measurement)
        
        # Identify improvement opportunities
        improvement_opportunities = self._identify_improvement_opportunities(
            recovery_measurement, bottlenecks, mechanism_analysis
        )
        
        return {
            "service": service,
            "total_recovery_time_seconds": recovery_measurement.total_recovery_time_seconds,
            "phase_analysis": {
                phase: {
                    "avg_duration_ms": statistics.mean(durations),
                    "total_events": len(durations),
                    "percentage_of_total": (statistics.mean(durations) / 1000) / recovery_measurement.total_recovery_time_seconds * 100
                }
                for phase, durations in phase_durations.items()
            },
            "bottlenecks": bottlenecks,
            "mechanism_analysis": mechanism_analysis,
            "improvement_opportunities": improvement_opportunities
        }
    
    async def validate_recovery_consistency(self, service: str, num_trials: int = 5) -> Dict[str, Any]:
        """Validate consistency of recovery across multiple trials"""
        logger.info(f"Validating recovery consistency for {service} across {num_trials} trials")
        
        trial_results = []
        
        for trial in range(num_trials):
            try:
                # Inject failure and measure recovery
                failure_start = datetime.now()
                await self._simulate_failure_injection(service, "service_crash")
                
                recovery_measurement = await self._measure_service_recovery(
                    service, failure_start, failure_start + timedelta(minutes=10)
                )
                
                if recovery_measurement:
                    trial_results.append({
                        "trial": trial + 1,
                        "recovery_time": recovery_measurement.total_recovery_time_seconds,
                        "effectiveness": recovery_measurement.recovery_effectiveness,
                        "mechanisms_used": recovery_measurement.mechanisms_triggered,
                        "automatic_recovery": recovery_measurement.automatic_recovery
                    })
                
                # Wait between trials
                await asyncio.sleep(60)
                
            except Exception as e:
                logger.error(f"Recovery consistency trial {trial + 1} failed: {e}")
        
        if not trial_results:
            return {"error": "No successful trials completed"}
        
        # Analyze consistency
        recovery_times = [r["recovery_time"] for r in trial_results]
        effectiveness_scores = [r["effectiveness"] for r in trial_results]
        
        consistency_metrics = {
            "recovery_time_consistency": {
                "mean": statistics.mean(recovery_times),
                "std_dev": statistics.stdev(recovery_times) if len(recovery_times) > 1 else 0,
                "coefficient_of_variation": (statistics.stdev(recovery_times) / statistics.mean(recovery_times)) if len(recovery_times) > 1 and statistics.mean(recovery_times) > 0 else 0,
                "consistency_score": max(0, 1.0 - (statistics.stdev(recovery_times) / statistics.mean(recovery_times))) if len(recovery_times) > 1 and statistics.mean(recovery_times) > 0 else 1.0
            },
            "effectiveness_consistency": {
                "mean": statistics.mean(effectiveness_scores),
                "std_dev": statistics.stdev(effectiveness_scores) if len(effectiveness_scores) > 1 else 0,
                "consistency_score": max(0, 1.0 - statistics.stdev(effectiveness_scores)) if len(effectiveness_scores) > 1 else 1.0
            },
            "mechanism_consistency": self._analyze_mechanism_consistency(trial_results)
        }
        
        return {
            "service": service,
            "trials_completed": len(trial_results),
            "trial_results": trial_results,
            "consistency_metrics": consistency_metrics,
            "overall_consistency_score": (
                consistency_metrics["recovery_time_consistency"]["consistency_score"] +
                consistency_metrics["effectiveness_consistency"]["consistency_score"]
            ) / 2
        }
    
    # Internal measurement methods
    async def _measure_service_recovery(self, service: str, failure_start: datetime,
                                      measurement_end: datetime) -> Optional[RecoveryMeasurement]:
        """Measure recovery for a single service"""
        measurement = RecoveryMeasurement(
            service_name=service,
            failure_start=failure_start
        )
        
        # Get baseline metrics
        baseline_metrics = await self._get_baseline_metrics(service)
        self.baseline_metrics[service] = baseline_metrics
        
        # Track recovery phases
        current_phase = RecoveryPhase.DETECTION
        phase_start_time = datetime.now()
        
        measurement_start = datetime.now()
        
        while datetime.now() < measurement_end:
            current_time = datetime.now()
            
            # Check service health and metrics
            service_health = await self._check_service_health(service)
            service_metrics = await self._get_current_service_metrics(service)
            
            # Determine current recovery phase
            new_phase = await self._determine_recovery_phase(
                service, service_health, service_metrics, baseline_metrics, current_phase
            )
            
            # If phase changed, record the transition
            if new_phase != current_phase:
                phase_duration = (current_time - phase_start_time).total_seconds() * 1000
                
                # Record phase completion event
                event = RecoveryEvent(
                    timestamp=current_time,
                    phase=current_phase,
                    event_type=f"phase_{current_phase.value}_completed",
                    details={
                        "duration_ms": phase_duration,
                        "next_phase": new_phase.value
                    },
                    service=service,
                    duration_ms=phase_duration
                )
                measurement.recovery_events.append(event)
                measurement.recovery_phases[current_phase.value] = phase_duration / 1000
                
                # Update recovery timing
                if current_phase == RecoveryPhase.DETECTION and measurement.recovery_start is None:
                    measurement.recovery_start = current_time
                    measurement.detection_time_seconds = (current_time - failure_start).total_seconds()
                
                current_phase = new_phase
                phase_start_time = current_time
            
            # Record specific recovery events
            recovery_events = await self._detect_recovery_events(service, service_health, service_metrics)
            measurement.recovery_events.extend(recovery_events)
            
            # Check if recovery is complete
            if current_phase == RecoveryPhase.COMPLETION:
                measurement.recovery_end = current_time
                measurement.total_recovery_time_seconds = (current_time - failure_start).total_seconds()
                break
            
            await asyncio.sleep(self.sampling_interval)
        
        # Calculate final metrics
        if measurement.recovery_end:
            measurement.recovery_effectiveness = await self._calculate_recovery_effectiveness(
                service, baseline_metrics, measurement
            )
            measurement.recovery_quality_score = await self._calculate_recovery_quality_score(measurement)
            measurement.mean_time_to_recovery = measurement.total_recovery_time_seconds
            
            # Analyze recovery mechanisms
            measurement.mechanisms_triggered = await self._identify_recovery_mechanisms(measurement)
            measurement.automatic_recovery = await self._detect_automatic_recovery(measurement)
            measurement.manual_intervention = await self._detect_manual_intervention(measurement)
        
        return measurement
    
    async def _determine_recovery_phase(self, service: str, health: Dict[str, Any], 
                                      metrics: Dict[str, Any], baseline: Dict[str, Any],
                                      current_phase: RecoveryPhase) -> RecoveryPhase:
        """Determine current recovery phase based on service state"""
        
        # Detection phase: Service failure detected
        if current_phase == RecoveryPhase.DETECTION:
            if not health.get("healthy", True):
                return RecoveryPhase.RESPONSE
        
        # Response phase: Recovery mechanisms activated
        elif current_phase == RecoveryPhase.RESPONSE:
            if health.get("healthy", False):
                return RecoveryPhase.STABILIZATION
        
        # Stabilization phase: Service is healthy but may not be fully stable
        elif current_phase == RecoveryPhase.STABILIZATION:
            if await self._is_service_stable(service, metrics, baseline):
                return RecoveryPhase.VALIDATION
        
        # Validation phase: Verify full functionality
        elif current_phase == RecoveryPhase.VALIDATION:
            if await self._is_service_fully_recovered(service, metrics, baseline):
                return RecoveryPhase.COMPLETION
        
        return current_phase
    
    async def _detect_recovery_events(self, service: str, health: Dict[str, Any],
                                    metrics: Dict[str, Any]) -> List[RecoveryEvent]:
        """Detect specific recovery events"""
        events = []
        current_time = datetime.now()
        
        # Service restart detected
        if await self._detect_service_restart(service):
            events.append(RecoveryEvent(
                timestamp=current_time,
                phase=RecoveryPhase.RESPONSE,
                event_type="service_restart",
                details={"restart_method": "automatic"},
                service=service
            ))
        
        # Failover detected
        if await self._detect_failover_activation(service):
            events.append(RecoveryEvent(
                timestamp=current_time,
                phase=RecoveryPhase.RESPONSE,
                event_type="failover_activated",
                details={"failover_target": "secondary_instance"},
                service=service
            ))
        
        # Circuit breaker state change
        circuit_breaker_state = await self._get_circuit_breaker_state(service)
        if circuit_breaker_state in ["half_open", "closed"]:
            events.append(RecoveryEvent(
                timestamp=current_time,
                phase=RecoveryPhase.STABILIZATION,
                event_type="circuit_breaker_state_change",
                details={"new_state": circuit_breaker_state},
                service=service
            ))
        
        return events
    
    async def _calculate_recovery_effectiveness(self, service: str, baseline_metrics: Dict[str, Any],
                                              measurement: RecoveryMeasurement) -> float:
        """Calculate recovery effectiveness score"""
        try:
            current_metrics = await self._get_current_service_metrics(service)
            
            # Compare current metrics to baseline
            response_time_ratio = min(1.0, baseline_metrics.get("response_time", 1.0) / current_metrics.get("response_time", 1.0))
            throughput_ratio = min(1.0, current_metrics.get("throughput", 0) / baseline_metrics.get("throughput", 1.0))
            error_rate_ratio = min(1.0, baseline_metrics.get("error_rate", 0.01) / max(current_metrics.get("error_rate", 0.01), 0.001))
            
            # Factor in recovery time
            time_penalty = max(0, 1.0 - (measurement.total_recovery_time_seconds / 300))  # Penalty after 5 minutes
            
            effectiveness = (response_time_ratio + throughput_ratio + error_rate_ratio + time_penalty) / 4
            return min(1.0, max(0.0, effectiveness))
            
        except Exception as e:
            logger.error(f"Failed to calculate recovery effectiveness: {e}")
            return 0.0
    
    async def _calculate_recovery_quality_score(self, measurement: RecoveryMeasurement) -> float:
        """Calculate overall recovery quality score"""
        quality_factors = {
            "speed": max(0, 1.0 - (measurement.total_recovery_time_seconds / 600)),  # Up to 10 minutes
            "automation": 1.0 if measurement.automatic_recovery else 0.5,
            "data_integrity": 1.0 if measurement.data_integrity_maintained else 0.0,
            "functionality": measurement.functionality_restoration,
            "performance": measurement.performance_restoration
        }
        
        # Weighted average
        weights = {"speed": 0.25, "automation": 0.15, "data_integrity": 0.25, "functionality": 0.2, "performance": 0.15}
        quality_score = sum(quality_factors[factor] * weights[factor] for factor in quality_factors)
        
        return min(1.0, max(0.0, quality_score))
    
    # Helper methods for service state checking
    async def _check_service_health(self, service: str) -> Dict[str, Any]:
        """Check service health status"""
        try:
            # This would perform actual health check
            return {
                "healthy": True,
                "response_time": 0.1,
                "status": "healthy"
            }
        except:
            return {"healthy": False, "error": "Health check failed"}
    
    async def _get_current_service_metrics(self, service: str) -> Dict[str, Any]:
        """Get current service metrics"""
        try:
            # This would get actual service metrics
            return {
                "response_time": 0.1,
                "throughput": 100.0,
                "error_rate": 0.01,
                "cpu_usage": 0.5,
                "memory_usage": 0.6
            }
        except:
            return {}
    
    async def _get_baseline_metrics(self, service: str) -> Dict[str, Any]:
        """Get baseline service metrics"""
        return {
            "response_time": 0.1,
            "throughput": 100.0,
            "error_rate": 0.01,
            "cpu_usage": 0.4,
            "memory_usage": 0.5
        }
    
    async def _is_service_stable(self, service: str, current_metrics: Dict[str, Any],
                               baseline_metrics: Dict[str, Any]) -> bool:
        """Check if service is stable (consistent metrics for stability threshold)"""
        # This would check for stability over time
        return True
    
    async def _is_service_fully_recovered(self, service: str, current_metrics: Dict[str, Any],
                                        baseline_metrics: Dict[str, Any]) -> bool:
        """Check if service has fully recovered to baseline performance"""
        try:
            response_time_ok = current_metrics.get("response_time", 0) <= baseline_metrics.get("response_time", 0) * 1.1
            throughput_ok = current_metrics.get("throughput", 0) >= baseline_metrics.get("throughput", 0) * 0.9
            error_rate_ok = current_metrics.get("error_rate", 1) <= baseline_metrics.get("error_rate", 0) * 1.5
            
            return response_time_ok and throughput_ok and error_rate_ok
        except:
            return False
    
    # Detection methods for recovery events
    async def _detect_service_restart(self, service: str) -> bool:
        """Detect if service has been restarted"""
        return False  # Would check actual restart status
    
    async def _detect_failover_activation(self, service: str) -> bool:
        """Detect if failover has been activated"""
        return False  # Would check actual failover status
    
    async def _get_circuit_breaker_state(self, service: str) -> str:
        """Get circuit breaker state"""
        return "closed"  # Would check actual circuit breaker state
    
    async def _identify_recovery_mechanisms(self, measurement: RecoveryMeasurement) -> List[str]:
        """Identify which recovery mechanisms were triggered"""
        mechanisms = []
        
        for event in measurement.recovery_events:
            if event.event_type == "service_restart":
                mechanisms.append("auto_restart")
            elif event.event_type == "failover_activated":
                mechanisms.append("failover")
            elif event.event_type == "circuit_breaker_state_change":
                mechanisms.append("circuit_breaker")
        
        return list(set(mechanisms))  # Remove duplicates
    
    async def _detect_automatic_recovery(self, measurement: RecoveryMeasurement) -> bool:
        """Detect if recovery was automatic"""
        automatic_events = ["service_restart", "failover_activated", "circuit_breaker_state_change"]
        return any(event.event_type in automatic_events for event in measurement.recovery_events)
    
    async def _detect_manual_intervention(self, measurement: RecoveryMeasurement) -> bool:
        """Detect if manual intervention was required"""
        manual_events = ["manual_restart", "manual_failover", "operator_intervention"]
        return any(event.event_type in manual_events for event in measurement.recovery_events)
    
    # Analysis methods
    def _calculate_aggregate_recovery_metrics(self, service_metrics: Dict[str, Optional[RecoveryMeasurement]]) -> Dict[str, Any]:
        """Calculate aggregate recovery metrics across all services"""
        valid_measurements = [m for m in service_metrics.values() if m is not None]
        
        if not valid_measurements:
            return {
                "mean_recovery_time": 0.0,
                "overall_effectiveness": 0.0,
                "recovery_success_rate": 0.0
            }
        
        recovery_times = [m.total_recovery_time_seconds for m in valid_measurements if m.total_recovery_time_seconds > 0]
        effectiveness_scores = [m.recovery_effectiveness for m in valid_measurements]
        
        return {
            "mean_recovery_time": statistics.mean(recovery_times) if recovery_times else 0.0,
            "median_recovery_time": statistics.median(recovery_times) if recovery_times else 0.0,
            "p95_recovery_time": self._calculate_percentile(recovery_times, 95) if recovery_times else 0.0,
            "overall_effectiveness": statistics.mean(effectiveness_scores) if effectiveness_scores else 0.0,
            "recovery_success_rate": len(recovery_times) / len(valid_measurements),
            "automatic_recovery_rate": sum(1 for m in valid_measurements if m.automatic_recovery) / len(valid_measurements),
            "total_services_measured": len(service_metrics),
            "successful_recoveries": len(recovery_times)
        }
    
    def _analyze_recovery_patterns(self, service_metrics: Dict[str, Optional[RecoveryMeasurement]]) -> Dict[str, Any]:
        """Analyze patterns in recovery across services"""
        valid_measurements = [m for m in service_metrics.values() if m is not None]
        
        if not valid_measurements:
            return {"pattern_analysis": "No valid measurements"}
        
        # Analyze recovery mechanisms
        all_mechanisms = []
        for measurement in valid_measurements:
            all_mechanisms.extend(measurement.mechanisms_triggered)
        
        mechanism_frequency = {}
        for mechanism in all_mechanisms:
            mechanism_frequency[mechanism] = mechanism_frequency.get(mechanism, 0) + 1
        
        # Analyze recovery phases
        phase_patterns = {}
        for measurement in valid_measurements:
            for phase, duration in measurement.recovery_phases.items():
                if phase not in phase_patterns:
                    phase_patterns[phase] = []
                phase_patterns[phase].append(duration)
        
        phase_analysis = {}
        for phase, durations in phase_patterns.items():
            if durations:
                phase_analysis[phase] = {
                    "mean_duration": statistics.mean(durations),
                    "median_duration": statistics.median(durations),
                    "consistency": 1.0 - (statistics.stdev(durations) / statistics.mean(durations)) if len(durations) > 1 and statistics.mean(durations) > 0 else 1.0
                }
        
        return {
            "most_common_mechanisms": sorted(mechanism_frequency.items(), key=lambda x: x[1], reverse=True),
            "phase_analysis": phase_analysis,
            "recovery_consistency": self._calculate_recovery_consistency(valid_measurements),
            "automation_rate": sum(1 for m in valid_measurements if m.automatic_recovery) / len(valid_measurements)
        }
    
    def _analyze_recovery_mechanisms(self, measurement: RecoveryMeasurement) -> Dict[str, Any]:
        """Analyze effectiveness of different recovery mechanisms"""
        mechanism_analysis = {}
        
        for mechanism in measurement.mechanisms_triggered:
            mechanism_events = [
                event for event in measurement.recovery_events
                if mechanism.replace("_", " ") in event.event_type.replace("_", " ")
            ]
            
            if mechanism_events:
                mechanism_analysis[mechanism] = {
                    "activation_count": len(mechanism_events),
                    "first_activation_time": min(event.timestamp for event in mechanism_events),
                    "effectiveness_contribution": len(mechanism_events) / len(measurement.recovery_events)
                }
        
        return mechanism_analysis
    
    def _identify_improvement_opportunities(self, measurement: RecoveryMeasurement,
                                          bottlenecks: List[Dict[str, Any]],
                                          mechanism_analysis: Dict[str, Any]) -> List[str]:
        """Identify opportunities for recovery improvement"""
        opportunities = []
        
        # Long recovery time
        if measurement.total_recovery_time_seconds > 300:  # 5 minutes
            opportunities.append("Optimize recovery speed - current time exceeds 5 minutes")
        
        # Detection delays
        if measurement.detection_time_seconds > 60:  # 1 minute
            opportunities.append("Improve failure detection - detection time exceeds 1 minute")
        
        # Manual intervention required
        if measurement.manual_intervention:
            opportunities.append("Enhance automation - manual intervention was required")
        
        # Phase bottlenecks
        for bottleneck in bottlenecks:
            opportunities.append(f"Optimize {bottleneck['phase']} phase - identified as bottleneck")
        
        # Low effectiveness
        if measurement.recovery_effectiveness < 0.8:
            opportunities.append("Improve recovery effectiveness - current score below 80%")
        
        return opportunities
    
    def _analyze_mechanism_consistency(self, trial_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze consistency of recovery mechanisms across trials"""
        all_mechanisms = []
        for trial in trial_results:
            all_mechanisms.extend(trial.get("mechanisms_used", []))
        
        mechanism_counts = {}
        for mechanism in all_mechanisms:
            mechanism_counts[mechanism] = mechanism_counts.get(mechanism, 0) + 1
        
        total_trials = len(trial_results)
        mechanism_consistency = {}
        
        for mechanism, count in mechanism_counts.items():
            consistency_rate = count / total_trials
            mechanism_consistency[mechanism] = {
                "usage_rate": consistency_rate,
                "total_activations": count,
                "consistency_score": consistency_rate
            }
        
        return mechanism_consistency
    
    def _calculate_recovery_consistency(self, measurements: List[RecoveryMeasurement]) -> float:
        """Calculate overall recovery consistency score"""
        if len(measurements) < 2:
            return 1.0
        
        recovery_times = [m.total_recovery_time_seconds for m in measurements if m.total_recovery_time_seconds > 0]
        effectiveness_scores = [m.recovery_effectiveness for m in measurements]
        
        if not recovery_times or not effectiveness_scores:
            return 0.0
        
        # Consistency based on coefficient of variation
        time_consistency = max(0, 1.0 - (statistics.stdev(recovery_times) / statistics.mean(recovery_times))) if statistics.mean(recovery_times) > 0 else 0
        effectiveness_consistency = max(0, 1.0 - statistics.stdev(effectiveness_scores)) if len(effectiveness_scores) > 1 else 1.0
        
        return (time_consistency + effectiveness_consistency) / 2
    
    def _calculate_percentile(self, values: List[float], percentile: int) -> float:
        """Calculate percentile of values"""
        if not values:
            return 0.0
        
        sorted_values = sorted(values)
        index = (percentile / 100) * (len(sorted_values) - 1)
        
        if index.is_integer():
            return sorted_values[int(index)]
        else:
            lower = sorted_values[int(index)]
            upper = sorted_values[int(index) + 1]
            return lower + (upper - lower) * (index - int(index))
    
    # Simulation methods for testing
    async def _simulate_failure_injection(self, service: str, failure_type: str):
        """Simulate failure injection for testing"""
        logger.info(f"Simulating {failure_type} failure for {service}")
        # This would inject actual failure
        await asyncio.sleep(1)  # Simulate injection time