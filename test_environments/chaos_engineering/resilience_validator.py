"""
Resilience Validator

Validates system resilience, recovery mechanisms, and fault tolerance during chaos experiments.
Measures detection times, recovery effectiveness, and system stability.
"""

import asyncio
import logging
import time
import requests
import psutil
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import json
import statistics

logger = logging.getLogger(__name__)


@dataclass
class ResilienceMetrics:
    """Resilience measurement results"""
    service_name: str
    measurement_start: datetime
    measurement_end: datetime
    
    # Detection metrics
    failure_detected: bool = False
    detection_time_seconds: float = 0.0
    detection_method: str = ""
    
    # Recovery metrics
    recovery_initiated: bool = False
    recovery_completed: bool = False
    recovery_time_seconds: float = 0.0
    recovery_effectiveness: float = 0.0
    
    # Availability metrics
    uptime_percentage: float = 100.0
    downtime_seconds: float = 0.0
    service_availability: float = 100.0
    
    # Performance metrics
    response_times: List[float] = field(default_factory=list)
    error_rates: List[float] = field(default_factory=list)
    throughput_rps: List[float] = field(default_factory=list)
    
    # Health metrics
    health_check_results: List[Dict[str, Any]] = field(default_factory=list)
    circuit_breaker_trips: int = 0
    graceful_degradation: bool = False


@dataclass
class SystemResilienceProfile:
    """Overall system resilience profile"""
    total_services: int
    healthy_services: int
    degraded_services: int
    failed_services: int
    
    overall_availability: float
    mean_recovery_time: float
    detection_accuracy: float
    
    cascade_failure_contained: bool
    graceful_degradation_active: bool
    circuit_breakers_effective: bool
    
    resilience_score: float


class ResilienceValidator:
    """
    Validates system resilience and recovery mechanisms during chaos experiments.
    Measures fault tolerance, recovery effectiveness, and system stability.
    """
    
    def __init__(self):
        self.monitoring_tasks: Dict[str, asyncio.Task] = {}
        self.metrics_store: Dict[str, ResilienceMetrics] = {}
        
        # Validation configuration
        self.health_check_interval = 5  # seconds
        self.performance_sample_interval = 1  # seconds
        self.detection_timeout = 300  # 5 minutes max detection time
        self.recovery_timeout = 600  # 10 minutes max recovery time
        
        # Thresholds
        self.error_rate_threshold = 0.05  # 5%
        self.response_time_threshold = 5.0  # 5 seconds
        self.availability_threshold = 0.99  # 99%
        
        logger.info("Resilience Validator initialized")
    
    async def measure_resilience(self, services: List[str], start_time: datetime, 
                               end_time: datetime) -> Dict[str, Any]:
        """Measure overall system resilience during chaos experiment"""
        logger.info(f"Measuring resilience for {len(services)} services")
        
        # Start resilience monitoring for all services
        monitoring_tasks = []
        for service in services:
            task = asyncio.create_task(
                self._monitor_service_resilience(service, start_time, end_time)
            )
            monitoring_tasks.append(task)
        
        # Wait for all monitoring to complete
        resilience_results = await asyncio.gather(*monitoring_tasks, return_exceptions=True)
        
        # Aggregate results
        service_metrics = {}
        for i, service in enumerate(services):
            if isinstance(resilience_results[i], Exception):
                logger.error(f"Resilience monitoring failed for {service}: {resilience_results[i]}")
                service_metrics[service] = None
            else:
                service_metrics[service] = resilience_results[i]
        
        # Calculate overall resilience metrics
        overall_metrics = self._calculate_overall_resilience(service_metrics)
        
        return {
            "measurement_period": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat(),
                "duration_seconds": (end_time - start_time).total_seconds()
            },
            "service_metrics": {
                service: metrics.__dict__ if metrics else None 
                for service, metrics in service_metrics.items()
            },
            "overall_resilience": overall_metrics.__dict__,
            "mttd_seconds": overall_metrics.mean_recovery_time,
            "availability_impact": 1.0 - overall_metrics.overall_availability,
            "failure_rate": 1.0 - overall_metrics.detection_accuracy,
            "performance_degradation": self._calculate_performance_degradation(service_metrics)
        }
    
    async def validate_failure_detection(self, service: str, failure_injection_time: datetime,
                                       detection_timeout: int = 300) -> Dict[str, Any]:
        """Validate that failure detection mechanisms work correctly"""
        logger.info(f"Validating failure detection for {service}")
        
        detection_start = datetime.now()
        detection_methods = ["health_checks", "monitoring_alerts", "circuit_breakers", "user_reports"]
        
        detection_results = {}
        
        for method in detection_methods:
            try:
                detected, detection_time = await self._check_detection_method(
                    service, method, failure_injection_time, detection_timeout
                )
                
                detection_results[method] = {
                    "detected": detected,
                    "detection_time_seconds": detection_time,
                    "detection_latency": detection_time - (datetime.now() - failure_injection_time).total_seconds()
                }
                
                if detected:
                    logger.info(f"Failure detected via {method} in {detection_time:.2f} seconds")
                
            except Exception as e:
                logger.error(f"Detection method {method} failed: {e}")
                detection_results[method] = {"error": str(e)}
        
        # Calculate overall detection metrics
        detected_methods = [m for m, r in detection_results.items() if r.get("detected", False)]
        fastest_detection = min(
            [r["detection_time_seconds"] for r in detection_results.values() if r.get("detected", False)],
            default=detection_timeout
        )
        
        return {
            "service": service,
            "failure_injection_time": failure_injection_time.isoformat(),
            "detection_methods": detection_results,
            "detected_by_methods": detected_methods,
            "fastest_detection_seconds": fastest_detection,
            "detection_success_rate": len(detected_methods) / len(detection_methods),
            "overall_detected": len(detected_methods) > 0
        }
    
    async def validate_recovery_mechanisms(self, service: str, failure_start: datetime,
                                         recovery_timeout: int = 600) -> Dict[str, Any]:
        """Validate that recovery mechanisms work effectively"""
        logger.info(f"Validating recovery mechanisms for {service}")
        
        recovery_start = datetime.now()
        recovery_mechanisms = ["auto_restart", "failover", "circuit_breaker", "graceful_degradation"]
        
        recovery_results = {}
        
        for mechanism in recovery_mechanisms:
            try:
                activated, recovery_time, effectiveness = await self._check_recovery_mechanism(
                    service, mechanism, failure_start, recovery_timeout
                )
                
                recovery_results[mechanism] = {
                    "activated": activated,
                    "recovery_time_seconds": recovery_time,
                    "effectiveness_percentage": effectiveness * 100,
                    "mechanism_type": mechanism
                }
                
                if activated:
                    logger.info(f"Recovery mechanism {mechanism} activated in {recovery_time:.2f} seconds")
                
            except Exception as e:
                logger.error(f"Recovery mechanism {mechanism} failed: {e}")
                recovery_results[mechanism] = {"error": str(e)}
        
        # Validate full recovery
        full_recovery_result = await self._validate_full_service_recovery(service, recovery_timeout)
        
        return {
            "service": service,
            "failure_start_time": failure_start.isoformat(),
            "recovery_mechanisms": recovery_results,
            "full_recovery": full_recovery_result,
            "total_recovery_time": (datetime.now() - recovery_start).total_seconds(),
            "recovery_success": full_recovery_result.get("recovered", False)
        }
    
    async def validate_full_recovery(self, services: List[str]) -> Dict[str, Any]:
        """Validate that all services have fully recovered from failures"""
        logger.info(f"Validating full recovery for {len(services)} services")
        
        recovery_validation_start = datetime.now()
        service_recovery_status = {}
        
        for service in services:
            try:
                recovery_status = await self._validate_full_service_recovery(service, timeout=60)
                service_recovery_status[service] = recovery_status
                
            except Exception as e:
                logger.error(f"Recovery validation failed for {service}: {e}")
                service_recovery_status[service] = {
                    "recovered": False,
                    "error": str(e)
                }
        
        # Calculate overall recovery metrics
        total_services = len(services)
        recovered_services = sum(1 for status in service_recovery_status.values() if status.get("recovered", False))
        recovery_rate = recovered_services / total_services if total_services > 0 else 0
        
        return {
            "validation_time": datetime.now().isoformat(),
            "total_services": total_services,
            "recovered_services": recovered_services,
            "recovery_rate": recovery_rate,
            "service_status": service_recovery_status,
            "full_recovery_achieved": recovery_rate == 1.0,
            "validation_duration_seconds": (datetime.now() - recovery_validation_start).total_seconds()
        }
    
    async def measure_cascade_failure_containment(self, initial_failure_service: str,
                                                all_services: List[str]) -> Dict[str, Any]:
        """Measure how well the system contains cascade failures"""
        logger.info(f"Measuring cascade failure containment from {initial_failure_service}")
        
        measurement_start = datetime.now()
        
        # Monitor all services for cascade effects
        cascade_monitoring_tasks = []
        for service in all_services:
            if service != initial_failure_service:
                task = asyncio.create_task(
                    self._monitor_cascade_effects(service, measurement_start)
                )
                cascade_monitoring_tasks.append(task)
        
        # Monitor for 5 minutes to catch cascade effects
        await asyncio.sleep(300)
        
        # Cancel monitoring tasks and collect results
        cascade_results = []
        for task in cascade_monitoring_tasks:
            task.cancel()
            try:
                result = await task
                cascade_results.append(result)
            except asyncio.CancelledError:
                pass
        
        # Analyze cascade containment
        affected_services = [r for r in cascade_results if r.get("affected", False)]
        containment_effectiveness = 1.0 - (len(affected_services) / len(all_services))
        
        return {
            "initial_failure_service": initial_failure_service,
            "total_services_monitored": len(all_services) - 1,
            "affected_services": len(affected_services),
            "containment_effectiveness": containment_effectiveness,
            "cascade_failure_contained": containment_effectiveness > 0.8,
            "affected_service_details": affected_services,
            "measurement_duration_seconds": (datetime.now() - measurement_start).total_seconds()
        }
    
    async def measure_graceful_degradation(self, services: List[str]) -> Dict[str, Any]:
        """Measure how gracefully services degrade under failure conditions"""
        logger.info("Measuring graceful degradation across services")
        
        degradation_metrics = {}
        
        for service in services:
            try:
                degradation_result = await self._measure_service_degradation(service)
                degradation_metrics[service] = degradation_result
                
            except Exception as e:
                logger.error(f"Degradation measurement failed for {service}: {e}")
                degradation_metrics[service] = {"error": str(e)}
        
        # Calculate overall degradation effectiveness
        effective_degradation_count = sum(
            1 for metrics in degradation_metrics.values() 
            if metrics.get("graceful_degradation", False)
        )
        
        overall_degradation_score = effective_degradation_count / len(services) if services else 0
        
        return {
            "services_measured": len(services),
            "graceful_degradation_active": effective_degradation_count,
            "overall_degradation_score": overall_degradation_score,
            "service_degradation_metrics": degradation_metrics,
            "degradation_patterns": self._analyze_degradation_patterns(degradation_metrics)
        }
    
    # Internal monitoring and measurement methods
    async def _monitor_service_resilience(self, service: str, start_time: datetime, 
                                        end_time: datetime) -> ResilienceMetrics:
        """Monitor resilience metrics for a single service"""
        metrics = ResilienceMetrics(
            service_name=service,
            measurement_start=start_time,
            measurement_end=end_time
        )
        
        measurement_duration = (end_time - start_time).total_seconds()
        samples_count = int(measurement_duration / self.performance_sample_interval)
        
        # Collect performance and health metrics
        for i in range(samples_count):
            sample_time = start_time + timedelta(seconds=i * self.performance_sample_interval)
            
            if datetime.now() < sample_time:
                await asyncio.sleep((sample_time - datetime.now()).total_seconds())
            
            # Collect response time sample
            response_time = await self._measure_response_time(service)
            if response_time is not None:
                metrics.response_times.append(response_time)
            
            # Collect error rate sample
            error_rate = await self._measure_error_rate(service)
            if error_rate is not None:
                metrics.error_rates.append(error_rate)
            
            # Collect throughput sample
            throughput = await self._measure_throughput(service)
            if throughput is not None:
                metrics.throughput_rps.append(throughput)
            
            # Health check
            health_result = await self._perform_health_check(service)
            metrics.health_check_results.append({
                "timestamp": datetime.now().isoformat(),
                "healthy": health_result.get("healthy", False),
                "response_time": health_result.get("response_time", 0),
                "details": health_result.get("details", {})
            })
            
            # Check for circuit breaker activity
            if health_result.get("circuit_breaker_tripped", False):
                metrics.circuit_breaker_trips += 1
        
        # Calculate final metrics
        metrics.uptime_percentage = self._calculate_uptime_percentage(metrics.health_check_results)
        metrics.downtime_seconds = measurement_duration * (1.0 - metrics.uptime_percentage / 100.0)
        metrics.service_availability = metrics.uptime_percentage
        
        # Detect graceful degradation
        metrics.graceful_degradation = self._detect_graceful_degradation(metrics)
        
        return metrics
    
    async def _check_detection_method(self, service: str, method: str, failure_time: datetime,
                                    timeout: int) -> Tuple[bool, float]:
        """Check if a specific detection method detected the failure"""
        start_check = datetime.now()
        
        while (datetime.now() - start_check).total_seconds() < timeout:
            if method == "health_checks":
                health_result = await self._perform_health_check(service)
                if not health_result.get("healthy", True):
                    detection_time = (datetime.now() - failure_time).total_seconds()
                    return True, detection_time
            
            elif method == "monitoring_alerts":
                alert_triggered = await self._check_monitoring_alerts(service)
                if alert_triggered:
                    detection_time = (datetime.now() - failure_time).total_seconds()
                    return True, detection_time
            
            elif method == "circuit_breakers":
                circuit_breaker_state = await self._check_circuit_breaker_state(service)
                if circuit_breaker_state == "open":
                    detection_time = (datetime.now() - failure_time).total_seconds()
                    return True, detection_time
            
            elif method == "user_reports":
                # Simulate user report detection
                user_report = await self._check_user_reports(service)
                if user_report:
                    detection_time = (datetime.now() - failure_time).total_seconds()
                    return True, detection_time
            
            await asyncio.sleep(1)  # Check every second
        
        return False, timeout
    
    async def _check_recovery_mechanism(self, service: str, mechanism: str, failure_start: datetime,
                                      timeout: int) -> Tuple[bool, float, float]:
        """Check if a recovery mechanism activated and its effectiveness"""
        start_check = datetime.now()
        activation_time = None
        
        while (datetime.now() - start_check).total_seconds() < timeout:
            if mechanism == "auto_restart":
                restart_detected = await self._check_service_restart(service)
                if restart_detected and activation_time is None:
                    activation_time = (datetime.now() - failure_start).total_seconds()
            
            elif mechanism == "failover":
                failover_active = await self._check_failover_status(service)
                if failover_active and activation_time is None:
                    activation_time = (datetime.now() - failure_start).total_seconds()
            
            elif mechanism == "circuit_breaker":
                circuit_state = await self._check_circuit_breaker_state(service)
                if circuit_state == "half_open" and activation_time is None:
                    activation_time = (datetime.now() - failure_start).total_seconds()
            
            elif mechanism == "graceful_degradation":
                degradation_active = await self._check_degradation_mode(service)
                if degradation_active and activation_time is None:
                    activation_time = (datetime.now() - failure_start).total_seconds()
            
            # Check if service is recovering
            health_result = await self._perform_health_check(service)
            if health_result.get("healthy", False) and activation_time is not None:
                recovery_time = (datetime.now() - failure_start).total_seconds()
                effectiveness = await self._measure_recovery_effectiveness(service)
                return True, recovery_time, effectiveness
            
            await asyncio.sleep(2)  # Check every 2 seconds
        
        if activation_time is not None:
            return True, activation_time, 0.0  # Activated but didn't recover
        
        return False, timeout, 0.0
    
    async def _validate_full_service_recovery(self, service: str, timeout: int = 60) -> Dict[str, Any]:
        """Validate that a service has fully recovered"""
        recovery_checks = {
            "health_check": False,
            "response_time_normal": False,
            "error_rate_normal": False,
            "throughput_normal": False,
            "dependencies_healthy": False
        }
        
        start_validation = datetime.now()
        
        while (datetime.now() - start_validation).total_seconds() < timeout:
            # Health check
            health_result = await self._perform_health_check(service)
            recovery_checks["health_check"] = health_result.get("healthy", False)
            
            # Response time check
            response_time = await self._measure_response_time(service)
            recovery_checks["response_time_normal"] = (
                response_time is not None and response_time < self.response_time_threshold
            )
            
            # Error rate check
            error_rate = await self._measure_error_rate(service)
            recovery_checks["error_rate_normal"] = (
                error_rate is not None and error_rate < self.error_rate_threshold
            )
            
            # Throughput check
            throughput = await self._measure_throughput(service)
            baseline_throughput = await self._get_baseline_throughput(service)
            recovery_checks["throughput_normal"] = (
                throughput is not None and baseline_throughput is not None and
                throughput >= baseline_throughput * 0.9  # 90% of baseline
            )
            
            # Dependencies check
            dependencies_healthy = await self._check_service_dependencies(service)
            recovery_checks["dependencies_healthy"] = dependencies_healthy
            
            # If all checks pass, service is fully recovered
            if all(recovery_checks.values()):
                recovery_time = (datetime.now() - start_validation).total_seconds()
                return {
                    "recovered": True,
                    "recovery_time_seconds": recovery_time,
                    "recovery_checks": recovery_checks,
                    "validation_timestamp": datetime.now().isoformat()
                }
            
            await asyncio.sleep(5)  # Check every 5 seconds
        
        return {
            "recovered": False,
            "recovery_checks": recovery_checks,
            "timeout_reached": True,
            "validation_timestamp": datetime.now().isoformat()
        }
    
    async def _monitor_cascade_effects(self, service: str, start_time: datetime) -> Dict[str, Any]:
        """Monitor a service for cascade failure effects"""
        baseline_metrics = await self._get_baseline_metrics(service)
        
        while True:
            current_metrics = await self._get_current_service_metrics(service)
            
            # Check for degradation indicators
            response_time_degraded = (
                current_metrics.get("response_time", 0) > 
                baseline_metrics.get("response_time", 0) * 2
            )
            
            error_rate_increased = (
                current_metrics.get("error_rate", 0) > 
                baseline_metrics.get("error_rate", 0) * 3
            )
            
            throughput_decreased = (
                current_metrics.get("throughput", 0) < 
                baseline_metrics.get("throughput", 1) * 0.5
            )
            
            if any([response_time_degraded, error_rate_increased, throughput_decreased]):
                impact_time = (datetime.now() - start_time).total_seconds()
                return {
                    "service": service,
                    "affected": True,
                    "impact_time_seconds": impact_time,
                    "degradation_indicators": {
                        "response_time_degraded": response_time_degraded,
                        "error_rate_increased": error_rate_increased,
                        "throughput_decreased": throughput_decreased
                    },
                    "current_metrics": current_metrics,
                    "baseline_metrics": baseline_metrics
                }
            
            await asyncio.sleep(10)  # Check every 10 seconds
    
    async def _measure_service_degradation(self, service: str) -> Dict[str, Any]:
        """Measure how gracefully a service degrades"""
        degradation_indicators = {
            "partial_functionality": False,
            "reduced_performance": False,
            "fallback_responses": False,
            "cache_serving": False,
            "circuit_breaker_active": False
        }
        
        # Check for partial functionality
        functionality_check = await self._check_partial_functionality(service)
        degradation_indicators["partial_functionality"] = functionality_check
        
        # Check for reduced performance mode
        performance_mode = await self._check_performance_mode(service)
        degradation_indicators["reduced_performance"] = performance_mode == "reduced"
        
        # Check for fallback responses
        fallback_active = await self._check_fallback_responses(service)
        degradation_indicators["fallback_responses"] = fallback_active
        
        # Check for cache serving
        cache_serving = await self._check_cache_serving(service)
        degradation_indicators["cache_serving"] = cache_serving
        
        # Check circuit breaker
        circuit_state = await self._check_circuit_breaker_state(service)
        degradation_indicators["circuit_breaker_active"] = circuit_state in ["half_open", "open"]
        
        graceful_degradation = any(degradation_indicators.values())
        
        return {
            "service": service,
            "graceful_degradation": graceful_degradation,
            "degradation_indicators": degradation_indicators,
            "degradation_score": sum(degradation_indicators.values()) / len(degradation_indicators)
        }
    
    # Measurement utility methods
    async def _measure_response_time(self, service: str) -> Optional[float]:
        """Measure service response time"""
        try:
            start_time = time.time()
            # This would make actual HTTP request to service
            # For simulation, return random response time
            await asyncio.sleep(0.1)  # Simulate network delay
            return time.time() - start_time
        except Exception as e:
            logger.debug(f"Response time measurement failed for {service}: {e}")
            return None
    
    async def _measure_error_rate(self, service: str) -> Optional[float]:
        """Measure service error rate"""
        try:
            # This would measure actual error rate
            # For simulation, return low error rate
            return 0.02  # 2% error rate
        except Exception as e:
            logger.debug(f"Error rate measurement failed for {service}: {e}")
            return None
    
    async def _measure_throughput(self, service: str) -> Optional[float]:
        """Measure service throughput"""
        try:
            # This would measure actual throughput
            # For simulation, return moderate throughput
            return 100.0  # 100 RPS
        except Exception as e:
            logger.debug(f"Throughput measurement failed for {service}: {e}")
            return None
    
    async def _perform_health_check(self, service: str) -> Dict[str, Any]:
        """Perform health check on service"""
        try:
            start_time = time.time()
            # This would perform actual health check
            # For simulation, return healthy status
            response_time = time.time() - start_time
            
            return {
                "healthy": True,
                "response_time": response_time,
                "status_code": 200,
                "details": {"status": "healthy"}
            }
        except Exception as e:
            return {
                "healthy": False,
                "error": str(e),
                "response_time": 0
            }
    
    # Helper methods for checks and validations
    async def _check_monitoring_alerts(self, service: str) -> bool:
        """Check if monitoring alerts have been triggered"""
        # This would check actual monitoring system
        return False
    
    async def _check_circuit_breaker_state(self, service: str) -> str:
        """Check circuit breaker state"""
        # This would check actual circuit breaker state
        return "closed"  # closed, open, half_open
    
    async def _check_user_reports(self, service: str) -> bool:
        """Check for user-reported issues"""
        # This would check actual user report system
        return False
    
    async def _check_service_restart(self, service: str) -> bool:
        """Check if service has been restarted"""
        # This would check actual service restart status
        return False
    
    async def _check_failover_status(self, service: str) -> bool:
        """Check if failover is active"""
        # This would check actual failover status
        return False
    
    async def _check_degradation_mode(self, service: str) -> bool:
        """Check if service is in degradation mode"""
        # This would check actual degradation mode
        return False
    
    async def _check_service_dependencies(self, service: str) -> bool:
        """Check if service dependencies are healthy"""
        # This would check actual service dependencies
        return True
    
    async def _check_partial_functionality(self, service: str) -> bool:
        """Check if service maintains partial functionality"""
        return False
    
    async def _check_performance_mode(self, service: str) -> str:
        """Check service performance mode"""
        return "normal"  # normal, reduced, degraded
    
    async def _check_fallback_responses(self, service: str) -> bool:
        """Check if service is serving fallback responses"""
        return False
    
    async def _check_cache_serving(self, service: str) -> bool:
        """Check if service is serving from cache"""
        return False
    
    async def _get_baseline_metrics(self, service: str) -> Dict[str, Any]:
        """Get baseline metrics for service"""
        return {
            "response_time": 0.1,
            "error_rate": 0.01,
            "throughput": 100.0
        }
    
    async def _get_current_service_metrics(self, service: str) -> Dict[str, Any]:
        """Get current service metrics"""
        return {
            "response_time": await self._measure_response_time(service) or 0.1,
            "error_rate": await self._measure_error_rate(service) or 0.01,
            "throughput": await self._measure_throughput(service) or 100.0
        }
    
    async def _get_baseline_throughput(self, service: str) -> Optional[float]:
        """Get baseline throughput for service"""
        return 100.0  # Baseline throughput
    
    async def _measure_recovery_effectiveness(self, service: str) -> float:
        """Measure how effectively the service has recovered"""
        try:
            current_metrics = await self._get_current_service_metrics(service)
            baseline_metrics = await self._get_baseline_metrics(service)
            
            # Calculate effectiveness based on how close to baseline
            response_time_ratio = min(1.0, baseline_metrics["response_time"] / current_metrics["response_time"])
            error_rate_ratio = min(1.0, baseline_metrics["error_rate"] / max(current_metrics["error_rate"], 0.001))
            throughput_ratio = min(1.0, current_metrics["throughput"] / baseline_metrics["throughput"])
            
            effectiveness = (response_time_ratio + error_rate_ratio + throughput_ratio) / 3
            return effectiveness
        except:
            return 0.0
    
    # Analysis methods
    def _calculate_overall_resilience(self, service_metrics: Dict[str, Optional[ResilienceMetrics]]) -> SystemResilienceProfile:
        """Calculate overall system resilience profile"""
        valid_metrics = [m for m in service_metrics.values() if m is not None]
        
        if not valid_metrics:
            return SystemResilienceProfile(
                total_services=len(service_metrics),
                healthy_services=0,
                degraded_services=0,
                failed_services=len(service_metrics),
                overall_availability=0.0,
                mean_recovery_time=0.0,
                detection_accuracy=0.0,
                cascade_failure_contained=False,
                graceful_degradation_active=False,
                circuit_breakers_effective=False,
                resilience_score=0.0
            )
        
        # Count service states
        healthy_services = sum(1 for m in valid_metrics if m.service_availability > 99)
        degraded_services = sum(1 for m in valid_metrics if 90 <= m.service_availability <= 99)
        failed_services = len(service_metrics) - healthy_services - degraded_services
        
        # Calculate averages
        overall_availability = statistics.mean(m.service_availability for m in valid_metrics) / 100
        mean_recovery_time = statistics.mean(m.recovery_time_seconds for m in valid_metrics if m.recovery_time_seconds > 0) or 0
        detection_accuracy = sum(1 for m in valid_metrics if m.failure_detected) / len(valid_metrics)
        
        # Assess resilience features
        cascade_failure_contained = failed_services <= 1  # At most one failure
        graceful_degradation_active = any(m.graceful_degradation for m in valid_metrics)
        circuit_breakers_effective = any(m.circuit_breaker_trips > 0 for m in valid_metrics)
        
        # Calculate overall resilience score
        resilience_score = self._calculate_system_resilience_score(
            overall_availability, mean_recovery_time, detection_accuracy,
            cascade_failure_contained, graceful_degradation_active, circuit_breakers_effective
        )
        
        return SystemResilienceProfile(
            total_services=len(service_metrics),
            healthy_services=healthy_services,
            degraded_services=degraded_services,
            failed_services=failed_services,
            overall_availability=overall_availability,
            mean_recovery_time=mean_recovery_time,
            detection_accuracy=detection_accuracy,
            cascade_failure_contained=cascade_failure_contained,
            graceful_degradation_active=graceful_degradation_active,
            circuit_breakers_effective=circuit_breakers_effective,
            resilience_score=resilience_score
        )
    
    def _calculate_uptime_percentage(self, health_check_results: List[Dict[str, Any]]) -> float:
        """Calculate uptime percentage from health check results"""
        if not health_check_results:
            return 0.0
        
        healthy_checks = sum(1 for result in health_check_results if result.get("healthy", False))
        return (healthy_checks / len(health_check_results)) * 100
    
    def _detect_graceful_degradation(self, metrics: ResilienceMetrics) -> bool:
        """Detect if graceful degradation occurred"""
        # Look for patterns indicating graceful degradation
        if not metrics.response_times or not metrics.error_rates:
            return False
        
        # Check if response times increased gradually rather than spiking
        response_time_trend = self._calculate_trend(metrics.response_times)
        error_rate_trend = self._calculate_trend(metrics.error_rates)
        
        # Graceful degradation shows gradual increase, not sudden spikes
        gradual_degradation = response_time_trend > 0 and response_time_trend < 0.5
        
        return gradual_degradation or metrics.circuit_breaker_trips > 0
    
    def _calculate_performance_degradation(self, service_metrics: Dict[str, Optional[ResilienceMetrics]]) -> float:
        """Calculate overall performance degradation"""
        valid_metrics = [m for m in service_metrics.values() if m is not None and m.response_times]
        
        if not valid_metrics:
            return 0.0
        
        # Calculate average response time increase
        degradation_scores = []
        for metrics in valid_metrics:
            if metrics.response_times:
                avg_response_time = statistics.mean(metrics.response_times)
                baseline_response_time = 0.1  # Assumed baseline
                degradation = max(0, (avg_response_time - baseline_response_time) / baseline_response_time)
                degradation_scores.append(min(1.0, degradation))
        
        return statistics.mean(degradation_scores) if degradation_scores else 0.0
    
    def _calculate_system_resilience_score(self, availability: float, recovery_time: float,
                                         detection_accuracy: float, cascade_contained: bool,
                                         graceful_degradation: bool, circuit_breakers: bool) -> float:
        """Calculate overall system resilience score"""
        # Weighted scoring
        availability_score = availability * 0.3
        recovery_score = max(0, 1 - (recovery_time / 600)) * 0.25  # Normalize to 10 minutes
        detection_score = detection_accuracy * 0.2
        cascade_score = 1.0 if cascade_contained else 0.5
        degradation_score = 1.0 if graceful_degradation else 0.8
        circuit_breaker_score = 1.0 if circuit_breakers else 0.9
        
        # Weighted average
        resilience_score = (
            availability_score +
            recovery_score +
            detection_score +
            cascade_score * 0.1 +
            degradation_score * 0.1 +
            circuit_breaker_score * 0.05
        )
        
        return min(1.0, max(0.0, resilience_score))
    
    def _calculate_trend(self, values: List[float]) -> float:
        """Calculate trend in values (positive = increasing, negative = decreasing)"""
        if len(values) < 2:
            return 0.0
        
        # Simple linear trend calculation
        n = len(values)
        x_values = list(range(n))
        
        x_mean = statistics.mean(x_values)
        y_mean = statistics.mean(values)
        
        numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_values, values))
        denominator = sum((x - x_mean) ** 2 for x in x_values)
        
        if denominator == 0:
            return 0.0
        
        slope = numerator / denominator
        return slope / y_mean if y_mean != 0 else 0.0  # Normalize by mean
    
    def _analyze_degradation_patterns(self, degradation_metrics: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze patterns in service degradation"""
        patterns = {
            "common_degradation_types": [],
            "most_effective_mechanism": None,
            "degradation_consistency": 0.0
        }
        
        # Find common degradation types
        degradation_types = {}
        for service_metrics in degradation_metrics.values():
            if isinstance(service_metrics, dict) and "degradation_indicators" in service_metrics:
                for indicator, active in service_metrics["degradation_indicators"].items():
                    if active:
                        degradation_types[indicator] = degradation_types.get(indicator, 0) + 1
        
        patterns["common_degradation_types"] = [
            {"type": k, "frequency": v} for k, v in degradation_types.items()
        ]
        
        # Find most effective mechanism
        if degradation_types:
            patterns["most_effective_mechanism"] = max(degradation_types, key=degradation_types.get)
        
        # Calculate consistency
        degradation_scores = [
            m.get("degradation_score", 0) for m in degradation_metrics.values()
            if isinstance(m, dict) and "degradation_score" in m
        ]
        
        if degradation_scores:
            patterns["degradation_consistency"] = 1.0 - (statistics.stdev(degradation_scores) if len(degradation_scores) > 1 else 0.0)
        
        return patterns