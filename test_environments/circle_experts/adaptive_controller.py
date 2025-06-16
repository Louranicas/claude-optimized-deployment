"""
Adaptive Controller - Real-time test adaptation based on expert recommendations
Monitors system behavior and adapts test strategies dynamically
"""

import asyncio
import logging
import time
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
from enum import Enum
import statistics


class AdaptationTrigger(Enum):
    PERFORMANCE_DEGRADATION = "performance_degradation"
    ERROR_RATE_SPIKE = "error_rate_spike"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    EXPERT_RECOMMENDATION = "expert_recommendation"
    SAFETY_THRESHOLD = "safety_threshold"
    TIME_BASED = "time_based"


@dataclass
class AdaptationAction:
    """Adaptation action definition"""
    action_id: str
    trigger: AdaptationTrigger
    action_type: str
    parameters: Dict[str, Any]
    timestamp: float
    confidence: float
    expected_impact: Dict[str, float]
    rollback_condition: Optional[str] = None


@dataclass
class AdaptationResult:
    """Result of an adaptation action"""
    action_id: str
    success: bool
    execution_time: float
    impact_measured: Dict[str, float]
    side_effects: List[str]
    recommendation: str


class AdaptiveController:
    """
    Real-time test adaptation controller with expert-driven decision making
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.name = "Adaptive Controller"
        
        # Adaptation parameters
        self.adaptation_config = {
            'monitoring_interval': 1.0,  # seconds
            'adaptation_threshold': 0.8,  # confidence threshold
            'max_adaptations_per_minute': 5,
            'safety_override_threshold': 0.95,
            'rollback_timeout': 30.0,  # seconds
            'stability_window': 10.0  # seconds
        }
        
        # Adaptation triggers and thresholds
        self.adaptation_triggers = {
            AdaptationTrigger.PERFORMANCE_DEGRADATION: {
                'response_time_threshold': 2000,  # ms
                'throughput_degradation_threshold': 0.3,  # 30% degradation
                'cpu_threshold': 90,  # %
                'memory_threshold': 95  # %
            },
            AdaptationTrigger.ERROR_RATE_SPIKE: {
                'error_rate_threshold': 0.05,  # 5%
                'error_rate_increase_threshold': 0.02,  # 2% increase
                'consecutive_errors_threshold': 10
            },
            AdaptationTrigger.RESOURCE_EXHAUSTION: {
                'cpu_exhaustion_threshold': 98,  # %
                'memory_exhaustion_threshold': 98,  # %
                'disk_usage_threshold': 95,  # %
                'connection_pool_threshold': 95  # %
            },
            AdaptationTrigger.SAFETY_THRESHOLD: {
                'critical_error_rate': 0.1,  # 10%
                'response_time_limit': 10000,  # 10 seconds
                'availability_threshold': 0.9  # 90%
            }
        }
        
        # Adaptation strategies
        self.adaptation_strategies = {
            'reduce_load': {
                'description': 'Reduce test load intensity',
                'parameters': ['load_reduction_factor'],
                'impact': {'cpu_reduction': 20, 'response_time_improvement': 30}
            },
            'increase_timeout': {
                'description': 'Increase timeout thresholds',
                'parameters': ['timeout_multiplier'],
                'impact': {'error_rate_reduction': 15, 'stability_improvement': 25}
            },
            'scale_resources': {
                'description': 'Scale system resources',
                'parameters': ['scale_factor', 'resource_type'],
                'impact': {'capacity_increase': 40, 'performance_improvement': 35}
            },
            'enable_circuit_breaker': {
                'description': 'Activate circuit breaker patterns',
                'parameters': ['failure_threshold', 'recovery_timeout'],
                'impact': {'error_isolation': 80, 'cascade_prevention': 70}
            },
            'adjust_retry_policy': {
                'description': 'Modify retry behavior',
                'parameters': ['max_retries', 'backoff_multiplier'],
                'impact': {'success_rate_improvement': 20, 'latency_increase': 10}
            },
            'activate_fallback': {
                'description': 'Enable fallback mechanisms',
                'parameters': ['fallback_mode', 'degradation_level'],
                'impact': {'availability_improvement': 50, 'functionality_reduction': 20}
            },
            'emergency_stop': {
                'description': 'Emergency test termination',
                'parameters': ['stop_reason', 'cleanup_required'],
                'impact': {'immediate_protection': 100, 'test_interruption': 100}
            }
        }
        
        # Monitoring state
        self.monitoring_active = False
        self.current_metrics: Dict[str, Any] = {}
        self.metric_history: List[Dict[str, Any]] = []
        self.adaptation_history: List[AdaptationAction] = []
        self.active_adaptations: Dict[str, AdaptationAction] = {}
        
        # Callback functions for external integration
        self.metric_collectors: List[Callable] = []
        self.adaptation_executors: Dict[str, Callable] = {}
        self.notification_handlers: List[Callable] = []
        
    async def execute_with_adaptation(self, execution_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute strategy with real-time adaptation
        """
        self.logger.info("Starting adaptive execution with real-time monitoring")
        
        try:
            # Extract execution parameters
            strategy = execution_data.get('strategy', {})
            context = execution_data.get('context', {})
            adaptive_params = execution_data.get('adaptive_parameters', {})
            
            # Initialize adaptation
            await self._initialize_adaptation(adaptive_params)
            
            # Start monitoring
            monitoring_task = asyncio.create_task(self._continuous_monitoring())
            
            # Execute strategy with adaptation
            execution_results = await self._execute_strategy_with_adaptation(
                strategy, context, adaptive_params
            )
            
            # Stop monitoring
            self.monitoring_active = False
            await monitoring_task
            
            # Compile final results
            results = {
                'strategy_execution': execution_results,
                'adaptations': [self._action_to_dict(action) for action in self.adaptation_history],
                'adaptation_count': len(self.adaptation_history),
                'final_metrics': self.current_metrics.copy(),
                'adaptation_effectiveness': self._calculate_adaptation_effectiveness(),
                'stability_metrics': self._calculate_stability_metrics(),
                'recommendation': self._generate_adaptation_recommendation()
            }
            
            self.logger.info(f"Adaptive execution completed with {len(self.adaptation_history)} adaptations")
            return results
            
        except Exception as e:
            self.logger.error(f"Adaptive execution failed: {str(e)}")
            self.monitoring_active = False
            raise
    
    async def _initialize_adaptation(self, adaptive_params: Dict[str, Any]):
        """Initialize adaptive control system"""
        # Update configuration
        self.adaptation_config.update(adaptive_params)
        
        # Reset state
        self.current_metrics = {}
        self.metric_history = []
        self.adaptation_history = []
        self.active_adaptations = {}
        
        # Initialize monitoring
        self.monitoring_active = True
        
        self.logger.info("Adaptive controller initialized")
    
    async def _continuous_monitoring(self):
        """Continuous monitoring loop"""
        while self.monitoring_active:
            try:
                # Collect current metrics
                await self._collect_metrics()
                
                # Analyze for adaptation triggers
                adaptations_needed = await self._analyze_adaptation_triggers()
                
                # Execute adaptations
                for adaptation in adaptations_needed:
                    await self._execute_adaptation(adaptation)
                
                # Check for rollback conditions
                await self._check_rollback_conditions()
                
                # Sleep until next monitoring cycle
                await asyncio.sleep(self.adaptation_config['monitoring_interval'])
                
            except Exception as e:
                self.logger.error(f"Monitoring cycle failed: {str(e)}")
                await asyncio.sleep(self.adaptation_config['monitoring_interval'])
    
    async def _collect_metrics(self):
        """Collect current system metrics"""
        metrics = {
            'timestamp': time.time(),
            'response_time': 150,  # Default values - would be replaced by actual collectors
            'throughput': 500,
            'error_rate': 0.001,
            'cpu_utilization': 45,
            'memory_usage': 60,
            'active_connections': 100,
            'queue_length': 5
        }
        
        # Call external metric collectors
        for collector in self.metric_collectors:
            try:
                external_metrics = await collector()
                metrics.update(external_metrics)
            except Exception as e:
                self.logger.warning(f"Metric collector failed: {str(e)}")
        
        # Update current metrics
        self.current_metrics = metrics
        
        # Add to history
        self.metric_history.append(metrics.copy())
        
        # Maintain history size
        if len(self.metric_history) > 1000:
            self.metric_history = self.metric_history[-1000:]
    
    async def _analyze_adaptation_triggers(self) -> List[AdaptationAction]:
        """Analyze current state for adaptation triggers"""
        adaptations = []
        
        # Check performance degradation
        perf_adaptation = await self._check_performance_degradation()
        if perf_adaptation:
            adaptations.append(perf_adaptation)
        
        # Check error rate spikes
        error_adaptation = await self._check_error_rate_spike()
        if error_adaptation:
            adaptations.append(error_adaptation)
        
        # Check resource exhaustion
        resource_adaptation = await self._check_resource_exhaustion()
        if resource_adaptation:
            adaptations.append(resource_adaptation)
        
        # Check safety thresholds
        safety_adaptation = await self._check_safety_thresholds()
        if safety_adaptation:
            adaptations.append(safety_adaptation)
        
        # Filter adaptations by rate limiting
        adaptations = self._apply_rate_limiting(adaptations)
        
        return adaptations
    
    async def _check_performance_degradation(self) -> Optional[AdaptationAction]:
        """Check for performance degradation triggers"""
        if len(self.metric_history) < 5:
            return None
        
        current = self.current_metrics
        triggers = self.adaptation_triggers[AdaptationTrigger.PERFORMANCE_DEGRADATION]
        
        # Check response time degradation
        response_time = current.get('response_time', 0)
        if response_time > triggers['response_time_threshold']:
            return AdaptationAction(
                action_id=f"perf-response-{int(time.time())}",
                trigger=AdaptationTrigger.PERFORMANCE_DEGRADATION,
                action_type='reduce_load',
                parameters={'load_reduction_factor': 0.7},
                timestamp=time.time(),
                confidence=0.8,
                expected_impact={'response_time_improvement': 30},
                rollback_condition='response_time < 1000'
            )
        
        # Check throughput degradation
        if len(self.metric_history) >= 10:
            recent_throughput = [m.get('throughput', 0) for m in self.metric_history[-5:]]
            baseline_throughput = [m.get('throughput', 0) for m in self.metric_history[-10:-5]]
            
            if baseline_throughput and recent_throughput:
                recent_avg = statistics.mean(recent_throughput)
                baseline_avg = statistics.mean(baseline_throughput)
                
                if baseline_avg > 0:
                    degradation = (baseline_avg - recent_avg) / baseline_avg
                    if degradation > triggers['throughput_degradation_threshold']:
                        return AdaptationAction(
                            action_id=f"perf-throughput-{int(time.time())}",
                            trigger=AdaptationTrigger.PERFORMANCE_DEGRADATION,
                            action_type='scale_resources',
                            parameters={'scale_factor': 1.5, 'resource_type': 'compute'},
                            timestamp=time.time(),
                            confidence=0.75,
                            expected_impact={'throughput_improvement': 40},
                            rollback_condition='throughput > baseline'
                        )
        
        return None
    
    async def _check_error_rate_spike(self) -> Optional[AdaptationAction]:
        """Check for error rate spike triggers"""
        current = self.current_metrics
        triggers = self.adaptation_triggers[AdaptationTrigger.ERROR_RATE_SPIKE]
        
        error_rate = current.get('error_rate', 0)
        
        # Check absolute error rate threshold
        if error_rate > triggers['error_rate_threshold']:
            return AdaptationAction(
                action_id=f"error-spike-{int(time.time())}",
                trigger=AdaptationTrigger.ERROR_RATE_SPIKE,
                action_type='enable_circuit_breaker',
                parameters={'failure_threshold': 5, 'recovery_timeout': 30},
                timestamp=time.time(),
                confidence=0.85,
                expected_impact={'error_isolation': 70},
                rollback_condition='error_rate < 0.01'
            )
        
        # Check error rate increase
        if len(self.metric_history) >= 5:
            recent_errors = [m.get('error_rate', 0) for m in self.metric_history[-5:]]
            if len(recent_errors) >= 2:
                error_increase = recent_errors[-1] - recent_errors[0]
                if error_increase > triggers['error_rate_increase_threshold']:
                    return AdaptationAction(
                        action_id=f"error-increase-{int(time.time())}",
                        trigger=AdaptationTrigger.ERROR_RATE_SPIKE,
                        action_type='adjust_retry_policy',
                        parameters={'max_retries': 3, 'backoff_multiplier': 2.0},
                        timestamp=time.time(),
                        confidence=0.7,
                        expected_impact={'success_rate_improvement': 25},
                        rollback_condition='error_rate_stable'
                    )
        
        return None
    
    async def _check_resource_exhaustion(self) -> Optional[AdaptationAction]:
        """Check for resource exhaustion triggers"""
        current = self.current_metrics
        triggers = self.adaptation_triggers[AdaptationTrigger.RESOURCE_EXHAUSTION]
        
        # Check CPU exhaustion
        cpu_usage = current.get('cpu_utilization', 0)
        if cpu_usage > triggers['cpu_exhaustion_threshold']:
            return AdaptationAction(
                action_id=f"resource-cpu-{int(time.time())}",
                trigger=AdaptationTrigger.RESOURCE_EXHAUSTION,
                action_type='reduce_load',
                parameters={'load_reduction_factor': 0.6},
                timestamp=time.time(),
                confidence=0.9,
                expected_impact={'cpu_reduction': 25},
                rollback_condition='cpu_utilization < 85'
            )
        
        # Check memory exhaustion
        memory_usage = current.get('memory_usage', 0)
        if memory_usage > triggers['memory_exhaustion_threshold']:
            return AdaptationAction(
                action_id=f"resource-memory-{int(time.time())}",
                trigger=AdaptationTrigger.RESOURCE_EXHAUSTION,
                action_type='scale_resources',
                parameters={'scale_factor': 1.3, 'resource_type': 'memory'},
                timestamp=time.time(),
                confidence=0.85,
                expected_impact={'memory_relief': 30},
                rollback_condition='memory_usage < 90'
            )
        
        return None
    
    async def _check_safety_thresholds(self) -> Optional[AdaptationAction]:
        """Check for safety threshold violations"""
        current = self.current_metrics
        triggers = self.adaptation_triggers[AdaptationTrigger.SAFETY_THRESHOLD]
        
        # Check critical error rate
        error_rate = current.get('error_rate', 0)
        if error_rate > triggers['critical_error_rate']:
            return AdaptationAction(
                action_id=f"safety-critical-{int(time.time())}",
                trigger=AdaptationTrigger.SAFETY_THRESHOLD,
                action_type='emergency_stop',
                parameters={'stop_reason': 'critical_error_rate', 'cleanup_required': True},
                timestamp=time.time(),
                confidence=1.0,
                expected_impact={'immediate_protection': 100},
                rollback_condition=None  # No rollback for emergency stop
            )
        
        # Check response time limit
        response_time = current.get('response_time', 0)
        if response_time > triggers['response_time_limit']:
            return AdaptationAction(
                action_id=f"safety-response-{int(time.time())}",
                trigger=AdaptationTrigger.SAFETY_THRESHOLD,
                action_type='activate_fallback',
                parameters={'fallback_mode': 'degraded', 'degradation_level': 0.5},
                timestamp=time.time(),
                confidence=0.95,
                expected_impact={'availability_improvement': 60},
                rollback_condition='response_time < 5000'
            )
        
        return None
    
    def _apply_rate_limiting(self, adaptations: List[AdaptationAction]) -> List[AdaptationAction]:
        """Apply rate limiting to adaptation actions"""
        if not adaptations:
            return adaptations
        
        # Check adaptations per minute
        current_time = time.time()
        recent_adaptations = [
            a for a in self.adaptation_history 
            if current_time - a.timestamp < 60
        ]
        
        max_adaptations = self.adaptation_config['max_adaptations_per_minute']
        available_slots = max_adaptations - len(recent_adaptations)
        
        if available_slots <= 0:
            self.logger.warning("Adaptation rate limit reached, deferring actions")
            return []
        
        # Prioritize by confidence and safety
        adaptations.sort(key=lambda a: (
            a.trigger == AdaptationTrigger.SAFETY_THRESHOLD,
            a.confidence
        ), reverse=True)
        
        return adaptations[:available_slots]
    
    async def _execute_adaptation(self, adaptation: AdaptationAction):
        """Execute an adaptation action"""
        self.logger.info(f"Executing adaptation: {adaptation.action_type} for {adaptation.trigger.value}")
        
        try:
            # Check if adaptation is already active
            if adaptation.action_id in self.active_adaptations:
                return
            
            # Execute adaptation strategy
            success = await self._execute_adaptation_strategy(adaptation)
            
            if success:
                # Add to active adaptations
                self.active_adaptations[adaptation.action_id] = adaptation
                
                # Add to history
                self.adaptation_history.append(adaptation)
                
                # Notify handlers
                await self._notify_adaptation_executed(adaptation)
                
                self.logger.info(f"Adaptation {adaptation.action_id} executed successfully")
            else:
                self.logger.warning(f"Adaptation {adaptation.action_id} execution failed")
                
        except Exception as e:
            self.logger.error(f"Failed to execute adaptation {adaptation.action_id}: {str(e)}")
    
    async def _execute_adaptation_strategy(self, adaptation: AdaptationAction) -> bool:
        """Execute specific adaptation strategy"""
        strategy = self.adaptation_strategies.get(adaptation.action_type)
        if not strategy:
            self.logger.error(f"Unknown adaptation strategy: {adaptation.action_type}")
            return False
        
        # Check if we have an executor for this strategy
        if adaptation.action_type in self.adaptation_executors:
            try:
                executor = self.adaptation_executors[adaptation.action_type]
                result = await executor(adaptation.parameters)
                return result.get('success', False)
            except Exception as e:
                self.logger.error(f"Adaptation executor failed: {str(e)}")
                return False
        
        # Default implementation for common strategies
        if adaptation.action_type == 'reduce_load':
            return await self._default_reduce_load(adaptation.parameters)
        elif adaptation.action_type == 'increase_timeout':
            return await self._default_increase_timeout(adaptation.parameters)
        elif adaptation.action_type == 'emergency_stop':
            return await self._default_emergency_stop(adaptation.parameters)
        
        # If no executor available, log and assume success for testing
        self.logger.info(f"No executor for {adaptation.action_type}, simulating success")
        return True
    
    async def _default_reduce_load(self, parameters: Dict[str, Any]) -> bool:
        """Default implementation for load reduction"""
        reduction_factor = parameters.get('load_reduction_factor', 0.8)
        self.logger.info(f"Reducing load by factor {reduction_factor}")
        
        # Simulate load reduction effect on metrics
        if 'response_time' in self.current_metrics:
            self.current_metrics['response_time'] *= reduction_factor
        if 'cpu_utilization' in self.current_metrics:
            self.current_metrics['cpu_utilization'] *= reduction_factor
        
        return True
    
    async def _default_increase_timeout(self, parameters: Dict[str, Any]) -> bool:
        """Default implementation for timeout increase"""
        timeout_multiplier = parameters.get('timeout_multiplier', 1.5)
        self.logger.info(f"Increasing timeouts by factor {timeout_multiplier}")
        return True
    
    async def _default_emergency_stop(self, parameters: Dict[str, Any]) -> bool:
        """Default implementation for emergency stop"""
        stop_reason = parameters.get('stop_reason', 'unknown')
        self.logger.critical(f"Emergency stop triggered: {stop_reason}")
        
        # Set monitoring to stop
        self.monitoring_active = False
        
        return True
    
    async def _check_rollback_conditions(self):
        """Check if any active adaptations should be rolled back"""
        adaptations_to_rollback = []
        
        for action_id, adaptation in self.active_adaptations.items():
            if adaptation.rollback_condition:
                should_rollback = await self._evaluate_rollback_condition(
                    adaptation.rollback_condition
                )
                
                if should_rollback:
                    adaptations_to_rollback.append(action_id)
            
            # Check timeout
            if time.time() - adaptation.timestamp > self.adaptation_config['rollback_timeout']:
                adaptations_to_rollback.append(action_id)
        
        # Execute rollbacks
        for action_id in adaptations_to_rollback:
            await self._rollback_adaptation(action_id)
    
    async def _evaluate_rollback_condition(self, condition: str) -> bool:
        """Evaluate rollback condition"""
        try:
            # Simple condition evaluation (would be more sophisticated in practice)
            if 'response_time <' in condition:
                threshold = float(condition.split('<')[1].strip())
                return self.current_metrics.get('response_time', 0) < threshold
            elif 'error_rate <' in condition:
                threshold = float(condition.split('<')[1].strip())
                return self.current_metrics.get('error_rate', 0) < threshold
            elif 'cpu_utilization <' in condition:
                threshold = float(condition.split('<')[1].strip())
                return self.current_metrics.get('cpu_utilization', 0) < threshold
            
            return False
            
        except Exception as e:
            self.logger.warning(f"Failed to evaluate rollback condition '{condition}': {str(e)}")
            return False
    
    async def _rollback_adaptation(self, action_id: str):
        """Rollback an adaptation action"""
        if action_id not in self.active_adaptations:
            return
        
        adaptation = self.active_adaptations[action_id]
        self.logger.info(f"Rolling back adaptation: {action_id}")
        
        try:
            # Execute rollback logic (strategy-specific)
            await self._execute_rollback_strategy(adaptation)
            
            # Remove from active adaptations
            del self.active_adaptations[action_id]
            
            # Notify handlers
            await self._notify_adaptation_rolled_back(adaptation)
            
        except Exception as e:
            self.logger.error(f"Failed to rollback adaptation {action_id}: {str(e)}")
    
    async def _execute_rollback_strategy(self, adaptation: AdaptationAction):
        """Execute rollback for specific adaptation strategy"""
        # Implementation would depend on the specific strategy
        self.logger.info(f"Executing rollback for {adaptation.action_type}")
    
    async def _execute_strategy_with_adaptation(
        self,
        strategy: Dict[str, Any],
        context: Dict[str, Any],
        adaptive_params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute strategy while monitoring and adapting"""
        
        # Simulate strategy execution
        execution_start = time.time()
        
        # Strategy execution phases
        phases = [
            "initialization",
            "ramp_up", 
            "steady_state",
            "peak_load",
            "ramp_down"
        ]
        
        phase_results = {}
        
        for phase in phases:
            if not self.monitoring_active:
                break
                
            self.logger.info(f"Executing phase: {phase}")
            
            # Simulate phase execution
            phase_duration = adaptive_params.get('phase_duration', 60)
            await asyncio.sleep(min(phase_duration, 10))  # Cap for testing
            
            # Record phase metrics
            phase_results[phase] = {
                'duration': time.time() - execution_start,
                'metrics': self.current_metrics.copy(),
                'adaptations': len(self.adaptation_history)
            }
        
        execution_time = time.time() - execution_start
        
        return {
            'execution_time': execution_time,
            'phases': phase_results,
            'success': self.monitoring_active,  # False if emergency stopped
            'final_state': self.current_metrics.copy()
        }
    
    def _calculate_adaptation_effectiveness(self) -> Dict[str, float]:
        """Calculate effectiveness of adaptations"""
        if not self.adaptation_history or len(self.metric_history) < 10:
            return {'overall_effectiveness': 0.5}
        
        # Compare metrics before and after adaptations
        pre_adaptation_metrics = []
        post_adaptation_metrics = []
        
        for adaptation in self.adaptation_history:
            adaptation_time = adaptation.timestamp
            
            # Find metrics before adaptation
            pre_metrics = [m for m in self.metric_history if m['timestamp'] < adaptation_time]
            if pre_metrics:
                pre_adaptation_metrics.append(pre_metrics[-1])
            
            # Find metrics after adaptation
            post_metrics = [m for m in self.metric_history if m['timestamp'] > adaptation_time + 10]
            if post_metrics:
                post_adaptation_metrics.append(post_metrics[0])
        
        if not pre_adaptation_metrics or not post_adaptation_metrics:
            return {'overall_effectiveness': 0.5}
        
        # Calculate improvements
        effectiveness = {}
        
        # Response time improvement
        pre_response = statistics.mean([m.get('response_time', 0) for m in pre_adaptation_metrics])
        post_response = statistics.mean([m.get('response_time', 0) for m in post_adaptation_metrics])
        
        if pre_response > 0:
            response_improvement = max(0, (pre_response - post_response) / pre_response)
            effectiveness['response_time_improvement'] = response_improvement
        
        # Error rate improvement
        pre_errors = statistics.mean([m.get('error_rate', 0) for m in pre_adaptation_metrics])
        post_errors = statistics.mean([m.get('error_rate', 0) for m in post_adaptation_metrics])
        
        if pre_errors > 0:
            error_improvement = max(0, (pre_errors - post_errors) / pre_errors)
            effectiveness['error_rate_improvement'] = error_improvement
        
        # Overall effectiveness
        improvements = list(effectiveness.values())
        if improvements:
            effectiveness['overall_effectiveness'] = statistics.mean(improvements)
        else:
            effectiveness['overall_effectiveness'] = 0.5
        
        return effectiveness
    
    def _calculate_stability_metrics(self) -> Dict[str, float]:
        """Calculate system stability metrics"""
        if len(self.metric_history) < 10:
            return {'stability_score': 0.5}
        
        # Calculate variance in key metrics
        response_times = [m.get('response_time', 0) for m in self.metric_history[-20:]]
        error_rates = [m.get('error_rate', 0) for m in self.metric_history[-20:]]
        
        stability_metrics = {}
        
        # Response time stability
        if len(response_times) > 1:
            response_variance = statistics.variance(response_times)
            response_mean = statistics.mean(response_times)
            if response_mean > 0:
                response_cv = (response_variance ** 0.5) / response_mean
                stability_metrics['response_time_stability'] = max(0, 1 - response_cv)
        
        # Error rate stability
        if len(error_rates) > 1:
            error_variance = statistics.variance(error_rates)
            error_mean = statistics.mean(error_rates)
            if error_mean > 0:
                error_cv = (error_variance ** 0.5) / error_mean
                stability_metrics['error_rate_stability'] = max(0, 1 - error_cv)
        
        # Overall stability
        if stability_metrics:
            stability_metrics['stability_score'] = statistics.mean(stability_metrics.values())
        else:
            stability_metrics['stability_score'] = 0.5
        
        return stability_metrics
    
    def _generate_adaptation_recommendation(self) -> str:
        """Generate recommendation based on adaptation results"""
        if not self.adaptation_history:
            return "No adaptations were needed - system performed stably"
        
        adaptation_count = len(self.adaptation_history)
        effectiveness = self._calculate_adaptation_effectiveness()
        
        if adaptation_count > 10:
            return "High adaptation frequency indicates system instability - consider architectural improvements"
        elif adaptation_count > 5:
            return "Moderate adaptations applied - monitor system for recurring patterns"
        elif effectiveness.get('overall_effectiveness', 0) > 0.7:
            return "Adaptations were highly effective - system responded well to dynamic adjustments"
        elif effectiveness.get('overall_effectiveness', 0) > 0.4:
            return "Adaptations showed moderate effectiveness - some fine-tuning may be needed"
        else:
            return "Adaptations had limited effectiveness - investigate root causes"
    
    async def _notify_adaptation_executed(self, adaptation: AdaptationAction):
        """Notify handlers of adaptation execution"""
        for handler in self.notification_handlers:
            try:
                await handler('adaptation_executed', adaptation)
            except Exception as e:
                self.logger.warning(f"Notification handler failed: {str(e)}")
    
    async def _notify_adaptation_rolled_back(self, adaptation: AdaptationAction):
        """Notify handlers of adaptation rollback"""
        for handler in self.notification_handlers:
            try:
                await handler('adaptation_rolled_back', adaptation)
            except Exception as e:
                self.logger.warning(f"Notification handler failed: {str(e)}")
    
    def _action_to_dict(self, action: AdaptationAction) -> Dict[str, Any]:
        """Convert adaptation action to dictionary"""
        return {
            'action_id': action.action_id,
            'trigger': action.trigger.value,
            'action_type': action.action_type,
            'parameters': action.parameters,
            'timestamp': action.timestamp,
            'confidence': action.confidence,
            'expected_impact': action.expected_impact,
            'rollback_condition': action.rollback_condition
        }
    
    # Public interface methods for integration
    
    def add_metric_collector(self, collector: Callable):
        """Add a metric collector function"""
        self.metric_collectors.append(collector)
    
    def add_adaptation_executor(self, strategy_type: str, executor: Callable):
        """Add an adaptation executor for a specific strategy"""
        self.adaptation_executors[strategy_type] = executor
    
    def add_notification_handler(self, handler: Callable):
        """Add a notification handler for adaptation events"""
        self.notification_handlers.append(handler)
    
    def get_current_metrics(self) -> Dict[str, Any]:
        """Get current system metrics"""
        return self.current_metrics.copy()
    
    def get_adaptation_history(self) -> List[Dict[str, Any]]:
        """Get adaptation history"""
        return [self._action_to_dict(action) for action in self.adaptation_history]
    
    def get_active_adaptations(self) -> List[Dict[str, Any]]:
        """Get currently active adaptations"""
        return [self._action_to_dict(action) for action in self.active_adaptations.values()]