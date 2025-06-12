"""
Autoscaler - Automatic scaling based on metrics and rules

This module provides comprehensive autoscaling capabilities including
rule-based scaling, metric-driven decisions, custom scaling policies,
and integration with cloud provider autoscaling services.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import json
import math
from collections import defaultdict, deque

from ..circle_of_experts import CircleOfExperts, QueryRequest
from .scaling_orchestrator import ScalingAction, ScalingStrategy


class ScalingDirection(Enum):
    UP = "up"
    DOWN = "down"
    OUT = "out"
    IN = "in"


class ScalingTrigger(Enum):
    METRIC_THRESHOLD = "metric_threshold"
    SCHEDULE_BASED = "schedule_based"
    PREDICTIVE = "predictive"
    MANUAL = "manual"
    EXPERT_RECOMMENDATION = "expert_recommendation"


@dataclass
class ScalingRule:
    """Scaling rule definition"""
    rule_id: str
    name: str
    trigger: ScalingTrigger
    metric_name: str
    threshold_value: float
    comparison_operator: str  # >, <, >=, <=, ==
    scaling_direction: ScalingDirection
    scaling_amount: float
    cooldown_period: timedelta
    priority: int = 1
    enabled: bool = True
    conditions: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScalingPolicy:
    """Scaling policy configuration"""
    policy_id: str
    name: str
    rules: List[ScalingRule]
    target_resource: str
    min_capacity: float
    max_capacity: float
    default_cooldown: timedelta
    scale_up_factor: float = 1.2
    scale_down_factor: float = 0.8
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScalingEvent:
    """Scaling event record"""
    event_id: str
    timestamp: datetime
    policy_id: str
    rule_id: str
    trigger: ScalingTrigger
    action: ScalingAction
    old_capacity: float
    new_capacity: float
    metric_value: float
    threshold_value: float
    reason: str
    success: bool
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AutoscalerMetrics:
    """Autoscaler performance metrics"""
    total_scaling_events: int
    successful_events: int
    failed_events: int
    scale_up_events: int
    scale_down_events: int
    average_response_time: float
    policy_efficiency: Dict[str, float]
    recent_events: List[ScalingEvent]


class Autoscaler:
    """
    Automatic scaling system based on metrics and rules
    
    Provides rule-based autoscaling, metric monitoring, policy management,
    and integration with cloud provider autoscaling services.
    """
    
    def __init__(self, circle_of_experts: Optional[CircleOfExperts] = None):
        self.logger = logging.getLogger(__name__)
        self.circle_of_experts = circle_of_experts
        
        # Scaling configuration
        self.scaling_policies: Dict[str, ScalingPolicy] = {}
        self.scaling_rules: Dict[str, ScalingRule] = {}
        self.custom_evaluators: Dict[str, Callable] = {}
        
        # Event tracking
        self.scaling_events: deque = deque(maxlen=10000)
        self.last_scaling_times: Dict[str, datetime] = {}
        self.active_cooldowns: Dict[str, datetime] = {}
        
        # Metrics and monitoring
        self.current_metrics: Dict[str, float] = {}
        self.metric_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        
        # Autoscaler state
        self.enabled = True
        self.monitoring_interval = 30  # seconds
        self.evaluation_timeout = 10  # seconds
        
        # Performance tracking
        self.performance_metrics = AutoscalerMetrics(
            total_scaling_events=0,
            successful_events=0,
            failed_events=0,
            scale_up_events=0,
            scale_down_events=0,
            average_response_time=0.0,
            policy_efficiency={},
            recent_events=[]
        )
        
        # Initialize default policies
        self._initialize_default_policies()
        
        # Start monitoring
        self._monitoring_task = None
        if self.enabled:
            self._start_monitoring()
    
    async def execute_scaling(
        self,
        action: ScalingAction,
        target_resources: Dict[str, Any],
        strategy: ScalingStrategy
    ) -> Dict[str, Any]:
        """
        Execute scaling action
        
        Args:
            action: Scaling action to execute
            target_resources: Target resource configuration
            strategy: Scaling strategy being used
            
        Returns:
            Execution result and status
        """
        execution_start = datetime.now()
        
        try:
            # Validate scaling action
            validation_result = await self._validate_scaling_action(
                action, target_resources
            )
            
            if not validation_result['valid']:
                return {
                    'success': False,
                    'error': validation_result['reason'],
                    'execution_time': 0.0
                }
            
            # Execute based on action type
            if action == ScalingAction.SCALE_UP:
                result = await self._execute_scale_up(target_resources)
            elif action == ScalingAction.SCALE_DOWN:
                result = await self._execute_scale_down(target_resources)
            elif action == ScalingAction.SCALE_OUT:
                result = await self._execute_scale_out(target_resources)
            elif action == ScalingAction.SCALE_IN:
                result = await self._execute_scale_in(target_resources)
            elif action == ScalingAction.OPTIMIZE:
                result = await self._execute_optimize(target_resources)
            else:  # MAINTAIN
                result = {'success': True, 'message': 'No scaling action required'}
            
            execution_time = (datetime.now() - execution_start).total_seconds()
            
            # Record scaling event
            event = ScalingEvent(
                event_id=f"auto_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                timestamp=datetime.now(),
                policy_id="manual",
                rule_id="manual",
                trigger=ScalingTrigger.MANUAL,
                action=action,
                old_capacity=0.0,  # Would be retrieved from current state
                new_capacity=target_resources.get('instance_count', 0),
                metric_value=0.0,
                threshold_value=0.0,
                reason=f"Manual {action.value} execution",
                success=result.get('success', False),
                error_message=result.get('error'),
                metadata={'strategy': strategy.value, 'execution_time': execution_time}
            )
            
            self.scaling_events.append(event)
            self._update_performance_metrics(event)
            
            return {
                'success': result.get('success', False),
                'result': result,
                'execution_time': execution_time,
                'event_id': event.event_id
            }
            
        except Exception as e:
            execution_time = (datetime.now() - execution_start).total_seconds()
            self.logger.error(f"Scaling execution failed: {e}")
            
            return {
                'success': False,
                'error': str(e),
                'execution_time': execution_time
            }
    
    async def add_scaling_policy(
        self,
        policy: ScalingPolicy
    ) -> bool:
        """Add a new scaling policy"""
        try:
            # Validate policy
            if not await self._validate_scaling_policy(policy):
                return False
            
            self.scaling_policies[policy.policy_id] = policy
            
            # Add individual rules
            for rule in policy.rules:
                self.scaling_rules[rule.rule_id] = rule
            
            self.logger.info(f"Added scaling policy: {policy.policy_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add scaling policy: {e}")
            return False
    
    async def add_scaling_rule(
        self,
        rule: ScalingRule,
        policy_id: Optional[str] = None
    ) -> bool:
        """Add a new scaling rule"""
        try:
            # Validate rule
            if not await self._validate_scaling_rule(rule):
                return False
            
            self.scaling_rules[rule.rule_id] = rule
            
            # Add to policy if specified
            if policy_id and policy_id in self.scaling_policies:
                policy = self.scaling_policies[policy_id]
                if rule not in policy.rules:
                    policy.rules.append(rule)
            
            self.logger.info(f"Added scaling rule: {rule.rule_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add scaling rule: {e}")
            return False
    
    async def update_metrics(self, metrics: Dict[str, float]):
        """Update current metrics for autoscaling evaluation"""
        self.current_metrics.update(metrics)
        
        # Store in history
        timestamp = datetime.now()
        for metric_name, value in metrics.items():
            self.metric_history[metric_name].append((timestamp, value))
        
        # Trigger evaluation if monitoring is not running
        if not self._monitoring_task or self._monitoring_task.done():
            await self._evaluate_scaling_rules()
    
    async def evaluate_scaling_rules(self) -> List[Dict[str, Any]]:
        """Manually evaluate all scaling rules"""
        return await self._evaluate_scaling_rules()
    
    async def get_autoscaler_status(self) -> Dict[str, Any]:
        """Get current autoscaler status and metrics"""
        return {
            'enabled': self.enabled,
            'monitoring_interval': self.monitoring_interval,
            'active_policies': len(self.scaling_policies),
            'active_rules': len(self.scaling_rules),
            'current_metrics': self.current_metrics,
            'active_cooldowns': {
                resource: (cooldown_end - datetime.now()).total_seconds()
                for resource, cooldown_end in self.active_cooldowns.items()
                if cooldown_end > datetime.now()
            },
            'performance_metrics': {
                'total_events': self.performance_metrics.total_scaling_events,
                'success_rate': (self.performance_metrics.successful_events / 
                               max(1, self.performance_metrics.total_scaling_events) * 100),
                'scale_up_events': self.performance_metrics.scale_up_events,
                'scale_down_events': self.performance_metrics.scale_down_events,
                'average_response_time': self.performance_metrics.average_response_time
            },
            'recent_events': [
                {
                    'event_id': event.event_id,
                    'timestamp': event.timestamp.isoformat(),
                    'action': event.action.value,
                    'success': event.success,
                    'reason': event.reason
                }
                for event in list(self.scaling_events)[-10:]
            ]
        }
    
    async def _start_monitoring(self):
        """Start automatic monitoring and evaluation"""
        if self._monitoring_task and not self._monitoring_task.done():
            return
        
        self._monitoring_task = asyncio.create_task(self._monitoring_loop())
    
    async def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.enabled:
            try:
                await self._evaluate_scaling_rules()
                await asyncio.sleep(self.monitoring_interval)
            except Exception as e:
                self.logger.error(f"Monitoring loop error: {e}")
                await asyncio.sleep(self.monitoring_interval)
    
    async def _evaluate_scaling_rules(self) -> List[Dict[str, Any]]:
        """Evaluate all scaling rules and trigger actions"""
        evaluation_results = []
        
        for policy_id, policy in self.scaling_policies.items():
            if not policy.enabled:
                continue
            
            try:
                policy_results = await self._evaluate_policy(policy)
                evaluation_results.extend(policy_results)
            except Exception as e:
                self.logger.error(f"Policy evaluation failed for {policy_id}: {e}")
        
        return evaluation_results
    
    async def _evaluate_policy(self, policy: ScalingPolicy) -> List[Dict[str, Any]]:
        """Evaluate a specific scaling policy"""
        results = []
        
        for rule in policy.rules:
            if not rule.enabled:
                continue
            
            try:
                # Check cooldown
                if await self._is_in_cooldown(rule, policy):
                    continue
                
                # Evaluate rule condition
                evaluation = await self._evaluate_rule_condition(rule)
                
                if evaluation['triggered']:
                    # Execute scaling action
                    scaling_result = await self._execute_rule_action(rule, policy, evaluation)
                    results.append({
                        'rule_id': rule.rule_id,
                        'policy_id': policy.policy_id,
                        'triggered': True,
                        'action_taken': scaling_result['action_taken'],
                        'success': scaling_result['success'],
                        'details': scaling_result
                    })
                    
                    # Set cooldown
                    self.active_cooldowns[f"{policy.policy_id}_{rule.rule_id}"] = (
                        datetime.now() + rule.cooldown_period
                    )
                else:
                    results.append({
                        'rule_id': rule.rule_id,
                        'policy_id': policy.policy_id,
                        'triggered': False,
                        'reason': evaluation['reason']
                    })
                    
            except Exception as e:
                self.logger.error(f"Rule evaluation failed for {rule.rule_id}: {e}")
                results.append({
                    'rule_id': rule.rule_id,
                    'policy_id': policy.policy_id,
                    'triggered': False,
                    'error': str(e)
                })
        
        return results
    
    async def _evaluate_rule_condition(self, rule: ScalingRule) -> Dict[str, Any]:
        """Evaluate if a rule condition is met"""
        try:
            # Get current metric value
            if rule.metric_name not in self.current_metrics:
                return {
                    'triggered': False,
                    'reason': f"Metric {rule.metric_name} not available"
                }
            
            current_value = self.current_metrics[rule.metric_name]
            threshold = rule.threshold_value
            operator = rule.comparison_operator
            
            # Evaluate condition
            triggered = False
            if operator == '>':
                triggered = current_value > threshold
            elif operator == '>=':
                triggered = current_value >= threshold
            elif operator == '<':
                triggered = current_value < threshold
            elif operator == '<=':
                triggered = current_value <= threshold
            elif operator == '==':
                triggered = abs(current_value - threshold) < 0.001
            
            # Check additional conditions
            if triggered and rule.conditions:
                additional_check = await self._check_additional_conditions(rule.conditions)
                triggered = triggered and additional_check
            
            return {
                'triggered': triggered,
                'current_value': current_value,
                'threshold_value': threshold,
                'operator': operator,
                'reason': f"Current: {current_value}, Threshold: {threshold}, Op: {operator}"
            }
            
        except Exception as e:
            return {
                'triggered': False,
                'reason': f"Evaluation error: {str(e)}"
            }
    
    async def _execute_rule_action(
        self,
        rule: ScalingRule,
        policy: ScalingPolicy,
        evaluation: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute scaling action for a triggered rule"""
        try:
            # Determine scaling action
            if rule.scaling_direction == ScalingDirection.UP:
                action = ScalingAction.SCALE_UP
            elif rule.scaling_direction == ScalingDirection.DOWN:
                action = ScalingAction.SCALE_DOWN
            elif rule.scaling_direction == ScalingDirection.OUT:
                action = ScalingAction.SCALE_OUT
            elif rule.scaling_direction == ScalingDirection.IN:
                action = ScalingAction.SCALE_IN
            else:
                action = ScalingAction.MAINTAIN
            
            # Calculate new capacity
            current_capacity = self._get_current_capacity(policy.target_resource)
            
            if rule.scaling_direction in [ScalingDirection.UP, ScalingDirection.OUT]:
                new_capacity = min(
                    current_capacity * policy.scale_up_factor,
                    policy.max_capacity
                )
            else:
                new_capacity = max(
                    current_capacity * policy.scale_down_factor,
                    policy.min_capacity
                )
            
            # Apply scaling amount
            if rule.scaling_amount > 0:
                if rule.scaling_direction in [ScalingDirection.UP, ScalingDirection.OUT]:
                    new_capacity = min(current_capacity + rule.scaling_amount, policy.max_capacity)
                else:
                    new_capacity = max(current_capacity - rule.scaling_amount, policy.min_capacity)
            
            # Execute scaling
            target_resources = {
                'instance_count': int(new_capacity),
                'target_resource': policy.target_resource
            }
            
            execution_result = await self.execute_scaling(
                action, target_resources, ScalingStrategy.REACTIVE
            )
            
            # Record event
            event = ScalingEvent(
                event_id=f"rule_{rule.rule_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                timestamp=datetime.now(),
                policy_id=policy.policy_id,
                rule_id=rule.rule_id,
                trigger=rule.trigger,
                action=action,
                old_capacity=current_capacity,
                new_capacity=new_capacity,
                metric_value=evaluation['current_value'],
                threshold_value=evaluation['threshold_value'],
                reason=f"Rule {rule.name} triggered",
                success=execution_result['success'],
                error_message=execution_result.get('error'),
                metadata={'evaluation': evaluation}
            )
            
            self.scaling_events.append(event)
            self._update_performance_metrics(event)
            
            return {
                'action_taken': action.value,
                'success': execution_result['success'],
                'old_capacity': current_capacity,
                'new_capacity': new_capacity,
                'execution_result': execution_result,
                'event_id': event.event_id
            }
            
        except Exception as e:
            self.logger.error(f"Rule action execution failed: {e}")
            return {
                'action_taken': 'none',
                'success': False,
                'error': str(e)
            }
    
    async def _validate_scaling_action(
        self,
        action: ScalingAction,
        target_resources: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Validate scaling action before execution"""
        # Basic validation
        if not target_resources:
            return {'valid': False, 'reason': 'No target resources specified'}
        
        # Check resource limits
        instance_count = target_resources.get('instance_count', 1)
        if instance_count < 1:
            return {'valid': False, 'reason': 'Instance count cannot be less than 1'}
        
        if instance_count > 1000:  # Arbitrary upper limit
            return {'valid': False, 'reason': 'Instance count exceeds maximum limit'}
        
        return {'valid': True, 'reason': 'Validation passed'}
    
    async def _execute_scale_up(self, target_resources: Dict[str, Any]) -> Dict[str, Any]:
        """Execute scale up action"""
        try:
            # Simulate scaling up
            instance_count = target_resources.get('instance_count', 1)
            
            # In practice, this would interact with cloud provider APIs
            self.logger.info(f"Scaling up to {instance_count} instances")
            
            # Simulate some processing time
            await asyncio.sleep(0.1)
            
            return {
                'success': True,
                'message': f'Successfully scaled up to {instance_count} instances',
                'new_capacity': instance_count
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def _execute_scale_down(self, target_resources: Dict[str, Any]) -> Dict[str, Any]:
        """Execute scale down action"""
        try:
            instance_count = target_resources.get('instance_count', 1)
            
            self.logger.info(f"Scaling down to {instance_count} instances")
            await asyncio.sleep(0.1)
            
            return {
                'success': True,
                'message': f'Successfully scaled down to {instance_count} instances',
                'new_capacity': instance_count
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def _execute_scale_out(self, target_resources: Dict[str, Any]) -> Dict[str, Any]:
        """Execute scale out action (horizontal scaling)"""
        return await self._execute_scale_up(target_resources)
    
    async def _execute_scale_in(self, target_resources: Dict[str, Any]) -> Dict[str, Any]:
        """Execute scale in action (horizontal scaling)"""
        return await self._execute_scale_down(target_resources)
    
    async def _execute_optimize(self, target_resources: Dict[str, Any]) -> Dict[str, Any]:
        """Execute optimization action"""
        try:
            self.logger.info("Executing resource optimization")
            
            # Simulate optimization
            await asyncio.sleep(0.1)
            
            return {
                'success': True,
                'message': 'Resource optimization completed',
                'optimizations_applied': ['cpu_tuning', 'memory_optimization']
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _get_current_capacity(self, resource_name: str) -> float:
        """Get current capacity for a resource"""
        # In practice, this would query the actual resource state
        return self.current_metrics.get(f"{resource_name}_capacity", 1.0)
    
    async def _is_in_cooldown(self, rule: ScalingRule, policy: ScalingPolicy) -> bool:
        """Check if rule is in cooldown period"""
        cooldown_key = f"{policy.policy_id}_{rule.rule_id}"
        
        if cooldown_key in self.active_cooldowns:
            return datetime.now() < self.active_cooldowns[cooldown_key]
        
        return False
    
    async def _check_additional_conditions(self, conditions: Dict[str, Any]) -> bool:
        """Check additional rule conditions"""
        # Simple condition checking
        for condition_name, condition_value in conditions.items():
            if condition_name in self.current_metrics:
                if self.current_metrics[condition_name] != condition_value:
                    return False
        
        return True
    
    def _update_performance_metrics(self, event: ScalingEvent):
        """Update autoscaler performance metrics"""
        self.performance_metrics.total_scaling_events += 1
        
        if event.success:
            self.performance_metrics.successful_events += 1
        else:
            self.performance_metrics.failed_events += 1
        
        if event.action in [ScalingAction.SCALE_UP, ScalingAction.SCALE_OUT]:
            self.performance_metrics.scale_up_events += 1
        elif event.action in [ScalingAction.SCALE_DOWN, ScalingAction.SCALE_IN]:
            self.performance_metrics.scale_down_events += 1
        
        # Update recent events
        self.performance_metrics.recent_events.append(event)
        if len(self.performance_metrics.recent_events) > 100:
            self.performance_metrics.recent_events = self.performance_metrics.recent_events[-100:]
    
    def _initialize_default_policies(self):
        """Initialize default scaling policies"""
        # CPU-based scaling policy
        cpu_scale_up_rule = ScalingRule(
            rule_id="cpu_scale_up",
            name="CPU Scale Up",
            trigger=ScalingTrigger.METRIC_THRESHOLD,
            metric_name="cpu_utilization",
            threshold_value=80.0,
            comparison_operator=">",
            scaling_direction=ScalingDirection.UP,
            scaling_amount=1.0,
            cooldown_period=timedelta(minutes=5)
        )
        
        cpu_scale_down_rule = ScalingRule(
            rule_id="cpu_scale_down",
            name="CPU Scale Down",
            trigger=ScalingTrigger.METRIC_THRESHOLD,
            metric_name="cpu_utilization",
            threshold_value=20.0,
            comparison_operator="<",
            scaling_direction=ScalingDirection.DOWN,
            scaling_amount=1.0,
            cooldown_period=timedelta(minutes=10)
        )
        
        cpu_policy = ScalingPolicy(
            policy_id="default_cpu_policy",
            name="Default CPU Scaling Policy",
            rules=[cpu_scale_up_rule, cpu_scale_down_rule],
            target_resource="compute_instances",
            min_capacity=1.0,
            max_capacity=10.0,
            default_cooldown=timedelta(minutes=5)
        )
        
        # Memory-based scaling policy
        memory_scale_up_rule = ScalingRule(
            rule_id="memory_scale_up",
            name="Memory Scale Up",
            trigger=ScalingTrigger.METRIC_THRESHOLD,
            metric_name="memory_utilization",
            threshold_value=85.0,
            comparison_operator=">",
            scaling_direction=ScalingDirection.UP,
            scaling_amount=1.0,
            cooldown_period=timedelta(minutes=5)
        )
        
        memory_policy = ScalingPolicy(
            policy_id="default_memory_policy",
            name="Default Memory Scaling Policy",
            rules=[memory_scale_up_rule],
            target_resource="compute_instances",
            min_capacity=1.0,
            max_capacity=10.0,
            default_cooldown=timedelta(minutes=5)
        )
        
        # Add policies
        self.scaling_policies[cpu_policy.policy_id] = cpu_policy
        self.scaling_policies[memory_policy.policy_id] = memory_policy
        
        # Add rules
        for policy in [cpu_policy, memory_policy]:
            for rule in policy.rules:
                self.scaling_rules[rule.rule_id] = rule
    
    async def _validate_scaling_policy(self, policy: ScalingPolicy) -> bool:
        """Validate scaling policy configuration"""
        if policy.min_capacity >= policy.max_capacity:
            self.logger.error("Min capacity must be less than max capacity")
            return False
        
        if not policy.rules:
            self.logger.error("Policy must have at least one rule")
            return False
        
        return True
    
    async def _validate_scaling_rule(self, rule: ScalingRule) -> bool:
        """Validate scaling rule configuration"""
        valid_operators = ['>', '>=', '<', '<=', '==']
        if rule.comparison_operator not in valid_operators:
            self.logger.error(f"Invalid comparison operator: {rule.comparison_operator}")
            return False
        
        if rule.cooldown_period.total_seconds() < 0:
            self.logger.error("Cooldown period cannot be negative")
            return False
        
        return True
    
    def stop_monitoring(self):
        """Stop automatic monitoring"""
        self.enabled = False
        if self._monitoring_task and not self._monitoring_task.done():
            self._monitoring_task.cancel()
    
    def cleanup(self):
        """Cleanup autoscaler resources"""
        self.stop_monitoring()