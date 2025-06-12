"""
Scaling Orchestrator - Central scaling coordination and control system

This module provides the main orchestration layer for dynamic scaling operations
across multiple cloud providers and infrastructure types.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json

try:
    from ...src.circle_of_experts import CircleOfExperts, QueryRequest
except ImportError:
    try:
        from src.circle_of_experts import CircleOfExperts, QueryRequest
    except ImportError:
        # Mock classes if not available
        class CircleOfExperts:
            async def process_query(self, query):
                class MockResponse:
                    def __init__(self):
                        self.expert_responses = []
                return MockResponse()
        
        class QueryRequest:
            def __init__(self, **kwargs):
                pass
from .resource_manager import ResourceManager
from .cost_optimizer import CostOptimizer
from .capacity_planner import CapacityPlanner
from .autoscaler import Autoscaler


class ScalingAction(Enum):
    SCALE_UP = "scale_up"
    SCALE_DOWN = "scale_down"
    SCALE_OUT = "scale_out"
    SCALE_IN = "scale_in"
    OPTIMIZE = "optimize"
    MAINTAIN = "maintain"


class ScalingStrategy(Enum):
    REACTIVE = "reactive"
    PREDICTIVE = "predictive"
    EXPERT_DRIVEN = "expert_driven"
    COST_AWARE = "cost_aware"
    PERFORMANCE_FOCUSED = "performance_focused"


@dataclass
class ScalingDecision:
    """Represents a scaling decision with context and metadata"""
    action: ScalingAction
    strategy: ScalingStrategy
    target_resources: Dict[str, Any]
    confidence: float
    estimated_cost: float
    expected_performance: Dict[str, float]
    expert_recommendations: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ScalingMetrics:
    """Current scaling metrics and status"""
    cpu_utilization: float
    memory_utilization: float
    network_io: float
    disk_io: float
    active_connections: int
    queue_depth: int
    response_time: float
    error_rate: float
    cost_per_hour: float
    timestamp: datetime = field(default_factory=datetime.now)


class ScalingOrchestrator:
    """
    Central scaling coordination and control system
    
    Coordinates scaling decisions across multiple providers and strategies,
    integrating expert recommendations and cost optimization.
    """
    
    def __init__(
        self,
        resource_manager: Optional[ResourceManager] = None,
        cost_optimizer: Optional[CostOptimizer] = None,
        capacity_planner: Optional[CapacityPlanner] = None,
        autoscaler: Optional[Autoscaler] = None,
        circle_of_experts: Optional[CircleOfExperts] = None
    ):
        self.logger = logging.getLogger(__name__)
        self.resource_manager = resource_manager or ResourceManager()
        self.cost_optimizer = cost_optimizer or CostOptimizer()
        self.capacity_planner = capacity_planner or CapacityPlanner()
        self.autoscaler = autoscaler or Autoscaler()
        self.circle_of_experts = circle_of_experts
        
        # Scaling configuration
        self.scaling_policies: Dict[str, Dict] = {}
        self.active_strategies: List[ScalingStrategy] = [
            ScalingStrategy.REACTIVE,
            ScalingStrategy.COST_AWARE
        ]
        
        # State tracking
        self.current_metrics: Optional[ScalingMetrics] = None
        self.scaling_history: List[ScalingDecision] = []
        self.active_scaling_operations: Dict[str, Dict] = {}
        
        # Thresholds and limits
        self.scaling_thresholds = {
            'cpu_high': 80.0,
            'cpu_low': 20.0,
            'memory_high': 85.0,
            'memory_low': 25.0,
            'response_time_high': 2.0,
            'error_rate_high': 5.0
        }
        
        self.scaling_limits = {
            'max_instances': 100,
            'min_instances': 1,
            'max_cost_per_hour': 1000.0,
            'scaling_cooldown': 300  # 5 minutes
        }
    
    async def orchestrate_scaling(
        self,
        metrics: ScalingMetrics,
        workload_forecast: Optional[Dict] = None
    ) -> ScalingDecision:
        """
        Main orchestration method for scaling decisions
        
        Args:
            metrics: Current system metrics
            workload_forecast: Optional workload forecast data
            
        Returns:
            ScalingDecision with recommended actions
        """
        self.current_metrics = metrics
        
        try:
            # Analyze current state
            scaling_need = await self._analyze_scaling_need(metrics)
            
            # Get expert recommendations if available
            expert_recommendations = await self._get_expert_recommendations(
                metrics, scaling_need
            )
            
            # Generate scaling options
            scaling_options = await self._generate_scaling_options(
                metrics, scaling_need, expert_recommendations
            )
            
            # Select optimal scaling decision
            decision = await self._select_optimal_decision(
                scaling_options, expert_recommendations
            )
            
            # Validate and apply scaling decision
            validated_decision = await self._validate_scaling_decision(decision)
            
            if validated_decision:
                await self._execute_scaling_decision(validated_decision)
                self.scaling_history.append(validated_decision)
            
            return validated_decision or decision
            
        except Exception as e:
            self.logger.error(f"Error in scaling orchestration: {e}")
            return ScalingDecision(
                action=ScalingAction.MAINTAIN,
                strategy=ScalingStrategy.REACTIVE,
                target_resources={},
                confidence=0.0,
                estimated_cost=0.0,
                expected_performance={},
                metadata={'error': str(e)}
            )
    
    async def _analyze_scaling_need(self, metrics: ScalingMetrics) -> Dict[str, Any]:
        """Analyze current metrics to determine scaling needs"""
        scaling_need = {
            'urgency': 'normal',
            'direction': 'maintain',
            'factors': [],
            'severity': 0.0
        }
        
        # CPU analysis
        if metrics.cpu_utilization > self.scaling_thresholds['cpu_high']:
            scaling_need['factors'].append('high_cpu')
            scaling_need['direction'] = 'scale_up'
            scaling_need['severity'] = max(scaling_need['severity'], 
                                         (metrics.cpu_utilization - self.scaling_thresholds['cpu_high']) / 20.0)
        elif metrics.cpu_utilization < self.scaling_thresholds['cpu_low']:
            scaling_need['factors'].append('low_cpu')
            scaling_need['direction'] = 'scale_down'
        
        # Memory analysis
        if metrics.memory_utilization > self.scaling_thresholds['memory_high']:
            scaling_need['factors'].append('high_memory')
            scaling_need['direction'] = 'scale_up'
            scaling_need['severity'] = max(scaling_need['severity'],
                                         (metrics.memory_utilization - self.scaling_thresholds['memory_high']) / 15.0)
        elif metrics.memory_utilization < self.scaling_thresholds['memory_low']:
            scaling_need['factors'].append('low_memory')
            if scaling_need['direction'] != 'scale_up':
                scaling_need['direction'] = 'scale_down'
        
        # Performance analysis
        if metrics.response_time > self.scaling_thresholds['response_time_high']:
            scaling_need['factors'].append('high_response_time')
            scaling_need['direction'] = 'scale_up'
            scaling_need['urgency'] = 'high'
            scaling_need['severity'] = max(scaling_need['severity'], 0.8)
        
        if metrics.error_rate > self.scaling_thresholds['error_rate_high']:
            scaling_need['factors'].append('high_error_rate')
            scaling_need['direction'] = 'scale_up'
            scaling_need['urgency'] = 'critical'
            scaling_need['severity'] = 1.0
        
        return scaling_need
    
    async def _get_expert_recommendations(
        self,
        metrics: ScalingMetrics,
        scaling_need: Dict[str, Any]
    ) -> List[str]:
        """Get expert recommendations for scaling decisions"""
        if not self.circle_of_experts:
            return []
        
        try:
            query = QueryRequest(
                query=f"""
                Given these system metrics and scaling analysis, what scaling recommendations do you have?
                
                Current Metrics:
                - CPU Utilization: {metrics.cpu_utilization}%
                - Memory Utilization: {metrics.memory_utilization}%
                - Response Time: {metrics.response_time}s
                - Error Rate: {metrics.error_rate}%
                - Cost per Hour: ${metrics.cost_per_hour}
                
                Scaling Analysis:
                - Direction: {scaling_need['direction']}
                - Urgency: {scaling_need['urgency']}
                - Factors: {', '.join(scaling_need['factors'])}
                - Severity: {scaling_need['severity']}
                
                Please provide specific recommendations for:
                1. Scaling strategy (reactive, predictive, cost-aware)
                2. Resource allocation adjustments
                3. Cost optimization opportunities
                4. Performance improvement suggestions
                """,
                experts=["scalability_expert", "performance_expert", "cost_optimization_expert"],
                require_consensus=False
            )
            
            response = await self.circle_of_experts.process_query(query)
            return [resp.content for resp in response.expert_responses]
            
        except Exception as e:
            self.logger.warning(f"Failed to get expert recommendations: {e}")
            return []
    
    async def _generate_scaling_options(
        self,
        metrics: ScalingMetrics,
        scaling_need: Dict[str, Any],
        expert_recommendations: List[str]
    ) -> List[ScalingDecision]:
        """Generate multiple scaling options for evaluation"""
        options = []
        
        # Reactive scaling option
        reactive_option = await self._generate_reactive_option(metrics, scaling_need)
        options.append(reactive_option)
        
        # Predictive scaling option
        predictive_option = await self._generate_predictive_option(metrics, scaling_need)
        options.append(predictive_option)
        
        # Cost-aware scaling option
        cost_aware_option = await self._generate_cost_aware_option(metrics, scaling_need)
        options.append(cost_aware_option)
        
        # Expert-driven option if recommendations available
        if expert_recommendations:
            expert_option = await self._generate_expert_option(
                metrics, scaling_need, expert_recommendations
            )
            options.append(expert_option)
        
        return options
    
    async def _generate_reactive_option(
        self,
        metrics: ScalingMetrics,
        scaling_need: Dict[str, Any]
    ) -> ScalingDecision:
        """Generate reactive scaling option based on current metrics"""
        current_resources = await self.resource_manager.get_current_resources()
        
        if scaling_need['direction'] == 'scale_up':
            action = ScalingAction.SCALE_UP
            target_resources = await self._calculate_scale_up_resources(
                current_resources, scaling_need['severity']
            )
        elif scaling_need['direction'] == 'scale_down':
            action = ScalingAction.SCALE_DOWN
            target_resources = await self._calculate_scale_down_resources(
                current_resources, metrics
            )
        else:
            action = ScalingAction.MAINTAIN
            target_resources = current_resources
        
        estimated_cost = await self.cost_optimizer.estimate_cost(target_resources)
        
        return ScalingDecision(
            action=action,
            strategy=ScalingStrategy.REACTIVE,
            target_resources=target_resources,
            confidence=0.8,
            estimated_cost=estimated_cost,
            expected_performance={
                'response_time': max(0.5, metrics.response_time * 0.8),
                'throughput': metrics.active_connections * 1.2
            }
        )
    
    async def _generate_predictive_option(
        self,
        metrics: ScalingMetrics,
        scaling_need: Dict[str, Any]
    ) -> ScalingDecision:
        """Generate predictive scaling option based on forecasting"""
        forecast = await self.capacity_planner.generate_forecast(
            current_metrics=metrics,
            horizon_hours=2
        )
        
        current_resources = await self.resource_manager.get_current_resources()
        
        # Adjust resources based on forecast
        if forecast['predicted_load_increase'] > 0.3:
            action = ScalingAction.SCALE_UP
            target_resources = await self._calculate_predictive_resources(
                current_resources, forecast
            )
        elif forecast['predicted_load_decrease'] > 0.3:
            action = ScalingAction.SCALE_DOWN
            target_resources = await self._calculate_predictive_resources(
                current_resources, forecast
            )
        else:
            action = ScalingAction.MAINTAIN
            target_resources = current_resources
        
        estimated_cost = await self.cost_optimizer.estimate_cost(target_resources)
        
        return ScalingDecision(
            action=action,
            strategy=ScalingStrategy.PREDICTIVE,
            target_resources=target_resources,
            confidence=forecast.get('confidence', 0.7),
            estimated_cost=estimated_cost,
            expected_performance={
                'response_time': forecast.get('predicted_response_time', metrics.response_time),
                'throughput': forecast.get('predicted_throughput', metrics.active_connections)
            },
            metadata={'forecast': forecast}
        )
    
    async def _generate_cost_aware_option(
        self,
        metrics: ScalingMetrics,
        scaling_need: Dict[str, Any]
    ) -> ScalingDecision:
        """Generate cost-optimized scaling option"""
        current_resources = await self.resource_manager.get_current_resources()
        
        # Get cost optimization recommendations
        cost_recommendations = await self.cost_optimizer.optimize_resources(
            current_resources, metrics
        )
        
        target_resources = cost_recommendations.get('optimized_resources', current_resources)
        
        # Determine action based on cost optimization
        if cost_recommendations.get('cost_savings', 0) > 0.1:  # >10% savings
            action = ScalingAction.OPTIMIZE
        elif scaling_need['urgency'] == 'critical':
            action = ScalingAction.SCALE_UP
        else:
            action = ScalingAction.MAINTAIN
        
        estimated_cost = cost_recommendations.get('estimated_cost', metrics.cost_per_hour)
        
        return ScalingDecision(
            action=action,
            strategy=ScalingStrategy.COST_AWARE,
            target_resources=target_resources,
            confidence=0.9,
            estimated_cost=estimated_cost,
            expected_performance={
                'response_time': metrics.response_time * 1.1,  # Slight performance trade-off
                'cost_savings': cost_recommendations.get('cost_savings', 0)
            },
            metadata={'cost_recommendations': cost_recommendations}
        )
    
    async def _generate_expert_option(
        self,
        metrics: ScalingMetrics,
        scaling_need: Dict[str, Any],
        expert_recommendations: List[str]
    ) -> ScalingDecision:
        """Generate expert-driven scaling option"""
        current_resources = await self.resource_manager.get_current_resources()
        
        # Parse expert recommendations (simplified - in practice would use NLP)
        parsed_recommendations = await self._parse_expert_recommendations(
            expert_recommendations
        )
        
        target_resources = await self._apply_expert_recommendations(
            current_resources, parsed_recommendations
        )
        
        estimated_cost = await self.cost_optimizer.estimate_cost(target_resources)
        
        return ScalingDecision(
            action=ScalingAction.OPTIMIZE,
            strategy=ScalingStrategy.EXPERT_DRIVEN,
            target_resources=target_resources,
            confidence=0.95,
            estimated_cost=estimated_cost,
            expected_performance={
                'response_time': metrics.response_time * 0.7,
                'throughput': metrics.active_connections * 1.5
            },
            expert_recommendations=expert_recommendations,
            metadata={'parsed_recommendations': parsed_recommendations}
        )
    
    async def _select_optimal_decision(
        self,
        options: List[ScalingDecision],
        expert_recommendations: List[str]
    ) -> ScalingDecision:
        """Select the optimal scaling decision from available options"""
        if not options:
            return ScalingDecision(
                action=ScalingAction.MAINTAIN,
                strategy=ScalingStrategy.REACTIVE,
                target_resources={},
                confidence=0.0,
                estimated_cost=0.0,
                expected_performance={}
            )
        
        # Score each option based on multiple criteria
        scored_options = []
        for option in options:
            score = await self._score_scaling_option(option)
            scored_options.append((score, option))
        
        # Sort by score and return the best option
        scored_options.sort(key=lambda x: x[0], reverse=True)
        return scored_options[0][1]
    
    async def _score_scaling_option(self, option: ScalingDecision) -> float:
        """Score a scaling option based on multiple criteria"""
        score = 0.0
        
        # Confidence weight
        score += option.confidence * 0.3
        
        # Cost efficiency weight
        if option.estimated_cost > 0:
            cost_efficiency = 1.0 / (1.0 + option.estimated_cost / 100.0)
            score += cost_efficiency * 0.3
        
        # Performance weight
        performance_score = 0.0
        if 'response_time' in option.expected_performance:
            # Lower response time is better
            performance_score += 1.0 / (1.0 + option.expected_performance['response_time'])
        if 'throughput' in option.expected_performance:
            # Higher throughput is better
            performance_score += min(1.0, option.expected_performance['throughput'] / 1000.0)
        score += (performance_score / 2.0) * 0.3
        
        # Strategy preference weight
        strategy_weights = {
            ScalingStrategy.EXPERT_DRIVEN: 1.0,
            ScalingStrategy.PREDICTIVE: 0.9,
            ScalingStrategy.COST_AWARE: 0.8,
            ScalingStrategy.REACTIVE: 0.7,
            ScalingStrategy.PERFORMANCE_FOCUSED: 0.8
        }
        score += strategy_weights.get(option.strategy, 0.5) * 0.1
        
        return score
    
    async def _validate_scaling_decision(
        self,
        decision: ScalingDecision
    ) -> Optional[ScalingDecision]:
        """Validate scaling decision against limits and constraints"""
        # Check cost limits
        if decision.estimated_cost > self.scaling_limits['max_cost_per_hour']:
            self.logger.warning(f"Scaling decision exceeds cost limit: {decision.estimated_cost}")
            return None
        
        # Check instance limits
        instance_count = decision.target_resources.get('instance_count', 1)
        if instance_count > self.scaling_limits['max_instances']:
            decision.target_resources['instance_count'] = self.scaling_limits['max_instances']
        elif instance_count < self.scaling_limits['min_instances']:
            decision.target_resources['instance_count'] = self.scaling_limits['min_instances']
        
        # Check cooldown period
        if await self._is_in_cooldown_period():
            self.logger.info("Scaling operation skipped due to cooldown period")
            return None
        
        return decision
    
    async def _execute_scaling_decision(self, decision: ScalingDecision):
        """Execute the scaling decision"""
        operation_id = f"scaling_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        self.active_scaling_operations[operation_id] = {
            'decision': decision,
            'status': 'executing',
            'start_time': datetime.now()
        }
        
        try:
            # Execute through autoscaler
            result = await self.autoscaler.execute_scaling(
                decision.action,
                decision.target_resources,
                decision.strategy
            )
            
            self.active_scaling_operations[operation_id]['status'] = 'completed'
            self.active_scaling_operations[operation_id]['result'] = result
            
            self.logger.info(f"Scaling operation {operation_id} completed successfully")
            
        except Exception as e:
            self.active_scaling_operations[operation_id]['status'] = 'failed'
            self.active_scaling_operations[operation_id]['error'] = str(e)
            
            self.logger.error(f"Scaling operation {operation_id} failed: {e}")
            raise
    
    async def _calculate_scale_up_resources(
        self,
        current_resources: Dict[str, Any],
        severity: float
    ) -> Dict[str, Any]:
        """Calculate target resources for scaling up"""
        target_resources = current_resources.copy()
        
        # Scale based on severity
        scale_factor = 1.0 + (severity * 0.5)  # Max 50% increase
        
        if 'instance_count' in current_resources:
            new_count = int(current_resources['instance_count'] * scale_factor)
            target_resources['instance_count'] = min(
                new_count, self.scaling_limits['max_instances']
            )
        
        if 'cpu_cores' in current_resources:
            target_resources['cpu_cores'] = int(
                current_resources['cpu_cores'] * scale_factor
            )
        
        if 'memory_gb' in current_resources:
            target_resources['memory_gb'] = int(
                current_resources['memory_gb'] * scale_factor
            )
        
        return target_resources
    
    async def _calculate_scale_down_resources(
        self,
        current_resources: Dict[str, Any],
        metrics: ScalingMetrics
    ) -> Dict[str, Any]:
        """Calculate target resources for scaling down"""
        target_resources = current_resources.copy()
        
        # Conservative scale down to avoid thrashing
        scale_factor = 0.8
        
        if 'instance_count' in current_resources:
            new_count = int(current_resources['instance_count'] * scale_factor)
            target_resources['instance_count'] = max(
                new_count, self.scaling_limits['min_instances']
            )
        
        return target_resources
    
    async def _calculate_predictive_resources(
        self,
        current_resources: Dict[str, Any],
        forecast: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Calculate target resources based on predictive forecast"""
        target_resources = current_resources.copy()
        
        load_change = forecast.get('predicted_load_change', 0.0)
        scale_factor = 1.0 + load_change
        
        if 'instance_count' in current_resources:
            new_count = int(current_resources['instance_count'] * scale_factor)
            target_resources['instance_count'] = max(
                self.scaling_limits['min_instances'],
                min(new_count, self.scaling_limits['max_instances'])
            )
        
        return target_resources
    
    async def _parse_expert_recommendations(
        self,
        recommendations: List[str]
    ) -> Dict[str, Any]:
        """Parse expert recommendations into actionable items"""
        parsed = {
            'scale_direction': 'maintain',
            'resource_adjustments': {},
            'strategy_suggestions': [],
            'cost_optimizations': []
        }
        
        # Simple keyword-based parsing (in practice would use NLP)
        combined_text = ' '.join(recommendations).lower()
        
        if 'scale up' in combined_text or 'increase' in combined_text:
            parsed['scale_direction'] = 'up'
        elif 'scale down' in combined_text or 'decrease' in combined_text:
            parsed['scale_direction'] = 'down'
        
        if 'cpu' in combined_text:
            parsed['resource_adjustments']['focus_cpu'] = True
        if 'memory' in combined_text:
            parsed['resource_adjustments']['focus_memory'] = True
        
        return parsed
    
    async def _apply_expert_recommendations(
        self,
        current_resources: Dict[str, Any],
        recommendations: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Apply expert recommendations to resource configuration"""
        target_resources = current_resources.copy()
        
        if recommendations['scale_direction'] == 'up':
            if 'instance_count' in current_resources:
                target_resources['instance_count'] = min(
                    int(current_resources['instance_count'] * 1.3),
                    self.scaling_limits['max_instances']
                )
        elif recommendations['scale_direction'] == 'down':
            if 'instance_count' in current_resources:
                target_resources['instance_count'] = max(
                    int(current_resources['instance_count'] * 0.8),
                    self.scaling_limits['min_instances']
                )
        
        return target_resources
    
    async def _is_in_cooldown_period(self) -> bool:
        """Check if system is in scaling cooldown period"""
        if not self.scaling_history:
            return False
        
        last_scaling = self.scaling_history[-1]
        cooldown_end = last_scaling.timestamp + timedelta(
            seconds=self.scaling_limits['scaling_cooldown']
        )
        
        return datetime.now() < cooldown_end
    
    async def get_scaling_status(self) -> Dict[str, Any]:
        """Get current scaling status and metrics"""
        return {
            'current_metrics': self.current_metrics.__dict__ if self.current_metrics else None,
            'active_operations': self.active_scaling_operations,
            'scaling_history': [decision.__dict__ for decision in self.scaling_history[-10:]],
            'scaling_policies': self.scaling_policies,
            'active_strategies': [strategy.value for strategy in self.active_strategies]
        }
    
    async def update_scaling_policy(
        self,
        policy_name: str,
        policy_config: Dict[str, Any]
    ):
        """Update scaling policy configuration"""
        self.scaling_policies[policy_name] = policy_config
        self.logger.info(f"Updated scaling policy: {policy_name}")
    
    async def set_scaling_thresholds(self, thresholds: Dict[str, float]):
        """Update scaling thresholds"""
        self.scaling_thresholds.update(thresholds)
        self.logger.info(f"Updated scaling thresholds: {thresholds}")
    
    async def set_scaling_limits(self, limits: Dict[str, Any]):
        """Update scaling limits"""
        self.scaling_limits.update(limits)
        self.logger.info(f"Updated scaling limits: {limits}")