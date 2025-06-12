"""
Cost Optimizer - Budget-aware scaling and resource management

This module provides comprehensive cost optimization capabilities including
budget monitoring, cost-aware scaling, spot instance management, and
multi-cloud cost comparison.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json
import math
from collections import defaultdict, deque

from ..circle_of_experts import CircleOfExperts, QueryRequest


class CostOptimizationStrategy(Enum):
    MINIMUM_COST = "minimum_cost"
    COST_PERFORMANCE_BALANCED = "cost_performance_balanced"
    BUDGET_CONSTRAINED = "budget_constrained"
    SPOT_INSTANCE_PREFERRED = "spot_instance_preferred"
    RESERVED_INSTANCE_OPTIMIZED = "reserved_instance_optimized"


class InstanceType(Enum):
    ON_DEMAND = "on_demand"
    SPOT = "spot"
    RESERVED = "reserved"
    PREEMPTIBLE = "preemptible"
    DEDICATED = "dedicated"


@dataclass
class CostModel:
    """Cost model for resource pricing"""
    instance_type: InstanceType
    cost_per_hour: float
    cost_per_gb_storage: float
    cost_per_gb_transfer: float
    upfront_cost: float = 0.0
    minimum_duration: timedelta = field(default_factory=lambda: timedelta(hours=1))
    availability_risk: float = 0.0  # 0.0 = guaranteed, 1.0 = high risk
    discount_factor: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BudgetConstraint:
    """Budget constraint specification"""
    budget_id: str
    total_budget: float
    time_period: timedelta
    spent_amount: float = 0.0
    alert_thresholds: List[float] = field(default_factory=lambda: [0.5, 0.8, 0.9])
    hard_limit: bool = True
    priority: int = 1


@dataclass
class CostOptimizationResult:
    """Result of cost optimization analysis"""
    strategy: CostOptimizationStrategy
    original_cost: float
    optimized_cost: float
    cost_savings: float
    savings_percentage: float
    optimized_resources: Dict[str, Any]
    risk_assessment: Dict[str, float]
    recommendations: List[str]
    confidence_score: float
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class SpotInstanceRecommendation:
    """Spot instance usage recommendation"""
    instance_type: str
    availability_zone: str
    current_price: float
    price_history_trend: str  # "increasing", "decreasing", "stable"
    interruption_risk: float
    potential_savings: float
    recommended_usage: str  # "high", "medium", "low", "avoid"


class CostOptimizer:
    """
    Budget-aware scaling and resource management system
    
    Provides cost optimization, budget monitoring, spot instance management,
    and multi-cloud cost comparison capabilities.
    """
    
    def __init__(self, circle_of_experts: Optional[CircleOfExperts] = None):
        self.logger = logging.getLogger(__name__)
        self.circle_of_experts = circle_of_experts
        
        # Cost models and pricing
        self.cost_models: Dict[str, CostModel] = {}
        self.pricing_history: deque = deque(maxlen=10000)
        self.spot_price_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        
        # Budget management
        self.budget_constraints: Dict[str, BudgetConstraint] = {}
        self.cost_tracking: Dict[str, Dict] = defaultdict(dict)
        self.budget_alerts: List[Dict] = []
        
        # Optimization settings
        self.optimization_policies = {
            'default_strategy': CostOptimizationStrategy.COST_PERFORMANCE_BALANCED,
            'enable_spot_instances': True,
            'max_spot_percentage': 0.7,
            'reserved_instance_threshold': 0.8,
            'cost_efficiency_threshold': 0.8
        }
        
        # Multi-cloud pricing
        self.cloud_providers = {
            'aws': {
                'compute_multiplier': 1.0,
                'storage_multiplier': 1.0,
                'network_multiplier': 1.0
            },
            'azure': {
                'compute_multiplier': 0.95,
                'storage_multiplier': 1.1,
                'network_multiplier': 0.9
            },
            'gcp': {
                'compute_multiplier': 0.9,
                'storage_multiplier': 0.85,
                'network_multiplier': 0.85
            }
        }
        
        # Initialize default cost models
        self._initialize_default_cost_models()
    
    async def optimize_resources(
        self,
        current_resources: Dict[str, Any],
        metrics: Dict[str, Any],
        strategy: CostOptimizationStrategy = CostOptimizationStrategy.COST_PERFORMANCE_BALANCED
    ) -> CostOptimizationResult:
        """
        Optimize resources for cost efficiency
        
        Args:
            current_resources: Current resource configuration
            metrics: Performance and utilization metrics
            strategy: Cost optimization strategy
            
        Returns:
            Cost optimization results and recommendations
        """
        try:
            # Calculate current cost
            original_cost = await self._calculate_current_cost(current_resources)
            
            # Analyze resource utilization
            utilization_analysis = await self._analyze_resource_utilization(
                current_resources, metrics
            )
            
            # Generate optimization options
            optimization_options = await self._generate_optimization_options(
                current_resources, utilization_analysis, strategy
            )
            
            # Get expert cost optimization recommendations
            expert_recommendations = await self._get_cost_optimization_recommendations(
                current_resources, metrics, optimization_options
            )
            
            # Select optimal configuration
            optimal_config = await self._select_optimal_configuration(
                optimization_options, expert_recommendations
            )
            
            # Calculate optimized cost
            optimized_cost = await self._calculate_optimized_cost(optimal_config)
            
            # Assess risks
            risk_assessment = await self._assess_optimization_risks(optimal_config)
            
            # Build result
            cost_savings = original_cost - optimized_cost
            savings_percentage = (cost_savings / original_cost * 100) if original_cost > 0 else 0
            
            return CostOptimizationResult(
                strategy=strategy,
                original_cost=original_cost,
                optimized_cost=optimized_cost,
                cost_savings=cost_savings,
                savings_percentage=savings_percentage,
                optimized_resources=optimal_config,
                risk_assessment=risk_assessment,
                recommendations=expert_recommendations,
                confidence_score=0.9
            )
            
        except Exception as e:
            self.logger.error(f"Cost optimization failed: {e}")
            return CostOptimizationResult(
                strategy=strategy,
                original_cost=0.0,
                optimized_cost=0.0,
                cost_savings=0.0,
                savings_percentage=0.0,
                optimized_resources={},
                risk_assessment={'error': 1.0},
                recommendations=[f"Optimization failed: {str(e)}"],
                confidence_score=0.0
            )
    
    async def estimate_cost(
        self,
        resources: Dict[str, Any],
        duration: Optional[timedelta] = None
    ) -> float:
        """
        Estimate cost for given resource configuration
        
        Args:
            resources: Resource configuration
            duration: Time duration for cost calculation
            
        Returns:
            Estimated cost
        """
        if duration is None:
            duration = timedelta(hours=1)
        
        total_cost = 0.0
        hours = duration.total_seconds() / 3600
        
        try:
            # Compute cost
            instance_count = resources.get('instance_count', 1)
            instance_type = resources.get('instance_type', 'on_demand')
            cpu_cores = resources.get('cpu_cores', 1)
            memory_gb = resources.get('memory_gb', 1)
            storage_gb = resources.get('storage_gb', 0)
            
            # Base compute cost
            if instance_type in self.cost_models:
                cost_model = self.cost_models[instance_type]
                compute_cost = cost_model.cost_per_hour * instance_count * hours
                total_cost += compute_cost
                
                # Storage cost
                storage_cost = cost_model.cost_per_gb_storage * storage_gb * hours
                total_cost += storage_cost
            else:
                # Fallback calculation
                base_cost_per_hour = 0.1 * cpu_cores + 0.05 * memory_gb
                total_cost = base_cost_per_hour * instance_count * hours
            
            # Cloud provider adjustments
            provider = resources.get('cloud_provider', 'aws')
            if provider in self.cloud_providers:
                multiplier = self.cloud_providers[provider]['compute_multiplier']
                total_cost *= multiplier
            
            return total_cost
            
        except Exception as e:
            self.logger.error(f"Cost estimation failed: {e}")
            return 0.0
    
    async def monitor_budget(
        self,
        budget_id: str
    ) -> Dict[str, Any]:
        """
        Monitor budget usage and generate alerts
        
        Args:
            budget_id: Budget constraint identifier
            
        Returns:
            Budget monitoring results
        """
        if budget_id not in self.budget_constraints:
            return {'error': f'Budget {budget_id} not found'}
        
        budget = self.budget_constraints[budget_id]
        
        # Calculate current usage
        usage_percentage = (budget.spent_amount / budget.total_budget * 100) \
                          if budget.total_budget > 0 else 0
        
        remaining_budget = budget.total_budget - budget.spent_amount
        
        # Check alert thresholds
        alerts = []
        for threshold in budget.alert_thresholds:
            if usage_percentage >= threshold * 100:
                alerts.append({
                    'level': 'warning' if threshold < 0.9 else 'critical',
                    'message': f'Budget usage exceeded {threshold*100}%',
                    'threshold': threshold,
                    'current_usage': usage_percentage
                })
        
        # Budget exhaustion prediction
        if budget.spent_amount > 0:
            time_elapsed = datetime.now() - budget.time_period
            burn_rate = budget.spent_amount / max(1, time_elapsed.total_seconds() / 3600)
            time_to_exhaustion = remaining_budget / burn_rate if burn_rate > 0 else float('inf')
        else:
            burn_rate = 0.0
            time_to_exhaustion = float('inf')
        
        return {
            'budget_id': budget_id,
            'total_budget': budget.total_budget,
            'spent_amount': budget.spent_amount,
            'remaining_budget': remaining_budget,
            'usage_percentage': usage_percentage,
            'burn_rate_per_hour': burn_rate,
            'estimated_exhaustion_hours': time_to_exhaustion,
            'alerts': alerts,
            'status': 'ok' if usage_percentage < 80 else 'warning' if usage_percentage < 95 else 'critical'
        }
    
    async def get_spot_instance_recommendations(
        self,
        requirements: Dict[str, Any]
    ) -> List[SpotInstanceRecommendation]:
        """
        Get spot instance recommendations for cost optimization
        
        Args:
            requirements: Resource requirements
            
        Returns:
            List of spot instance recommendations
        """
        recommendations = []
        
        try:
            # Simulate spot instance data (in practice, would query cloud APIs)
            spot_instances = [
                {
                    'instance_type': 'm5.large',
                    'availability_zone': 'us-east-1a',
                    'current_price': 0.045,
                    'on_demand_price': 0.096,
                    'interruption_rate': 0.05
                },
                {
                    'instance_type': 'm5.xlarge',
                    'availability_zone': 'us-east-1b',
                    'current_price': 0.085,
                    'on_demand_price': 0.192,
                    'interruption_rate': 0.03
                },
                {
                    'instance_type': 'c5.large',
                    'availability_zone': 'us-east-1c',
                    'current_price': 0.040,
                    'on_demand_price': 0.085,
                    'interruption_rate': 0.08
                }
            ]
            
            for instance in spot_instances:
                savings = (instance['on_demand_price'] - instance['current_price']) / instance['on_demand_price']
                
                # Determine recommendation level
                if savings > 0.5 and instance['interruption_rate'] < 0.1:
                    usage_recommendation = "high"
                elif savings > 0.3 and instance['interruption_rate'] < 0.2:
                    usage_recommendation = "medium"
                elif savings > 0.1:
                    usage_recommendation = "low"
                else:
                    usage_recommendation = "avoid"
                
                recommendation = SpotInstanceRecommendation(
                    instance_type=instance['instance_type'],
                    availability_zone=instance['availability_zone'],
                    current_price=instance['current_price'],
                    price_history_trend="stable",  # Would analyze historical data
                    interruption_risk=instance['interruption_rate'],
                    potential_savings=savings * 100,
                    recommended_usage=usage_recommendation
                )
                
                recommendations.append(recommendation)
            
            # Sort by potential savings
            recommendations.sort(key=lambda x: x.potential_savings, reverse=True)
            
            return recommendations
            
        except Exception as e:
            self.logger.error(f"Failed to get spot instance recommendations: {e}")
            return []
    
    async def compare_multi_cloud_costs(
        self,
        resources: Dict[str, Any],
        duration: Optional[timedelta] = None
    ) -> Dict[str, Dict[str, Any]]:
        """
        Compare costs across multiple cloud providers
        
        Args:
            resources: Resource configuration
            duration: Time duration for comparison
            
        Returns:
            Cost comparison across providers
        """
        if duration is None:
            duration = timedelta(hours=24)
        
        comparison = {}
        
        for provider, pricing_config in self.cloud_providers.items():
            try:
                # Adjust resources for provider-specific pricing
                adjusted_resources = resources.copy()
                adjusted_resources['cloud_provider'] = provider
                
                # Calculate cost with provider adjustments
                base_cost = await self.estimate_cost(adjusted_resources, duration)
                
                # Provider-specific discounts and features
                provider_features = {
                    'aws': {
                        'spot_discount': 0.7,
                        'reserved_discount': 0.4,
                        'sustained_use_discount': 0.0
                    },
                    'azure': {
                        'spot_discount': 0.8,
                        'reserved_discount': 0.35,
                        'sustained_use_discount': 0.0
                    },
                    'gcp': {
                        'spot_discount': 0.8,
                        'reserved_discount': 0.37,
                        'sustained_use_discount': 0.3
                    }
                }
                
                features = provider_features.get(provider, {})
                
                comparison[provider] = {
                    'base_cost': base_cost,
                    'with_spot_instances': base_cost * features.get('spot_discount', 1.0),
                    'with_reserved_instances': base_cost * features.get('reserved_discount', 1.0),
                    'with_sustained_use': base_cost * (1.0 - features.get('sustained_use_discount', 0.0)),
                    'features': features,
                    'pricing_multiplier': pricing_config
                }
                
            except Exception as e:
                self.logger.error(f"Cost comparison failed for {provider}: {e}")
                comparison[provider] = {'error': str(e)}
        
        # Find the most cost-effective option
        if comparison:
            cheapest_provider = min(
                comparison.keys(),
                key=lambda p: comparison[p].get('base_cost', float('inf'))
            )
            
            for provider_data in comparison.values():
                if isinstance(provider_data, dict) and 'base_cost' in provider_data:
                    provider_data['is_cheapest'] = False
            
            if 'base_cost' in comparison[cheapest_provider]:
                comparison[cheapest_provider]['is_cheapest'] = True
        
        return comparison
    
    async def add_budget_constraint(
        self,
        budget_id: str,
        total_budget: float,
        time_period: timedelta,
        alert_thresholds: Optional[List[float]] = None,
        hard_limit: bool = True
    ) -> bool:
        """Add a budget constraint"""
        try:
            if alert_thresholds is None:
                alert_thresholds = [0.5, 0.8, 0.9]
            
            budget = BudgetConstraint(
                budget_id=budget_id,
                total_budget=total_budget,
                time_period=time_period,
                alert_thresholds=alert_thresholds,
                hard_limit=hard_limit
            )
            
            self.budget_constraints[budget_id] = budget
            self.logger.info(f"Added budget constraint: {budget_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add budget constraint: {e}")
            return False
    
    async def update_budget_spending(
        self,
        budget_id: str,
        amount: float
    ) -> bool:
        """Update budget spending amount"""
        try:
            if budget_id not in self.budget_constraints:
                return False
            
            budget = self.budget_constraints[budget_id]
            budget.spent_amount += amount
            
            # Check for budget alerts
            await self._check_budget_alerts(budget_id)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update budget spending: {e}")
            return False
    
    async def _initialize_default_cost_models(self):
        """Initialize default cost models"""
        self.cost_models = {
            'on_demand': CostModel(
                instance_type=InstanceType.ON_DEMAND,
                cost_per_hour=0.10,
                cost_per_gb_storage=0.10,
                cost_per_gb_transfer=0.09,
                availability_risk=0.0,
                discount_factor=1.0
            ),
            'spot': CostModel(
                instance_type=InstanceType.SPOT,
                cost_per_hour=0.03,
                cost_per_gb_storage=0.10,
                cost_per_gb_transfer=0.09,
                availability_risk=0.15,
                discount_factor=0.7
            ),
            'reserved': CostModel(
                instance_type=InstanceType.RESERVED,
                cost_per_hour=0.06,
                cost_per_gb_storage=0.10,
                cost_per_gb_transfer=0.09,
                upfront_cost=1000.0,
                minimum_duration=timedelta(days=365),
                availability_risk=0.0,
                discount_factor=0.6
            )
        }
    
    async def _calculate_current_cost(self, resources: Dict[str, Any]) -> float:
        """Calculate current resource cost"""
        return await self.estimate_cost(resources, timedelta(hours=1))
    
    async def _analyze_resource_utilization(
        self,
        resources: Dict[str, Any],
        metrics: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze resource utilization for optimization"""
        analysis = {
            'cpu_utilization': metrics.get('cpu_utilization', 50.0),
            'memory_utilization': metrics.get('memory_utilization', 50.0),
            'storage_utilization': metrics.get('storage_utilization', 50.0),
            'network_utilization': metrics.get('network_utilization', 50.0),
            'optimization_opportunities': []
        }
        
        # Identify under-utilized resources
        if analysis['cpu_utilization'] < 30:
            analysis['optimization_opportunities'].append({
                'type': 'cpu_downsizing',
                'potential_savings': 0.3,
                'risk': 'low'
            })
        
        if analysis['memory_utilization'] < 40:
            analysis['optimization_opportunities'].append({
                'type': 'memory_optimization',
                'potential_savings': 0.2,
                'risk': 'medium'
            })
        
        return analysis
    
    async def _generate_optimization_options(
        self,
        resources: Dict[str, Any],
        utilization: Dict[str, Any],
        strategy: CostOptimizationStrategy
    ) -> List[Dict[str, Any]]:
        """Generate cost optimization options"""
        options = []
        
        if strategy == CostOptimizationStrategy.MINIMUM_COST:
            # Aggressive cost optimization
            options.append({
                'name': 'spot_instance_migration',
                'resources': {**resources, 'instance_type': 'spot'},
                'estimated_savings': 0.7,
                'risk_level': 'high'
            })
        
        elif strategy == CostOptimizationStrategy.COST_PERFORMANCE_BALANCED:
            # Balanced optimization
            options.append({
                'name': 'right_sizing',
                'resources': {
                    **resources,
                    'cpu_cores': max(1, int(resources.get('cpu_cores', 1) * 0.8)),
                    'memory_gb': max(1, int(resources.get('memory_gb', 1) * 0.8))
                },
                'estimated_savings': 0.2,
                'risk_level': 'low'
            })
            
            options.append({
                'name': 'mixed_instance_types',
                'resources': {**resources, 'spot_percentage': 0.3},
                'estimated_savings': 0.3,
                'risk_level': 'medium'
            })
        
        elif strategy == CostOptimizationStrategy.SPOT_INSTANCE_PREFERRED:
            # Heavy spot instance usage
            options.append({
                'name': 'high_spot_usage',
                'resources': {**resources, 'spot_percentage': 0.8},
                'estimated_savings': 0.6,
                'risk_level': 'high'
            })
        
        return options
    
    async def _get_cost_optimization_recommendations(
        self,
        resources: Dict[str, Any],
        metrics: Dict[str, Any],
        options: List[Dict[str, Any]]
    ) -> List[str]:
        """Get expert cost optimization recommendations"""
        if not self.circle_of_experts:
            return []
        
        try:
            query = QueryRequest(
                query=f"""
                Given these resources and optimization options, what cost optimization strategies do you recommend?
                
                Current Resources:
                {json.dumps(resources, indent=2)}
                
                Performance Metrics:
                {json.dumps(metrics, indent=2)}
                
                Optimization Options:
                {json.dumps(options, indent=2)}
                
                Please provide recommendations for:
                1. Most effective cost reduction strategies
                2. Risk mitigation for spot instances
                3. Right-sizing opportunities
                4. Long-term cost optimization
                """,
                experts=["cost_optimization_expert", "cloud_architecture_expert"],
                require_consensus=False
            )
            
            response = await self.circle_of_experts.process_query(query)
            return [resp.content for resp in response.expert_responses]
            
        except Exception as e:
            self.logger.warning(f"Failed to get cost optimization recommendations: {e}")
            return []
    
    async def _select_optimal_configuration(
        self,
        options: List[Dict[str, Any]],
        recommendations: List[str]
    ) -> Dict[str, Any]:
        """Select optimal cost configuration"""
        if not options:
            return {}
        
        # Score options based on savings and risk
        scored_options = []
        for option in options:
            savings = option.get('estimated_savings', 0.0)
            risk_penalty = {'low': 0.0, 'medium': 0.1, 'high': 0.3}.get(
                option.get('risk_level', 'medium'), 0.1
            )
            score = savings - risk_penalty
            scored_options.append((score, option))
        
        # Sort by score and return best option
        scored_options.sort(key=lambda x: x[0], reverse=True)
        return scored_options[0][1]['resources'] if scored_options else {}
    
    async def _calculate_optimized_cost(self, config: Dict[str, Any]) -> float:
        """Calculate cost for optimized configuration"""
        return await self.estimate_cost(config, timedelta(hours=1))
    
    async def _assess_optimization_risks(
        self,
        config: Dict[str, Any]
    ) -> Dict[str, float]:
        """Assess risks of optimization configuration"""
        risks = {
            'availability_risk': 0.0,
            'performance_risk': 0.0,
            'cost_variance_risk': 0.0,
            'operational_risk': 0.0
        }
        
        # Assess spot instance risks
        spot_percentage = config.get('spot_percentage', 0.0)
        if spot_percentage > 0:
            risks['availability_risk'] = min(1.0, spot_percentage * 0.2)
            risks['cost_variance_risk'] = min(1.0, spot_percentage * 0.3)
        
        # Assess downsizing risks
        original_cores = config.get('original_cpu_cores', config.get('cpu_cores', 1))
        current_cores = config.get('cpu_cores', 1)
        if current_cores < original_cores:
            downsize_ratio = current_cores / original_cores
            risks['performance_risk'] = min(1.0, (1.0 - downsize_ratio) * 2.0)
        
        return risks
    
    async def _check_budget_alerts(self, budget_id: str):
        """Check and generate budget alerts"""
        budget_status = await self.monitor_budget(budget_id)
        
        if budget_status.get('alerts'):
            for alert in budget_status['alerts']:
                self.budget_alerts.append({
                    **alert,
                    'budget_id': budget_id,
                    'timestamp': datetime.now()
                })
                
                self.logger.warning(
                    f"Budget alert for {budget_id}: {alert['message']}"
                )
    
    async def get_cost_report(
        self,
        time_range: Optional[Tuple[datetime, datetime]] = None
    ) -> Dict[str, Any]:
        """Generate comprehensive cost report"""
        if time_range is None:
            end_time = datetime.now()
            start_time = end_time - timedelta(days=30)
            time_range = (start_time, end_time)
        
        start_time, end_time = time_range
        
        return {
            'time_range': {
                'start': start_time.isoformat(),
                'end': end_time.isoformat()
            },
            'budget_status': {
                budget_id: await self.monitor_budget(budget_id)
                for budget_id in self.budget_constraints.keys()
            },
            'cost_models': {
                model_id: {
                    'instance_type': model.instance_type.value,
                    'cost_per_hour': model.cost_per_hour,
                    'availability_risk': model.availability_risk,
                    'discount_factor': model.discount_factor
                }
                for model_id, model in self.cost_models.items()
            },
            'optimization_policies': self.optimization_policies,
            'recent_alerts': self.budget_alerts[-10:] if self.budget_alerts else []
        }