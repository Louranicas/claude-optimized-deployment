"""
Strategy Selector - Expert strategy selection and optimization
Selects optimal testing strategies based on expert consensus and system capabilities
"""

import asyncio
import logging
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import random


class StrategyType(Enum):
    LOAD_TESTING = "load_testing"
    STRESS_TESTING = "stress_testing"
    ENDURANCE_TESTING = "endurance_testing"
    SPIKE_TESTING = "spike_testing"
    VOLUME_TESTING = "volume_testing"
    SCALABILITY_TESTING = "scalability_testing"
    SECURITY_TESTING = "security_testing"
    CHAOS_TESTING = "chaos_testing"
    HYBRID_TESTING = "hybrid_testing"


class StrategyComplexity(Enum):
    SIMPLE = "simple"
    MODERATE = "moderate"
    COMPLEX = "complex"
    ADVANCED = "advanced"


@dataclass
class StrategyOption:
    """Strategy option definition"""
    strategy_id: str
    name: str
    strategy_type: StrategyType
    complexity: StrategyComplexity
    resource_requirements: Dict[str, float]
    expected_duration: int  # minutes
    success_probability: float
    expert_scores: Dict[str, float]
    prerequisites: List[str]
    capabilities_required: List[str]
    risk_level: str


@dataclass
class StrategySelectionResult:
    """Result of strategy selection process"""
    selected_strategy: StrategyOption
    selection_reasoning: str
    confidence_score: float
    alternative_strategies: List[StrategyOption]
    adaptation_parameters: Dict[str, Any]
    implementation_plan: List[str]
    risk_mitigation: List[str]


class StrategySelector:
    """
    Expert-driven strategy selection and optimization system
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.name = "Strategy Selector"
        
        # Strategy templates and configurations
        self.strategy_templates = {
            StrategyType.LOAD_TESTING: {
                'description': 'Validate system behavior under expected load',
                'complexity_base': StrategyComplexity.SIMPLE,
                'duration_base': 30,  # minutes
                'resource_multiplier': 1.0,
                'expert_weights': {'performance': 0.4, 'reliability': 0.3, 'scalability': 0.2, 'security': 0.05, 'chaos': 0.05}
            },
            StrategyType.STRESS_TESTING: {
                'description': 'Determine system breaking points and failure modes',
                'complexity_base': StrategyComplexity.MODERATE,
                'duration_base': 45,
                'resource_multiplier': 1.5,
                'expert_weights': {'performance': 0.3, 'reliability': 0.4, 'scalability': 0.2, 'security': 0.05, 'chaos': 0.05}
            },
            StrategyType.ENDURANCE_TESTING: {
                'description': 'Validate system stability over extended periods',
                'complexity_base': StrategyComplexity.MODERATE,
                'duration_base': 240,  # 4 hours
                'resource_multiplier': 1.2,
                'expert_weights': {'performance': 0.2, 'reliability': 0.5, 'scalability': 0.2, 'security': 0.05, 'chaos': 0.05}
            },
            StrategyType.SPIKE_TESTING: {
                'description': 'Test system response to sudden load increases',
                'complexity_base': StrategyComplexity.MODERATE,
                'duration_base': 60,
                'resource_multiplier': 2.0,
                'expert_weights': {'performance': 0.3, 'reliability': 0.3, 'scalability': 0.3, 'security': 0.05, 'chaos': 0.05}
            },
            StrategyType.SCALABILITY_TESTING: {
                'description': 'Validate horizontal and vertical scaling capabilities',
                'complexity_base': StrategyComplexity.COMPLEX,
                'duration_base': 90,
                'resource_multiplier': 1.8,
                'expert_weights': {'performance': 0.2, 'reliability': 0.2, 'scalability': 0.5, 'security': 0.05, 'chaos': 0.05}
            },
            StrategyType.SECURITY_TESTING: {
                'description': 'Validate security under load and stress conditions',
                'complexity_base': StrategyComplexity.COMPLEX,
                'duration_base': 120,
                'resource_multiplier': 1.3,
                'expert_weights': {'performance': 0.1, 'reliability': 0.2, 'scalability': 0.1, 'security': 0.5, 'chaos': 0.1}
            },
            StrategyType.CHAOS_TESTING: {
                'description': 'Chaos engineering and resilience validation',
                'complexity_base': StrategyComplexity.ADVANCED,
                'duration_base': 180,
                'resource_multiplier': 1.6,
                'expert_weights': {'performance': 0.1, 'reliability': 0.3, 'scalability': 0.1, 'security': 0.1, 'chaos': 0.4}
            },
            StrategyType.HYBRID_TESTING: {
                'description': 'Combined testing approach with multiple techniques',
                'complexity_base': StrategyComplexity.ADVANCED,
                'duration_base': 150,
                'resource_multiplier': 2.2,
                'expert_weights': {'performance': 0.25, 'reliability': 0.25, 'scalability': 0.2, 'security': 0.15, 'chaos': 0.15}
            }
        }
        
        # System capability assessment criteria
        self.capability_requirements = {
            'basic_monitoring': ['response_time_tracking', 'error_rate_monitoring', 'throughput_measurement'],
            'advanced_monitoring': ['distributed_tracing', 'custom_metrics', 'real_time_dashboards'],
            'auto_scaling': ['horizontal_scaling', 'vertical_scaling', 'auto_scaling_policies'],
            'load_balancing': ['traffic_distribution', 'health_checks', 'failover_support'],
            'security_controls': ['authentication', 'authorization', 'encryption', 'audit_logging'],
            'chaos_readiness': ['circuit_breakers', 'bulkheads', 'timeouts', 'fallbacks'],
            'high_availability': ['redundancy', 'backup_systems', 'disaster_recovery']
        }
        
        # Risk assessment matrix
        self.risk_matrix = {
            ('simple', 'low'): 'low',
            ('simple', 'medium'): 'low',
            ('simple', 'high'): 'medium',
            ('moderate', 'low'): 'low',
            ('moderate', 'medium'): 'medium',
            ('moderate', 'high'): 'medium',
            ('complex', 'low'): 'medium',
            ('complex', 'medium'): 'medium',
            ('complex', 'high'): 'high',
            ('advanced', 'low'): 'medium',
            ('advanced', 'medium'): 'high',
            ('advanced', 'high'): 'high'
        }
        
        # Selection history for learning
        self.selection_history: List[Dict[str, Any]] = []
        
    async def select_strategy(self, strategy_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Select optimal strategy based on expert consensus and system capabilities
        """
        self.logger.info("Starting expert-driven strategy selection")
        
        try:
            # Extract input data
            consensus = strategy_data.get('consensus', {})
            context = strategy_data.get('context', {})
            system_capabilities = strategy_data.get('system_capabilities', {})
            resource_constraints = strategy_data.get('resource_constraints', {})
            
            # Generate strategy options
            strategy_options = await self._generate_strategy_options(
                consensus, context, system_capabilities
            )
            
            # Score and rank strategies
            scored_strategies = await self._score_strategies(
                strategy_options, consensus, system_capabilities, resource_constraints
            )
            
            # Select optimal strategy
            selection_result = await self._select_optimal_strategy(
                scored_strategies, context, resource_constraints
            )
            
            # Generate adaptation parameters
            adaptation_params = await self._generate_adaptation_parameters(
                selection_result.selected_strategy, context, system_capabilities
            )
            
            # Create implementation plan
            implementation_plan = await self._create_implementation_plan(
                selection_result.selected_strategy, context
            )
            
            # Identify risk mitigations
            risk_mitigations = await self._identify_risk_mitigations(
                selection_result.selected_strategy, system_capabilities
            )
            
            # Compile final strategy
            strategy = {
                'name': selection_result.selected_strategy.name,
                'type': selection_result.selected_strategy.strategy_type.value,
                'complexity': selection_result.selected_strategy.complexity.value,
                'confidence': selection_result.confidence_score,
                'selection_reasoning': selection_result.selection_reasoning,
                'resource_requirements': selection_result.selected_strategy.resource_requirements,
                'expected_duration': selection_result.selected_strategy.expected_duration,
                'success_probability': selection_result.selected_strategy.success_probability,
                'risk_level': selection_result.selected_strategy.risk_level,
                'adaptation_parameters': adaptation_params,
                'implementation_plan': implementation_plan,
                'risk_mitigations': risk_mitigations,
                'alternative_strategies': [
                    {
                        'name': alt.name,
                        'type': alt.strategy_type.value,
                        'confidence': alt.expert_scores.get('overall', 0.5)
                    }
                    for alt in selection_result.alternative_strategies[:3]
                ]
            }
            
            # Store selection for learning
            self._store_selection(strategy, consensus, context)
            
            self.logger.info(f"Selected strategy: {strategy['name']} with {strategy['confidence']:.2f} confidence")
            return strategy
            
        except Exception as e:
            self.logger.error(f"Strategy selection failed: {str(e)}")
            return self._generate_fallback_strategy()
    
    async def _generate_strategy_options(
        self,
        consensus: Dict[str, Any],
        context: Dict[str, Any],
        system_capabilities: Dict[str, Any]
    ) -> List[StrategyOption]:
        """Generate available strategy options"""
        options = []
        
        # Extract expert recommendations
        expert_recommendations = consensus.get('expert_recommendations', [])
        primary_strategy = consensus.get('primary_strategy', 'load_testing')
        confidence = consensus.get('confidence', 0.7)
        
        # Map primary strategy to enum
        try:
            primary_type = StrategyType(primary_strategy)
        except ValueError:
            primary_type = StrategyType.LOAD_TESTING
        
        # Generate primary strategy option
        primary_option = await self._create_strategy_option(
            primary_type, expert_recommendations, system_capabilities, context
        )
        options.append(primary_option)
        
        # Generate alternative strategies based on expert scores
        expert_preferences = self._extract_expert_preferences(expert_recommendations)
        
        # Add performance-focused alternatives
        if expert_preferences.get('performance', 0) > 0.3:
            if primary_type != StrategyType.STRESS_TESTING:
                stress_option = await self._create_strategy_option(
                    StrategyType.STRESS_TESTING, expert_recommendations, system_capabilities, context
                )
                options.append(stress_option)
        
        # Add reliability-focused alternatives
        if expert_preferences.get('reliability', 0) > 0.3:
            if primary_type != StrategyType.ENDURANCE_TESTING:
                endurance_option = await self._create_strategy_option(
                    StrategyType.ENDURANCE_TESTING, expert_recommendations, system_capabilities, context
                )
                options.append(endurance_option)
        
        # Add scalability-focused alternatives
        if expert_preferences.get('scalability', 0) > 0.3:
            if primary_type != StrategyType.SCALABILITY_TESTING:
                scalability_option = await self._create_strategy_option(
                    StrategyType.SCALABILITY_TESTING, expert_recommendations, system_capabilities, context
                )
                options.append(scalability_option)
        
        # Add security-focused alternatives
        if expert_preferences.get('security', 0) > 0.3:
            if primary_type != StrategyType.SECURITY_TESTING:
                security_option = await self._create_strategy_option(
                    StrategyType.SECURITY_TESTING, expert_recommendations, system_capabilities, context
                )
                options.append(security_option)
        
        # Add chaos testing if system is ready
        chaos_readiness = self._assess_chaos_readiness(system_capabilities)
        if chaos_readiness > 0.6 and primary_type != StrategyType.CHAOS_TESTING:
            chaos_option = await self._create_strategy_option(
                StrategyType.CHAOS_TESTING, expert_recommendations, system_capabilities, context
            )
            options.append(chaos_option)
        
        # Add hybrid strategy for complex scenarios
        if len(expert_recommendations) > 3 and confidence > 0.8:
            hybrid_option = await self._create_strategy_option(
                StrategyType.HYBRID_TESTING, expert_recommendations, system_capabilities, context
            )
            options.append(hybrid_option)
        
        return options
    
    async def _create_strategy_option(
        self,
        strategy_type: StrategyType,
        expert_recommendations: List[Dict[str, Any]],
        system_capabilities: Dict[str, Any],
        context: Dict[str, Any]
    ) -> StrategyOption:
        """Create a specific strategy option"""
        
        template = self.strategy_templates[strategy_type]
        
        # Calculate expert scores
        expert_scores = self._calculate_expert_scores(
            strategy_type, expert_recommendations, template['expert_weights']
        )
        
        # Assess complexity based on system state and requirements
        complexity = self._assess_strategy_complexity(
            strategy_type, system_capabilities, context
        )
        
        # Calculate resource requirements
        resource_requirements = self._calculate_resource_requirements(
            strategy_type, template, system_capabilities, context
        )
        
        # Estimate duration
        duration = self._estimate_duration(
            strategy_type, template, complexity, context
        )
        
        # Calculate success probability
        success_probability = self._calculate_success_probability(
            strategy_type, expert_scores, system_capabilities, complexity
        )
        
        # Identify prerequisites
        prerequisites = self._identify_prerequisites(strategy_type, system_capabilities)
        
        # Determine required capabilities
        capabilities_required = self._determine_required_capabilities(strategy_type)
        
        # Assess risk level
        system_risk = self._assess_system_risk(system_capabilities, context)
        risk_level = self.risk_matrix.get((complexity.value, system_risk), 'medium')
        
        return StrategyOption(
            strategy_id=f"{strategy_type.value}_{int(time.time())}",
            name=f"{template['description']} Strategy",
            strategy_type=strategy_type,
            complexity=complexity,
            resource_requirements=resource_requirements,
            expected_duration=duration,
            success_probability=success_probability,
            expert_scores=expert_scores,
            prerequisites=prerequisites,
            capabilities_required=capabilities_required,
            risk_level=risk_level
        )
    
    def _extract_expert_preferences(self, expert_recommendations: List[Dict[str, Any]]) -> Dict[str, float]:
        """Extract expert preferences from recommendations"""
        preferences = {'performance': 0, 'reliability': 0, 'scalability': 0, 'security': 0, 'chaos': 0}
        
        if not expert_recommendations:
            return preferences
        
        for recommendation in expert_recommendations:
            expert_name = recommendation.get('expert_name', '').lower()
            confidence = recommendation.get('confidence', 0.5)
            
            if 'performance' in expert_name:
                preferences['performance'] += confidence
            elif 'reliability' in expert_name:
                preferences['reliability'] += confidence
            elif 'scalability' in expert_name:
                preferences['scalability'] += confidence
            elif 'security' in expert_name:
                preferences['security'] += confidence
            elif 'chaos' in expert_name:
                preferences['chaos'] += confidence
        
        # Normalize
        total = sum(preferences.values())
        if total > 0:
            preferences = {k: v / total for k, v in preferences.items()}
        
        return preferences
    
    def _calculate_expert_scores(
        self,
        strategy_type: StrategyType,
        expert_recommendations: List[Dict[str, Any]],
        expert_weights: Dict[str, float]
    ) -> Dict[str, float]:
        """Calculate expert scores for strategy"""
        scores = {}
        
        # Calculate weighted score based on expert recommendations
        total_score = 0
        total_weight = 0
        
        for expert_name, weight in expert_weights.items():
            expert_recommendation = next(
                (rec for rec in expert_recommendations if expert_name in rec.get('expert_name', '').lower()),
                None
            )
            
            if expert_recommendation:
                confidence = expert_recommendation.get('confidence', 0.5)
                total_score += confidence * weight
                total_weight += weight
                scores[expert_name] = confidence
            else:
                scores[expert_name] = 0.5  # Default score
        
        # Overall score
        if total_weight > 0:
            scores['overall'] = total_score / total_weight
        else:
            scores['overall'] = 0.5
        
        # Strategy-specific adjustments
        if strategy_type == StrategyType.LOAD_TESTING:
            scores['overall'] *= 1.1  # Slightly favor load testing as baseline
        elif strategy_type == StrategyType.CHAOS_TESTING:
            scores['overall'] *= 0.9  # Slightly penalize chaos testing for complexity
        
        return scores
    
    def _assess_strategy_complexity(
        self,
        strategy_type: StrategyType,
        system_capabilities: Dict[str, Any],
        context: Dict[str, Any]
    ) -> StrategyComplexity:
        """Assess strategy complexity based on system and context"""
        
        base_complexity = self.strategy_templates[strategy_type]['complexity_base']
        
        # Factors that increase complexity
        complexity_factors = 0
        
        # System factors
        if not system_capabilities.get('monitoring_enabled', False):
            complexity_factors += 1
        if not system_capabilities.get('auto_scaling', False) and strategy_type in [StrategyType.SCALABILITY_TESTING, StrategyType.SPIKE_TESTING]:
            complexity_factors += 1
        if not system_capabilities.get('load_balancer', False) and strategy_type in [StrategyType.LOAD_TESTING, StrategyType.STRESS_TESTING]:
            complexity_factors += 1
        
        # Context factors
        objectives = context.get('test_objectives', [])
        if len(objectives) > 3:
            complexity_factors += 1
        
        constraints = context.get('constraints', {})
        if len(constraints) > 2:
            complexity_factors += 1
        
        # Adjust complexity
        complexity_levels = [StrategyComplexity.SIMPLE, StrategyComplexity.MODERATE, StrategyComplexity.COMPLEX, StrategyComplexity.ADVANCED]
        base_index = complexity_levels.index(base_complexity)
        
        adjusted_index = min(len(complexity_levels) - 1, base_index + complexity_factors)
        return complexity_levels[adjusted_index]
    
    def _calculate_resource_requirements(
        self,
        strategy_type: StrategyType,
        template: Dict[str, Any],
        system_capabilities: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Dict[str, float]:
        """Calculate resource requirements for strategy"""
        
        base_multiplier = template['resource_multiplier']
        
        # Base requirements
        requirements = {
            'cpu_cores': 4 * base_multiplier,
            'memory_gb': 8 * base_multiplier,
            'network_mbps': 100 * base_multiplier,
            'storage_gb': 50 * base_multiplier,
            'test_instances': max(1, int(2 * base_multiplier))
        }
        
        # Adjust based on system capabilities
        if system_capabilities.get('distributed_system', False):
            requirements['test_instances'] *= 2
        
        if strategy_type in [StrategyType.VOLUME_TESTING, StrategyType.ENDURANCE_TESTING]:
            requirements['storage_gb'] *= 2
        
        if strategy_type in [StrategyType.SPIKE_TESTING, StrategyType.STRESS_TESTING]:
            requirements['cpu_cores'] *= 1.5
            requirements['memory_gb'] *= 1.5
        
        # Context adjustments
        expected_load = context.get('expected_load', 1000)  # requests/sec
        if expected_load > 5000:
            scale_factor = expected_load / 5000
            for key in requirements:
                if key != 'test_instances':
                    requirements[key] *= scale_factor
        
        return requirements
    
    def _estimate_duration(
        self,
        strategy_type: StrategyType,
        template: Dict[str, Any],
        complexity: StrategyComplexity,
        context: Dict[str, Any]
    ) -> int:
        """Estimate strategy execution duration in minutes"""
        
        base_duration = template['duration_base']
        
        # Complexity multipliers
        complexity_multipliers = {
            StrategyComplexity.SIMPLE: 1.0,
            StrategyComplexity.MODERATE: 1.3,
            StrategyComplexity.COMPLEX: 1.6,
            StrategyComplexity.ADVANCED: 2.0
        }
        
        duration = base_duration * complexity_multipliers[complexity]
        
        # Context adjustments
        test_objectives = context.get('test_objectives', [])
        if len(test_objectives) > 3:
            duration *= 1.2
        
        # Strategy-specific adjustments
        if strategy_type == StrategyType.ENDURANCE_TESTING:
            duration = max(duration, 240)  # Minimum 4 hours
        elif strategy_type == StrategyType.CHAOS_TESTING:
            duration = max(duration, 120)  # Minimum 2 hours
        
        return int(duration)
    
    def _calculate_success_probability(
        self,
        strategy_type: StrategyType,
        expert_scores: Dict[str, float],
        system_capabilities: Dict[str, Any],
        complexity: StrategyComplexity
    ) -> float:
        """Calculate probability of successful strategy execution"""
        
        # Base probability from expert scores
        base_probability = expert_scores.get('overall', 0.5)
        
        # System readiness factors
        readiness_factors = []
        
        # Monitoring readiness
        if system_capabilities.get('monitoring_enabled', False):
            readiness_factors.append(0.9)
        else:
            readiness_factors.append(0.6)
        
        # Infrastructure readiness
        if system_capabilities.get('auto_scaling', False):
            readiness_factors.append(0.85)
        else:
            readiness_factors.append(0.7)
        
        # Observability readiness
        if system_capabilities.get('logging_enabled', False):
            readiness_factors.append(0.8)
        else:
            readiness_factors.append(0.6)
        
        # Calculate readiness score
        readiness_score = sum(readiness_factors) / len(readiness_factors)
        
        # Complexity penalty
        complexity_penalties = {
            StrategyComplexity.SIMPLE: 0.95,
            StrategyComplexity.MODERATE: 0.85,
            StrategyComplexity.COMPLEX: 0.75,
            StrategyComplexity.ADVANCED: 0.65
        }
        
        complexity_factor = complexity_penalties[complexity]
        
        # Strategy-specific adjustments
        strategy_adjustments = {
            StrategyType.LOAD_TESTING: 1.0,
            StrategyType.STRESS_TESTING: 0.9,
            StrategyType.ENDURANCE_TESTING: 0.85,
            StrategyType.SPIKE_TESTING: 0.8,
            StrategyType.SCALABILITY_TESTING: 0.75,
            StrategyType.SECURITY_TESTING: 0.8,
            StrategyType.CHAOS_TESTING: 0.7,
            StrategyType.HYBRID_TESTING: 0.75
        }
        
        strategy_factor = strategy_adjustments.get(strategy_type, 0.8)
        
        # Final probability calculation
        final_probability = base_probability * readiness_score * complexity_factor * strategy_factor
        
        return max(0.3, min(0.95, final_probability))  # Clamp between 30% and 95%
    
    def _identify_prerequisites(
        self,
        strategy_type: StrategyType,
        system_capabilities: Dict[str, Any]
    ) -> List[str]:
        """Identify prerequisites for strategy execution"""
        prerequisites = []
        
        # Common prerequisites
        if not system_capabilities.get('monitoring_enabled', False):
            prerequisites.append("Enable comprehensive system monitoring")
        
        if not system_capabilities.get('baseline_metrics', False):
            prerequisites.append("Establish baseline performance metrics")
        
        # Strategy-specific prerequisites
        if strategy_type in [StrategyType.SCALABILITY_TESTING, StrategyType.SPIKE_TESTING]:
            if not system_capabilities.get('auto_scaling', False):
                prerequisites.append("Configure auto-scaling mechanisms")
        
        if strategy_type == StrategyType.ENDURANCE_TESTING:
            if not system_capabilities.get('resource_monitoring', False):
                prerequisites.append("Implement resource leak monitoring")
        
        if strategy_type == StrategyType.SECURITY_TESTING:
            if not system_capabilities.get('security_logging', False):
                prerequisites.append("Enable security event logging")
        
        if strategy_type == StrategyType.CHAOS_TESTING:
            if not system_capabilities.get('circuit_breakers', False):
                prerequisites.append("Implement circuit breaker patterns")
            if not system_capabilities.get('health_checks', False):
                prerequisites.append("Configure health check endpoints")
        
        return prerequisites
    
    def _determine_required_capabilities(self, strategy_type: StrategyType) -> List[str]:
        """Determine required system capabilities for strategy"""
        capabilities = ['basic_monitoring']  # Always required
        
        capability_map = {
            StrategyType.LOAD_TESTING: ['basic_monitoring', 'load_balancing'],
            StrategyType.STRESS_TESTING: ['basic_monitoring', 'advanced_monitoring'],
            StrategyType.ENDURANCE_TESTING: ['basic_monitoring', 'advanced_monitoring'],
            StrategyType.SPIKE_TESTING: ['basic_monitoring', 'auto_scaling'],
            StrategyType.SCALABILITY_TESTING: ['basic_monitoring', 'auto_scaling', 'load_balancing'],
            StrategyType.SECURITY_TESTING: ['basic_monitoring', 'security_controls'],
            StrategyType.CHAOS_TESTING: ['advanced_monitoring', 'chaos_readiness', 'high_availability'],
            StrategyType.HYBRID_TESTING: ['basic_monitoring', 'advanced_monitoring', 'auto_scaling']
        }
        
        return capability_map.get(strategy_type, ['basic_monitoring'])
    
    def _assess_system_risk(
        self,
        system_capabilities: Dict[str, Any],
        context: Dict[str, Any]
    ) -> str:
        """Assess overall system risk level"""
        risk_factors = 0
        
        # Capability-based risk factors
        if not system_capabilities.get('monitoring_enabled', False):
            risk_factors += 1
        if not system_capabilities.get('backup_systems', False):
            risk_factors += 1
        if not system_capabilities.get('rollback_capability', False):
            risk_factors += 1
        
        # Context-based risk factors
        if context.get('production_like', False):
            risk_factors += 1
        if context.get('critical_system', False):
            risk_factors += 2
        
        # Risk level determination
        if risk_factors <= 1:
            return 'low'
        elif risk_factors <= 3:
            return 'medium'
        else:
            return 'high'
    
    def _assess_chaos_readiness(self, system_capabilities: Dict[str, Any]) -> float:
        """Assess system readiness for chaos testing"""
        readiness_score = 0
        
        chaos_requirements = [
            'circuit_breakers',
            'health_checks',
            'monitoring_enabled',
            'auto_restart',
            'backup_systems',
            'rollback_capability'
        ]
        
        for requirement in chaos_requirements:
            if system_capabilities.get(requirement, False):
                readiness_score += 1
        
        return readiness_score / len(chaos_requirements)
    
    async def _score_strategies(
        self,
        strategy_options: List[StrategyOption],
        consensus: Dict[str, Any],
        system_capabilities: Dict[str, Any],
        resource_constraints: Dict[str, Any]
    ) -> List[Tuple[StrategyOption, float]]:
        """Score and rank strategy options"""
        scored_strategies = []
        
        for option in strategy_options:
            score = await self._calculate_strategy_score(
                option, consensus, system_capabilities, resource_constraints
            )
            scored_strategies.append((option, score))
        
        # Sort by score (descending)
        scored_strategies.sort(key=lambda x: x[1], reverse=True)
        
        return scored_strategies
    
    async def _calculate_strategy_score(
        self,
        option: StrategyOption,
        consensus: Dict[str, Any],
        system_capabilities: Dict[str, Any],
        resource_constraints: Dict[str, Any]
    ) -> float:
        """Calculate comprehensive score for strategy option"""
        score_components = []
        
        # Expert consensus score (40% weight)
        expert_score = option.expert_scores.get('overall', 0.5)
        score_components.append(expert_score * 0.4)
        
        # Success probability score (25% weight)
        score_components.append(option.success_probability * 0.25)
        
        # Resource feasibility score (15% weight)
        resource_score = self._calculate_resource_feasibility_score(
            option.resource_requirements, resource_constraints
        )
        score_components.append(resource_score * 0.15)
        
        # System compatibility score (10% weight)
        compatibility_score = self._calculate_compatibility_score(
            option.capabilities_required, system_capabilities
        )
        score_components.append(compatibility_score * 0.1)
        
        # Risk adjustment (10% weight - inverted, lower risk = higher score)
        risk_scores = {'low': 1.0, 'medium': 0.7, 'high': 0.4}
        risk_score = risk_scores.get(option.risk_level, 0.7)
        score_components.append(risk_score * 0.1)
        
        return sum(score_components)
    
    def _calculate_resource_feasibility_score(
        self,
        requirements: Dict[str, float],
        constraints: Dict[str, Any]
    ) -> float:
        """Calculate resource feasibility score"""
        if not constraints:
            return 0.8  # Default good score if no constraints
        
        feasibility_scores = []
        
        # Check CPU feasibility
        required_cpu = requirements.get('cpu_cores', 4)
        available_cpu = constraints.get('max_cpu_cores', 8)
        if available_cpu > 0:
            cpu_feasibility = min(1.0, available_cpu / required_cpu)
            feasibility_scores.append(cpu_feasibility)
        
        # Check memory feasibility
        required_memory = requirements.get('memory_gb', 8)
        available_memory = constraints.get('max_memory_gb', 16)
        if available_memory > 0:
            memory_feasibility = min(1.0, available_memory / required_memory)
            feasibility_scores.append(memory_feasibility)
        
        # Check network feasibility
        required_network = requirements.get('network_mbps', 100)
        available_network = constraints.get('max_network_mbps', 1000)
        if available_network > 0:
            network_feasibility = min(1.0, available_network / required_network)
            feasibility_scores.append(network_feasibility)
        
        if feasibility_scores:
            return sum(feasibility_scores) / len(feasibility_scores)
        else:
            return 0.8  # Default if no resource data
    
    def _calculate_compatibility_score(
        self,
        required_capabilities: List[str],
        system_capabilities: Dict[str, Any]
    ) -> float:
        """Calculate system compatibility score"""
        if not required_capabilities:
            return 1.0
        
        satisfied_capabilities = 0
        
        for capability in required_capabilities:
            capability_requirements = self.capability_requirements.get(capability, [])
            
            if capability_requirements:
                # Check if all requirements for this capability are met
                satisfied_requirements = sum(
                    1 for req in capability_requirements 
                    if system_capabilities.get(req, False)
                )
                
                if satisfied_requirements == len(capability_requirements):
                    satisfied_capabilities += 1
                else:
                    # Partial credit
                    satisfied_capabilities += satisfied_requirements / len(capability_requirements)
            else:
                # If no specific requirements defined, assume satisfied
                satisfied_capabilities += 1
        
        return satisfied_capabilities / len(required_capabilities)
    
    async def _select_optimal_strategy(
        self,
        scored_strategies: List[Tuple[StrategyOption, float]],
        context: Dict[str, Any],
        resource_constraints: Dict[str, Any]
    ) -> StrategySelectionResult:
        """Select optimal strategy from scored options"""
        
        if not scored_strategies:
            raise ValueError("No strategy options available")
        
        # Select highest scoring strategy
        selected_strategy, best_score = scored_strategies[0]
        
        # Generate selection reasoning
        reasoning = self._generate_selection_reasoning(
            selected_strategy, scored_strategies, context
        )
        
        # Calculate confidence score
        confidence = self._calculate_selection_confidence(
            selected_strategy, scored_strategies, best_score
        )
        
        # Get alternative strategies
        alternatives = [option for option, score in scored_strategies[1:4]]  # Top 3 alternatives
        
        return StrategySelectionResult(
            selected_strategy=selected_strategy,
            selection_reasoning=reasoning,
            confidence_score=confidence,
            alternative_strategies=alternatives,
            adaptation_parameters={},  # Will be filled later
            implementation_plan=[],    # Will be filled later
            risk_mitigation=[]        # Will be filled later
        )
    
    def _generate_selection_reasoning(
        self,
        selected: StrategyOption,
        all_strategies: List[Tuple[StrategyOption, float]],
        context: Dict[str, Any]
    ) -> str:
        """Generate reasoning for strategy selection"""
        reasoning_parts = []
        
        # Primary selection factors
        reasoning_parts.append(f"Selected {selected.name} with {selected.success_probability:.1%} success probability")
        reasoning_parts.append(f"Expert consensus score: {selected.expert_scores.get('overall', 0.5):.2f}")
        reasoning_parts.append(f"Strategy complexity: {selected.complexity.value}")
        reasoning_parts.append(f"Risk level: {selected.risk_level}")
        
        # Comparative analysis
        if len(all_strategies) > 1:
            best_score = all_strategies[0][1]
            second_best_score = all_strategies[1][1] if len(all_strategies) > 1 else 0
            score_margin = best_score - second_best_score
            
            if score_margin > 0.2:
                reasoning_parts.append(f"Clear preference with {score_margin:.2f} score advantage")
            elif score_margin > 0.1:
                reasoning_parts.append(f"Moderate preference with {score_margin:.2f} score advantage")
            else:
                reasoning_parts.append(f"Close decision with {score_margin:.2f} score margin")
        
        # Context considerations
        objectives = context.get('test_objectives', [])
        if objectives:
            reasoning_parts.append(f"Aligned with {len(objectives)} test objectives")
        
        return ". ".join(reasoning_parts)
    
    def _calculate_selection_confidence(
        self,
        selected: StrategyOption,
        all_strategies: List[Tuple[StrategyOption, float]],
        best_score: float
    ) -> float:
        """Calculate confidence in strategy selection"""
        
        # Base confidence from strategy score
        base_confidence = best_score
        
        # Adjust based on score distribution
        if len(all_strategies) > 1:
            scores = [score for _, score in all_strategies]
            score_variance = sum((s - best_score) ** 2 for s in scores) / len(scores)
            
            # Higher variance means clearer choice
            variance_factor = min(0.2, score_variance * 2)
            base_confidence += variance_factor
        
        # Adjust based on prerequisites satisfaction
        if not selected.prerequisites:
            base_confidence += 0.1  # Bonus for no prerequisites
        else:
            prerequisite_penalty = min(0.2, len(selected.prerequisites) * 0.05)
            base_confidence -= prerequisite_penalty
        
        # Adjust based on risk level
        risk_adjustments = {'low': 0.05, 'medium': 0, 'high': -0.1}
        base_confidence += risk_adjustments.get(selected.risk_level, 0)
        
        return max(0.3, min(0.95, base_confidence))  # Clamp between 30% and 95%
    
    async def _generate_adaptation_parameters(
        self,
        strategy: StrategyOption,
        context: Dict[str, Any],
        system_capabilities: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate adaptation parameters for the selected strategy"""
        
        base_params = {
            'monitoring_interval': 5.0,  # seconds
            'adaptation_threshold': 0.7,
            'max_adaptations': 10,
            'safety_threshold': 0.9
        }
        
        # Adjust based on strategy type
        if strategy.strategy_type in [StrategyType.STRESS_TESTING, StrategyType.CHAOS_TESTING]:
            base_params['monitoring_interval'] = 2.0  # More frequent monitoring
            base_params['safety_threshold'] = 0.95    # Higher safety threshold
        
        if strategy.strategy_type == StrategyType.ENDURANCE_TESTING:
            base_params['monitoring_interval'] = 30.0  # Less frequent for long tests
            base_params['max_adaptations'] = 20        # More adaptations allowed
        
        # Adjust based on complexity
        if strategy.complexity in [StrategyComplexity.COMPLEX, StrategyComplexity.ADVANCED]:
            base_params['adaptation_threshold'] = 0.8  # Higher threshold for complex strategies
        
        # System-specific adjustments
        if not system_capabilities.get('monitoring_enabled', False):
            base_params['monitoring_interval'] = 10.0  # Less frequent if monitoring is limited
        
        return base_params
    
    async def _create_implementation_plan(
        self,
        strategy: StrategyOption,
        context: Dict[str, Any]
    ) -> List[str]:
        """Create implementation plan for the selected strategy"""
        
        plan = []
        
        # Prerequisites phase
        if strategy.prerequisites:
            plan.append("Phase 1: Prerequisites validation and setup")
            for prereq in strategy.prerequisites:
                plan.append(f"  - {prereq}")
        
        # Preparation phase
        plan.append("Phase 2: Test environment preparation")
        plan.append("  - Configure monitoring and alerting")
        plan.append("  - Establish baseline metrics")
        plan.append("  - Prepare test data and scenarios")
        
        # Execution phase
        plan.append("Phase 3: Strategy execution")
        
        if strategy.strategy_type == StrategyType.LOAD_TESTING:
            plan.extend([
                "  - Gradual load ramp-up",
                "  - Sustained load execution",
                "  - Graceful load ramp-down"
            ])
        elif strategy.strategy_type == StrategyType.STRESS_TESTING:
            plan.extend([
                "  - Progressive load increase",
                "  - Breaking point identification",
                "  - Recovery validation"
            ])
        elif strategy.strategy_type == StrategyType.CHAOS_TESTING:
            plan.extend([
                "  - Failure injection execution",
                "  - Resilience validation",
                "  - Recovery time measurement"
            ])
        else:
            plan.extend([
                "  - Test scenario execution",
                "  - Real-time monitoring",
                "  - Performance validation"
            ])
        
        # Analysis phase
        plan.append("Phase 4: Results analysis and reporting")
        plan.append("  - Metrics analysis and interpretation")
        plan.append("  - Performance bottleneck identification")
        plan.append("  - Recommendations generation")
        
        return plan
    
    async def _identify_risk_mitigations(
        self,
        strategy: StrategyOption,
        system_capabilities: Dict[str, Any]
    ) -> List[str]:
        """Identify risk mitigation measures for the strategy"""
        
        mitigations = []
        
        # General risk mitigations
        mitigations.extend([
            "Implement comprehensive monitoring and alerting",
            "Establish clear rollback procedures",
            "Define emergency stop conditions"
        ])
        
        # Risk-level specific mitigations
        if strategy.risk_level == 'high':
            mitigations.extend([
                "Conduct dry-run testing in isolated environment",
                "Implement progressive execution with safety gates",
                "Ensure dedicated incident response team availability"
            ])
        elif strategy.risk_level == 'medium':
            mitigations.extend([
                "Implement automated safety checks",
                "Define clear escalation procedures"
            ])
        
        # Strategy-specific mitigations
        if strategy.strategy_type in [StrategyType.STRESS_TESTING, StrategyType.CHAOS_TESTING]:
            mitigations.extend([
                "Implement circuit breaker patterns",
                "Ensure system recovery capabilities",
                "Validate backup and failover systems"
            ])
        
        if strategy.strategy_type == StrategyType.SECURITY_TESTING:
            mitigations.extend([
                "Isolate test environment from production",
                "Implement security monitoring and logging",
                "Ensure data protection and privacy compliance"
            ])
        
        # System capability mitigations
        if not system_capabilities.get('auto_scaling', False):
            mitigations.append("Manual resource scaling procedures")
        
        if not system_capabilities.get('backup_systems', False):
            mitigations.append("Manual backup and recovery procedures")
        
        return mitigations
    
    def _store_selection(
        self,
        strategy: Dict[str, Any],
        consensus: Dict[str, Any],
        context: Dict[str, Any]
    ):
        """Store strategy selection for learning and improvement"""
        
        record = {
            'timestamp': time.time(),
            'selected_strategy': strategy['name'],
            'strategy_type': strategy['type'],
            'confidence': strategy['confidence'],
            'expert_consensus': consensus.get('confidence', 0.5),
            'context_complexity': len(context.get('test_objectives', [])),
            'resource_requirements': strategy['resource_requirements'],
            'success_probability': strategy['success_probability']
        }
        
        self.selection_history.append(record)
        
        # Keep only last 100 records
        if len(self.selection_history) > 100:
            self.selection_history = self.selection_history[-100:]
    
    def _generate_fallback_strategy(self) -> Dict[str, Any]:
        """Generate fallback strategy when selection fails"""
        
        return {
            'name': 'Basic Load Testing Strategy',
            'type': 'load_testing',
            'complexity': 'simple',
            'confidence': 0.6,
            'selection_reasoning': 'Fallback strategy due to selection failure',
            'resource_requirements': {
                'cpu_cores': 4,
                'memory_gb': 8,
                'network_mbps': 100,
                'storage_gb': 50,
                'test_instances': 2
            },
            'expected_duration': 30,
            'success_probability': 0.8,
            'risk_level': 'low',
            'adaptation_parameters': {
                'monitoring_interval': 5.0,
                'adaptation_threshold': 0.7,
                'max_adaptations': 5,
                'safety_threshold': 0.9
            },
            'implementation_plan': [
                'Phase 1: Basic monitoring setup',
                'Phase 2: Load test execution',
                'Phase 3: Results analysis'
            ],
            'risk_mitigations': [
                'Basic monitoring and alerting',
                'Manual intervention procedures'
            ],
            'alternative_strategies': []
        }
    
    def get_strategy_templates(self) -> Dict[str, Dict[str, Any]]:
        """Get available strategy templates"""
        return {k.value: v for k, v in self.strategy_templates.items()}
    
    def get_selection_history(self) -> List[Dict[str, Any]]:
        """Get strategy selection history"""
        return self.selection_history.copy()
    
    def get_capability_requirements(self) -> Dict[str, List[str]]:
        """Get capability requirements mapping"""
        return self.capability_requirements.copy()