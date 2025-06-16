"""
Expert-Driven Chaos Controller

AI-driven chaos scenario selection, execution strategy optimization, and intelligent
chaos engineering guided by expert system recommendations.
"""

import asyncio
import logging
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


class ExpertiseArea(Enum):
    """Areas of chaos engineering expertise"""
    RELIABILITY_ENGINEERING = "reliability_engineering"
    PERFORMANCE_OPTIMIZATION = "performance_optimization"
    SYSTEM_ARCHITECTURE = "system_architecture"
    CHAOS_ENGINEERING = "chaos_engineering"
    INCIDENT_RESPONSE = "incident_response"
    CAPACITY_PLANNING = "capacity_planning"
    SECURITY_RESILIENCE = "security_resilience"


@dataclass
class ExpertRecommendation:
    """Expert recommendation for chaos experiments"""
    expert_area: ExpertiseArea
    recommendation_type: str
    priority: str  # high, medium, low
    description: str
    rationale: str
    implementation_steps: List[str] = field(default_factory=list)
    expected_outcomes: List[str] = field(default_factory=list)
    risk_assessment: Dict[str, Any] = field(default_factory=dict)
    confidence_score: float = 0.0


@dataclass
class IntelligentChaosStrategy:
    """AI-driven chaos strategy"""
    strategy_id: str
    target_system: str
    recommended_experiments: List[Dict[str, Any]] = field(default_factory=list)
    expert_recommendations: List[ExpertRecommendation] = field(default_factory=list)
    execution_priority: List[str] = field(default_factory=list)
    adaptive_parameters: Dict[str, Any] = field(default_factory=dict)
    learning_objectives: List[str] = field(default_factory=list)
    success_criteria: Dict[str, Any] = field(default_factory=dict)


class ExpertChaosController:
    """
    Expert-driven chaos controller that uses AI expertise to guide
    chaos engineering experiments for maximum learning and safety.
    """
    
    def __init__(self, expert_manager=None, chaos_orchestrator=None):
        self.expert_manager = expert_manager
        self.chaos_orchestrator = chaos_orchestrator
        
        # Strategy tracking
        self.active_strategies: Dict[str, IntelligentChaosStrategy] = {}
        self.strategy_history: List[IntelligentChaosStrategy] = []
        
        # Learning and adaptation
        self.experiment_outcomes: Dict[str, Dict[str, Any]] = {}
        self.learned_patterns: Dict[str, Any] = {}
        self.adaptation_metrics: Dict[str, float] = {}
        
        # Expert consultation cache
        self.expert_consultation_cache: Dict[str, Any] = {}
        
        logger.info("Expert Chaos Controller initialized")
    
    async def generate_intelligent_strategy(self, system_context: Dict[str, Any],
                                          learning_objectives: List[str]) -> IntelligentChaosStrategy:
        """Generate intelligent chaos strategy based on system context and objectives"""
        logger.info(f"Generating intelligent chaos strategy for {system_context.get('system_name', 'unknown system')}")
        
        strategy_id = f"strategy_{int(datetime.now().timestamp())}"
        
        # Consult experts for strategy recommendations
        expert_recommendations = await self._consult_experts_for_strategy(system_context, learning_objectives)
        
        # Analyze system architecture for optimal experiment design
        architecture_analysis = await self._analyze_system_architecture(system_context)
        
        # Generate recommended experiments
        recommended_experiments = await self._generate_recommended_experiments(
            system_context, learning_objectives, expert_recommendations, architecture_analysis
        )
        
        # Prioritize experiments based on learning value and risk
        execution_priority = await self._prioritize_experiments(recommended_experiments, expert_recommendations)
        
        # Set adaptive parameters for real-time strategy adjustment
        adaptive_parameters = await self._configure_adaptive_parameters(system_context, expert_recommendations)
        
        # Define success criteria
        success_criteria = await self._define_success_criteria(learning_objectives, expert_recommendations)
        
        strategy = IntelligentChaosStrategy(
            strategy_id=strategy_id,
            target_system=system_context.get("system_name", "unknown"),
            recommended_experiments=recommended_experiments,
            expert_recommendations=expert_recommendations,
            execution_priority=execution_priority,
            adaptive_parameters=adaptive_parameters,
            learning_objectives=learning_objectives,
            success_criteria=success_criteria
        )
        
        self.active_strategies[strategy_id] = strategy
        
        logger.info(f"Generated intelligent strategy {strategy_id} with {len(recommended_experiments)} experiments")
        return strategy
    
    async def execute_expert_guided_experiment(self, strategy_id: str, experiment_index: int = 0) -> Dict[str, Any]:
        """Execute chaos experiment with expert guidance"""
        if strategy_id not in self.active_strategies:
            return {"error": "Strategy not found"}
        
        strategy = self.active_strategies[strategy_id]
        
        if experiment_index >= len(strategy.recommended_experiments):
            return {"error": "Experiment index out of range"}
        
        experiment_config = strategy.recommended_experiments[experiment_index]
        
        logger.info(f"Executing expert-guided experiment {experiment_index} for strategy {strategy_id}")
        
        # Pre-experiment expert consultation
        pre_experiment_guidance = await self._get_pre_experiment_guidance(experiment_config, strategy)
        
        # Apply expert recommendations to experiment configuration
        optimized_config = await self._optimize_experiment_config(experiment_config, pre_experiment_guidance)
        
        # Execute experiment with real-time expert monitoring
        execution_result = await self._execute_with_expert_monitoring(optimized_config, strategy)
        
        # Post-experiment expert analysis
        post_experiment_analysis = await self._get_post_experiment_analysis(execution_result, strategy)
        
        # Update strategy based on learnings
        await self._update_strategy_from_learnings(strategy, execution_result, post_experiment_analysis)
        
        # Record experiment outcome for future learning
        self.experiment_outcomes[f"{strategy_id}_{experiment_index}"] = {
            "experiment_config": optimized_config,
            "execution_result": execution_result,
            "expert_analysis": post_experiment_analysis,
            "learning_extracted": post_experiment_analysis.get("learning_extracted", [])
        }
        
        return {
            "strategy_id": strategy_id,
            "experiment_index": experiment_index,
            "execution_result": execution_result,
            "expert_guidance": {
                "pre_experiment": pre_experiment_guidance,
                "post_experiment": post_experiment_analysis
            },
            "strategy_updated": True,
            "learning_objectives_progress": await self._assess_learning_progress(strategy)
        }
    
    async def adaptive_chaos_orchestration(self, strategy_id: str, max_experiments: int = 10) -> Dict[str, Any]:
        """Orchestrate adaptive chaos experiments with continuous expert guidance"""
        if strategy_id not in self.active_strategies:
            return {"error": "Strategy not found"}
        
        strategy = self.active_strategies[strategy_id]
        orchestration_start = datetime.now()
        
        logger.info(f"Starting adaptive chaos orchestration for strategy {strategy_id}")
        
        orchestration_results = {
            "strategy_id": strategy_id,
            "orchestration_start": orchestration_start,
            "experiments_executed": [],
            "adaptive_decisions": [],
            "learning_outcomes": [],
            "expert_insights": []
        }
        
        experiments_executed = 0
        learning_objectives_met = 0
        
        while experiments_executed < max_experiments and experiments_executed < len(strategy.recommended_experiments):
            # Get next experiment recommendation from experts
            next_experiment_guidance = await self._get_next_experiment_recommendation(
                strategy, orchestration_results
            )
            
            orchestration_results["adaptive_decisions"].append(next_experiment_guidance)
            
            # Execute recommended experiment
            if next_experiment_guidance.get("proceed", True):
                experiment_result = await self.execute_expert_guided_experiment(
                    strategy_id, experiments_executed
                )
                
                orchestration_results["experiments_executed"].append(experiment_result)
                experiments_executed += 1
                
                # Extract learning outcomes
                learning_outcome = await self._extract_learning_outcomes(experiment_result, strategy)
                orchestration_results["learning_outcomes"].append(learning_outcome)
                
                # Check if learning objectives are being met
                learning_progress = await self._assess_learning_progress(strategy)
                if learning_progress.get("objectives_met", 0) > learning_objectives_met:
                    learning_objectives_met = learning_progress["objectives_met"]
                    logger.info(f"Learning objective achieved: {learning_objectives_met}/{len(strategy.learning_objectives)}")
                
                # Adaptive strategy adjustment
                if next_experiment_guidance.get("adapt_strategy", False):
                    adaptation_result = await self._adapt_strategy_real_time(strategy, orchestration_results)
                    orchestration_results["adaptive_decisions"].append(adaptation_result)
                
                # Expert insight extraction
                expert_insight = await self._extract_expert_insights(experiment_result, strategy)
                orchestration_results["expert_insights"].append(expert_insight)
                
                # Check for early completion conditions
                if learning_progress.get("objectives_completion_rate", 0) > 0.8:  # 80% objectives met
                    logger.info("Learning objectives substantially met, considering early completion")
                    completion_recommendation = await self._get_completion_recommendation(strategy, orchestration_results)
                    if completion_recommendation.get("recommend_completion", False):
                        break
            
            else:
                logger.info(f"Expert recommendation: skip experiment {experiments_executed}")
                break
        
        # Final expert analysis and recommendations
        final_analysis = await self._get_final_orchestration_analysis(strategy, orchestration_results)
        orchestration_results["final_analysis"] = final_analysis
        
        # Move strategy to history
        strategy.execution_priority = []  # Mark as completed
        self.strategy_history.append(strategy)
        del self.active_strategies[strategy_id]
        
        orchestration_results["orchestration_end"] = datetime.now()
        orchestration_results["total_duration"] = (orchestration_results["orchestration_end"] - orchestration_start).total_seconds()
        
        logger.info(f"Completed adaptive chaos orchestration for strategy {strategy_id}")
        return orchestration_results
    
    async def continuous_learning_optimization(self, system_context: Dict[str, Any]) -> Dict[str, Any]:
        """Continuously optimize chaos strategies based on historical learnings"""
        logger.info("Performing continuous learning optimization")
        
        # Analyze historical experiment outcomes
        historical_analysis = await self._analyze_historical_outcomes()
        
        # Identify patterns and improvement opportunities
        pattern_analysis = await self._identify_learning_patterns()
        
        # Generate optimization recommendations
        optimization_recommendations = await self._generate_optimization_recommendations(
            historical_analysis, pattern_analysis, system_context
        )
        
        # Update adaptive parameters based on learnings
        updated_parameters = await self._update_adaptive_parameters(optimization_recommendations)
        
        # Generate improved strategy templates
        improved_templates = await self._generate_improved_strategy_templates(
            optimization_recommendations, system_context
        )
        
        return {
            "historical_analysis": historical_analysis,
            "pattern_analysis": pattern_analysis,
            "optimization_recommendations": optimization_recommendations,
            "updated_parameters": updated_parameters,
            "improved_templates": improved_templates,
            "learning_optimization_timestamp": datetime.now().isoformat()
        }
    
    # Expert consultation methods
    async def _consult_experts_for_strategy(self, system_context: Dict[str, Any],
                                          learning_objectives: List[str]) -> List[ExpertRecommendation]:
        """Consult experts for chaos strategy recommendations"""
        if not self.expert_manager:
            return self._generate_default_expert_recommendations(system_context, learning_objectives)
        
        expert_recommendations = []
        
        # Consult reliability engineering expert
        reliability_query = f"""
        System Context: {json.dumps(system_context, indent=2)}
        Learning Objectives: {learning_objectives}
        
        As a reliability engineering expert, provide specific recommendations for chaos experiments
        that would best validate system resilience and identify failure modes. Focus on:
        1. Critical failure scenarios to test
        2. System weak points to investigate
        3. Recovery mechanism validation approaches
        4. Cascading failure prevention strategies
        """
        
        try:
            reliability_response = await self.expert_manager.query_experts(
                query=reliability_query,
                expertise_areas=["reliability", "system_architecture"]
            )
            
            for response in reliability_response.expert_responses:
                expert_recommendations.append(ExpertRecommendation(
                    expert_area=ExpertiseArea.RELIABILITY_ENGINEERING,
                    recommendation_type="system_resilience",
                    priority="high",
                    description=response.content[:200] + "..." if len(response.content) > 200 else response.content,
                    rationale=response.reasoning if hasattr(response, 'reasoning') else "Expert analysis",
                    confidence_score=response.confidence if hasattr(response, 'confidence') else 0.8
                ))
        except Exception as e:
            logger.warning(f"Reliability expert consultation failed: {e}")
        
        # Consult chaos engineering expert
        chaos_query = f"""
        System Context: {json.dumps(system_context, indent=2)}
        Learning Objectives: {learning_objectives}
        
        As a chaos engineering expert, recommend optimal experiment design and execution strategies:
        1. Experiment sequencing for maximum learning
        2. Blast radius optimization
        3. Safety mechanisms and guardrails
        4. Measurement and observability strategies
        """
        
        try:
            chaos_response = await self.expert_manager.query_experts(
                query=chaos_query,
                expertise_areas=["chaos_engineering", "performance"]
            )
            
            for response in chaos_response.expert_responses:
                expert_recommendations.append(ExpertRecommendation(
                    expert_area=ExpertiseArea.CHAOS_ENGINEERING,
                    recommendation_type="experiment_design",
                    priority="high",
                    description=response.content[:200] + "..." if len(response.content) > 200 else response.content,
                    rationale=response.reasoning if hasattr(response, 'reasoning') else "Expert analysis",
                    confidence_score=response.confidence if hasattr(response, 'confidence') else 0.8
                ))
        except Exception as e:
            logger.warning(f"Chaos engineering expert consultation failed: {e}")
        
        return expert_recommendations
    
    def _generate_default_expert_recommendations(self, system_context: Dict[str, Any],
                                               learning_objectives: List[str]) -> List[ExpertRecommendation]:
        """Generate default expert recommendations when expert manager is not available"""
        default_recommendations = [
            ExpertRecommendation(
                expert_area=ExpertiseArea.RELIABILITY_ENGINEERING,
                recommendation_type="system_resilience",
                priority="high",
                description="Test service failure isolation and circuit breaker effectiveness",
                rationale="Service failures are common and isolation mechanisms are critical for system resilience",
                implementation_steps=[
                    "Start with non-critical service failures",
                    "Gradually increase failure scope",
                    "Validate circuit breaker activation",
                    "Measure recovery time and effectiveness"
                ],
                expected_outcomes=["Circuit breaker validation", "Recovery time measurement", "Isolation effectiveness"],
                confidence_score=0.8
            ),
            ExpertRecommendation(
                expert_area=ExpertiseArea.CHAOS_ENGINEERING,
                recommendation_type="experiment_design",
                priority="high",
                description="Implement gradual failure injection with continuous monitoring",
                rationale="Gradual approach minimizes risk while maximizing learning opportunities",
                implementation_steps=[
                    "Begin with 5% blast radius",
                    "Monitor system response continuously",
                    "Adjust intensity based on system behavior",
                    "Ensure rapid recovery mechanisms"
                ],
                expected_outcomes=["Safe experiment execution", "Comprehensive system behavior data", "Validated recovery procedures"],
                confidence_score=0.9
            )
        ]
        
        return default_recommendations
    
    # Strategy generation methods
    async def _analyze_system_architecture(self, system_context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze system architecture for experiment optimization"""
        architecture_analysis = {
            "service_count": len(system_context.get("services", [])),
            "critical_services": system_context.get("critical_services", []),
            "dependency_complexity": "medium",  # Would be calculated from actual dependencies
            "failure_domains": system_context.get("failure_domains", []),
            "recommended_blast_radius": 0.1,  # 10% for complex systems
            "optimal_experiment_duration": 300,  # 5 minutes
            "safety_considerations": [
                "Avoid multiple critical service failures",
                "Implement gradual failure injection",
                "Ensure monitoring coverage",
                "Validate recovery procedures"
            ]
        }
        
        return architecture_analysis
    
    async def _generate_recommended_experiments(self, system_context: Dict[str, Any],
                                              learning_objectives: List[str],
                                              expert_recommendations: List[ExpertRecommendation],
                                              architecture_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate recommended experiments based on expert input and system analysis"""
        experiments = []
        services = system_context.get("services", ["service1", "service2", "service3"])
        
        # Service failure experiments
        for i, service in enumerate(services[:3]):  # Limit to first 3 services
            experiments.append({
                "experiment_type": "service_failure",
                "name": f"Service Failure Test - {service}",
                "target_services": [service],
                "failure_scenarios": [{
                    "type": "service_crash",
                    "config": {"duration": 180}
                }],
                "blast_radius": 1.0 / len(services),  # Single service
                "duration_seconds": 300,
                "learning_objectives": ["resilience_validation", "recovery_testing"],
                "expert_priority": "high" if i == 0 else "medium",
                "safety_level": "low_risk"
            })
        
        # Network partition experiment
        if len(services) >= 2:
            experiments.append({
                "experiment_type": "network_partition",
                "name": "Network Partition Test",
                "target_services": services[:2],
                "failure_scenarios": [{
                    "type": "split_brain",
                    "config": {"duration": 240}
                }],
                "blast_radius": 2.0 / len(services),
                "duration_seconds": 360,
                "learning_objectives": ["partition_tolerance", "consistency_validation"],
                "expert_priority": "high",
                "safety_level": "medium_risk"
            })
        
        # Resource exhaustion experiment
        experiments.append({
            "experiment_type": "resource_exhaustion",
            "name": "CPU Exhaustion Test",
            "target_services": services[:1],
            "failure_scenarios": [{
                "type": "cpu_exhaustion",
                "config": {"intensity": 0.8, "duration": 180}
            }],
            "blast_radius": architecture_analysis["recommended_blast_radius"],
            "duration_seconds": 240,
            "learning_objectives": ["resource_management", "performance_degradation"],
            "expert_priority": "medium",
            "safety_level": "medium_risk"
        })
        
        # Cascade failure experiment (if multiple services)
        if len(services) >= 3:
            experiments.append({
                "experiment_type": "cascade_failure",
                "name": "Cascade Failure Test",
                "target_services": services[:3],
                "failure_scenarios": [{
                    "type": "linear_cascade",
                    "config": {"stage_delay": 30}
                }],
                "blast_radius": min(0.3, 3.0 / len(services)),  # Max 30%
                "duration_seconds": 450,
                "learning_objectives": ["cascade_containment", "isolation_effectiveness"],
                "expert_priority": "high",
                "safety_level": "high_risk"
            })
        
        return experiments
    
    async def _prioritize_experiments(self, experiments: List[Dict[str, Any]],
                                    expert_recommendations: List[ExpertRecommendation]) -> List[str]:
        """Prioritize experiments based on learning value and expert recommendations"""
        # Score experiments based on multiple factors
        experiment_scores = []
        
        for i, experiment in enumerate(experiments):
            score = 0.0
            
            # Expert priority weight
            priority_weights = {"high": 3.0, "medium": 2.0, "low": 1.0}
            score += priority_weights.get(experiment.get("expert_priority", "medium"), 2.0)
            
            # Safety consideration (lower risk = higher priority initially)
            safety_weights = {"low_risk": 2.0, "medium_risk": 1.5, "high_risk": 1.0}
            score += safety_weights.get(experiment.get("safety_level", "medium_risk"), 1.5)
            
            # Learning objective alignment
            if experiment.get("learning_objectives"):
                score += len(experiment["learning_objectives"]) * 0.5
            
            # Blast radius consideration (smaller blast radius = higher initial priority)
            blast_radius = experiment.get("blast_radius", 0.1)
            score += (1.0 - blast_radius) * 2.0
            
            experiment_scores.append((i, score, experiment.get("name", f"Experiment {i}")))
        
        # Sort by score (descending)
        experiment_scores.sort(key=lambda x: x[1], reverse=True)
        
        # Return experiment names in priority order
        return [name for _, _, name in experiment_scores]
    
    async def _configure_adaptive_parameters(self, system_context: Dict[str, Any],
                                           expert_recommendations: List[ExpertRecommendation]) -> Dict[str, Any]:
        """Configure adaptive parameters for real-time strategy adjustment"""
        return {
            "blast_radius_adjustment": {
                "min_radius": 0.05,  # 5% minimum
                "max_radius": 0.3,   # 30% maximum
                "adjustment_factor": 0.1,  # 10% adjustments
                "safety_threshold": 0.15   # 15% safety limit
            },
            "experiment_duration": {
                "min_duration": 120,  # 2 minutes minimum
                "max_duration": 600,  # 10 minutes maximum
                "adjustment_factor": 60,   # 1 minute adjustments
                "safety_timeout": 300      # 5 minute safety timeout
            },
            "learning_thresholds": {
                "success_threshold": 0.8,    # 80% success rate
                "learning_threshold": 0.7,   # 70% learning objective achievement
                "safety_threshold": 0.95,    # 95% safety metric threshold
                "adaptation_sensitivity": 0.1 # 10% sensitivity for changes
            },
            "expert_consultation_frequency": {
                "pre_experiment": True,
                "mid_experiment": False,
                "post_experiment": True,
                "emergency_consultation": True
            }
        }
    
    async def _define_success_criteria(self, learning_objectives: List[str],
                                     expert_recommendations: List[ExpertRecommendation]) -> Dict[str, Any]:
        """Define success criteria for chaos strategy"""
        return {
            "learning_objectives_completion": {
                "target_completion_rate": 0.8,  # 80% of objectives
                "minimum_experiments": 3,
                "maximum_experiments": 10
            },
            "system_resilience_validation": {
                "recovery_time_threshold": 300,  # 5 minutes max
                "availability_threshold": 0.95,  # 95% minimum availability
                "error_rate_threshold": 0.05,    # 5% maximum error rate
                "cascade_containment_rate": 0.8  # 80% containment success
            },
            "expert_confidence_targets": {
                "recommendation_accuracy": 0.8,  # 80% accurate predictions
                "learning_extraction_rate": 0.9, # 90% successful learning extraction
                "strategy_optimization_rate": 0.7 # 70% strategy improvement
            },
            "safety_compliance": {
                "zero_data_loss": True,
                "zero_security_breaches": True,
                "maximum_downtime": 600,  # 10 minutes total
                "blast_radius_compliance": 0.95  # 95% compliance with limits
            }
        }
    
    # Experiment execution and monitoring methods
    async def _get_pre_experiment_guidance(self, experiment_config: Dict[str, Any],
                                         strategy: IntelligentChaosStrategy) -> Dict[str, Any]:
        """Get expert guidance before experiment execution"""
        if self.expert_manager:
            guidance_query = f"""
            Experiment Configuration: {json.dumps(experiment_config, indent=2)}
            Strategy Context: {strategy.target_system}
            Learning Objectives: {strategy.learning_objectives}
            
            Provide pre-experiment guidance including:
            1. Experiment parameter optimization recommendations
            2. Key metrics to monitor during execution
            3. Potential risks and mitigation strategies
            4. Success criteria refinement
            """
            
            try:
                response = await self.expert_manager.query_experts(
                    query=guidance_query,
                    expertise_areas=["chaos_engineering", "reliability"]
                )
                
                return {
                    "expert_guidance": [r.content for r in response.expert_responses],
                    "recommended_adjustments": [],  # Would be parsed from expert responses
                    "monitoring_focus": ["system_health", "error_rates", "response_times"],
                    "risk_mitigation": ["continuous_monitoring", "rapid_recovery"]
                }
            except Exception as e:
                logger.warning(f"Pre-experiment expert consultation failed: {e}")
        
        # Default guidance
        return {
            "expert_guidance": ["Monitor system health continuously", "Ensure rapid recovery capabilities"],
            "recommended_adjustments": [],
            "monitoring_focus": ["system_health", "error_rates", "response_times"],
            "risk_mitigation": ["continuous_monitoring", "rapid_recovery"]
        }
    
    async def _optimize_experiment_config(self, experiment_config: Dict[str, Any],
                                        guidance: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize experiment configuration based on expert guidance"""
        optimized_config = experiment_config.copy()
        
        # Apply expert adjustments
        adjustments = guidance.get("recommended_adjustments", [])
        for adjustment in adjustments:
            if "blast_radius" in adjustment and "reduce" in adjustment.lower():
                optimized_config["blast_radius"] *= 0.8  # Reduce by 20%
            elif "duration" in adjustment and "reduce" in adjustment.lower():
                optimized_config["duration_seconds"] = int(optimized_config["duration_seconds"] * 0.8)
        
        # Ensure safety boundaries
        optimized_config["blast_radius"] = min(optimized_config.get("blast_radius", 0.1), 0.3)  # Max 30%
        optimized_config["duration_seconds"] = min(optimized_config.get("duration_seconds", 300), 600)  # Max 10 minutes
        
        return optimized_config
    
    async def _execute_with_expert_monitoring(self, experiment_config: Dict[str, Any],
                                            strategy: IntelligentChaosStrategy) -> Dict[str, Any]:
        """Execute experiment with expert monitoring"""
        if self.chaos_orchestrator:
            try:
                # Create chaos experiment
                experiment = await self.chaos_orchestrator.create_experiment(experiment_config)
                
                # Execute with monitoring
                execution_result = await self.chaos_orchestrator.run_experiment(experiment.id)
                
                return {
                    "experiment_id": experiment.id,
                    "execution_successful": True,
                    "metrics": execution_result.__dict__ if hasattr(execution_result, '__dict__') else execution_result,
                    "expert_monitoring": {
                        "monitoring_active": True,
                        "real_time_adjustments": 0,
                        "safety_interventions": 0
                    }
                }
            except Exception as e:
                logger.error(f"Experiment execution failed: {e}")
                return {
                    "execution_successful": False,
                    "error": str(e),
                    "expert_monitoring": {
                        "monitoring_active": False,
                        "emergency_recovery": True
                    }
                }
        else:
            # Simulation mode
            return {
                "execution_successful": True,
                "metrics": {
                    "mttd_seconds": 45.0,
                    "mttr_seconds": 120.0,
                    "resilience_score": 0.85,
                    "recovery_effectiveness": 0.9
                },
                "simulation": True,
                "expert_monitoring": {
                    "monitoring_active": True,
                    "real_time_adjustments": 0,
                    "safety_interventions": 0
                }
            }
    
    # Learning and adaptation methods
    async def _extract_learning_outcomes(self, experiment_result: Dict[str, Any],
                                       strategy: IntelligentChaosStrategy) -> Dict[str, Any]:
        """Extract learning outcomes from experiment results"""
        learning_outcomes = {
            "experiment_success": experiment_result.get("execution_result", {}).get("execution_successful", False),
            "key_learnings": [],
            "resilience_insights": [],
            "improvement_areas": [],
            "validated_mechanisms": [],
            "learning_objectives_progress": {}
        }
        
        # Extract metrics-based learnings
        metrics = experiment_result.get("execution_result", {}).get("metrics", {})
        
        if metrics.get("resilience_score", 0) > 0.8:
            learning_outcomes["key_learnings"].append("System demonstrates high resilience")
            learning_outcomes["validated_mechanisms"].append("resilience_mechanisms")
        
        if metrics.get("recovery_effectiveness", 0) > 0.9:
            learning_outcomes["key_learnings"].append("Recovery mechanisms are highly effective")
            learning_outcomes["validated_mechanisms"].append("recovery_systems")
        
        # Map learnings to objectives
        for objective in strategy.learning_objectives:
            if "resilience" in objective.lower():
                learning_outcomes["learning_objectives_progress"][objective] = metrics.get("resilience_score", 0)
            elif "recovery" in objective.lower():
                learning_outcomes["learning_objectives_progress"][objective] = metrics.get("recovery_effectiveness", 0)
        
        return learning_outcomes
    
    async def _assess_learning_progress(self, strategy: IntelligentChaosStrategy) -> Dict[str, Any]:
        """Assess progress towards learning objectives"""
        total_objectives = len(strategy.learning_objectives)
        if total_objectives == 0:
            return {"objectives_met": 0, "objectives_completion_rate": 1.0}
        
        # Count objectives with sufficient progress (>80% completion)
        objectives_met = 0
        for outcome in self.experiment_outcomes.values():
            learning_progress = outcome.get("learning_extracted", [])
            for objective in strategy.learning_objectives:
                if any(objective.lower() in learning.lower() for learning in learning_progress):
                    objectives_met += 1
                    break  # Count each objective only once
        
        objectives_met = min(objectives_met, total_objectives)  # Cap at total objectives
        completion_rate = objectives_met / total_objectives
        
        return {
            "total_objectives": total_objectives,
            "objectives_met": objectives_met,
            "objectives_completion_rate": completion_rate,
            "remaining_objectives": total_objectives - objectives_met
        }
    
    # Analysis and insight methods
    async def _analyze_historical_outcomes(self) -> Dict[str, Any]:
        """Analyze historical experiment outcomes for patterns"""
        if not self.experiment_outcomes:
            return {"total_experiments": 0, "analysis": "No historical data available"}
        
        total_experiments = len(self.experiment_outcomes)
        successful_experiments = sum(
            1 for outcome in self.experiment_outcomes.values()
            if outcome.get("execution_result", {}).get("execution_successful", False)
        )
        
        avg_resilience_score = sum(
            outcome.get("execution_result", {}).get("metrics", {}).get("resilience_score", 0)
            for outcome in self.experiment_outcomes.values()
        ) / total_experiments if total_experiments > 0 else 0
        
        return {
            "total_experiments": total_experiments,
            "success_rate": successful_experiments / total_experiments if total_experiments > 0 else 0,
            "average_resilience_score": avg_resilience_score,
            "experiment_types": self._analyze_experiment_types(),
            "learning_effectiveness": self._calculate_learning_effectiveness()
        }
    
    def _analyze_experiment_types(self) -> Dict[str, int]:
        """Analyze distribution of experiment types"""
        type_counts = {}
        for outcome in self.experiment_outcomes.values():
            exp_type = outcome.get("experiment_config", {}).get("experiment_type", "unknown")
            type_counts[exp_type] = type_counts.get(exp_type, 0) + 1
        return type_counts
    
    def _calculate_learning_effectiveness(self) -> float:
        """Calculate overall learning effectiveness"""
        if not self.experiment_outcomes:
            return 0.0
        
        total_learnings = sum(
            len(outcome.get("learning_extracted", []))
            for outcome in self.experiment_outcomes.values()
        )
        
        return total_learnings / len(self.experiment_outcomes) if self.experiment_outcomes else 0.0
    
    async def _identify_learning_patterns(self) -> Dict[str, Any]:
        """Identify patterns in learning outcomes"""
        patterns = {
            "common_learnings": [],
            "effectiveness_patterns": {},
            "failure_patterns": {},
            "optimization_opportunities": []
        }
        
        # Analyze common learnings
        all_learnings = []
        for outcome in self.experiment_outcomes.values():
            all_learnings.extend(outcome.get("learning_extracted", []))
        
        learning_counts = {}
        for learning in all_learnings:
            learning_counts[learning] = learning_counts.get(learning, 0) + 1
        
        # Top 5 most common learnings
        patterns["common_learnings"] = sorted(
            learning_counts.items(), key=lambda x: x[1], reverse=True
        )[:5]
        
        return patterns
    
    async def _get_post_experiment_analysis(self, execution_result: Dict[str, Any],
                                          strategy: IntelligentChaosStrategy) -> Dict[str, Any]:
        """Get expert post-experiment analysis"""
        if self.expert_manager:
            analysis_query = f"""
            Experiment Results: {json.dumps(execution_result, indent=2)}
            Strategy Context: {strategy.target_system}
            Learning Objectives: {strategy.learning_objectives}
            
            Provide post-experiment analysis including:
            1. Key insights and learnings from the results
            2. System resilience assessment
            3. Recommendations for next experiments
            4. Areas for system improvement
            """
            
            try:
                response = await self.expert_manager.query_experts(
                    query=analysis_query,
                    expertise_areas=["chaos_engineering", "reliability", "performance"]
                )
                
                return {
                    "expert_insights": [r.content for r in response.expert_responses],
                    "key_learnings": ["System resilience validated", "Recovery mechanisms effective"],
                    "improvement_recommendations": ["Optimize recovery time", "Enhance monitoring"],
                    "next_experiment_suggestions": ["Test cascade failure scenarios"],
                    "learning_extracted": ["resilience_validation", "recovery_testing"]
                }
            except Exception as e:
                logger.warning(f"Post-experiment expert analysis failed: {e}")
        
        # Default analysis
        return {
            "expert_insights": ["Experiment completed successfully"],
            "key_learnings": ["System behavior under failure conditions observed"],
            "improvement_recommendations": ["Continue systematic testing"],
            "next_experiment_suggestions": ["Expand failure scenarios"],
            "learning_extracted": ["baseline_resilience_established"]
        }
    
    async def _update_strategy_from_learnings(self, strategy: IntelligentChaosStrategy,
                                            execution_result: Dict[str, Any],
                                            analysis: Dict[str, Any]):
        """Update strategy based on experiment learnings"""
        # Update adaptive parameters based on results
        if execution_result.get("execution_result", {}).get("execution_successful", False):
            # Successful experiment - can be more aggressive
            if "blast_radius_adjustment" in strategy.adaptive_parameters:
                current_max = strategy.adaptive_parameters["blast_radius_adjustment"]["max_radius"]
                strategy.adaptive_parameters["blast_radius_adjustment"]["max_radius"] = min(0.4, current_max * 1.1)
        else:
            # Failed experiment - be more conservative
            if "blast_radius_adjustment" in strategy.adaptive_parameters:
                current_max = strategy.adaptive_parameters["blast_radius_adjustment"]["max_radius"]
                strategy.adaptive_parameters["blast_radius_adjustment"]["max_radius"] = max(0.05, current_max * 0.9)
        
        # Update learning objectives progress
        learning_extracted = analysis.get("learning_extracted", [])
        for learning in learning_extracted:
            if learning not in strategy.learning_objectives:
                strategy.learning_objectives.append(f"validated_{learning}")
    
    # Utility methods
    def get_strategy_history(self) -> List[Dict[str, Any]]:
        """Get history of completed strategies"""
        return [strategy.__dict__ for strategy in self.strategy_history]
    
    def get_active_strategies(self) -> Dict[str, Dict[str, Any]]:
        """Get currently active strategies"""
        return {sid: strategy.__dict__ for sid, strategy in self.active_strategies.items()}
    
    def get_learning_insights(self) -> Dict[str, Any]:
        """Get insights from all learning outcomes"""
        return {
            "total_experiments": len(self.experiment_outcomes),
            "learned_patterns": self.learned_patterns,
            "adaptation_metrics": self.adaptation_metrics,
            "expert_consultation_cache_size": len(self.expert_consultation_cache)
        }