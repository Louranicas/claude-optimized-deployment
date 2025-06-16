"""
Expert Scaling - Expert-driven scaling decisions

This module provides expert-driven scaling capabilities using the Circle of Experts
system to make intelligent scaling decisions based on AI recommendations.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json
import math

try:
    from ....src.circle_of_experts import CircleOfExperts, QueryRequest
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
                        self.content = "Mock expert response"
                return MockResponse()
        
        class QueryRequest:
            def __init__(self, **kwargs):
                pass


class ExpertScalingMode(Enum):
    ADVISORY = "advisory"
    AUTOMATIC = "automatic"
    HYBRID = "hybrid"


class ScalingConfidenceLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ExpertRecommendation:
    """Expert scaling recommendation"""
    expert_id: str
    recommendation_type: str  # scale_up, scale_down, optimize, maintain
    confidence: float
    reasoning: str
    suggested_capacity: Optional[Dict[str, Any]] = None
    risk_assessment: Dict[str, float] = field(default_factory=dict)
    timeline: Optional[str] = None
    conditions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExpertConsensus:
    """Expert consensus result"""
    consensus_reached: bool
    consensus_recommendation: str
    confidence_level: ScalingConfidenceLevel
    agreement_percentage: float
    conflicting_opinions: List[str]
    final_decision: Dict[str, Any]
    expert_votes: Dict[str, str]
    reasoning_summary: str


class ExpertScaling:
    """
    Expert-driven scaling decision system
    
    Leverages the Circle of Experts system to make intelligent scaling
    decisions based on AI expert recommendations and consensus.
    """
    
    def __init__(self, circle_of_experts: CircleOfExperts):
        self.logger = logging.getLogger(__name__)
        self.circle_of_experts = circle_of_experts
        
        # Expert scaling configuration
        self.scaling_mode = ExpertScalingMode.HYBRID
        self.confidence_threshold = 0.8
        self.consensus_threshold = 0.7
        self.expert_weights = {
            "scalability_expert": 1.0,
            "performance_expert": 0.9,
            "cost_optimization_expert": 0.8,
            "reliability_expert": 0.9,
            "security_expert": 0.7
        }
        
        # Decision history
        self.decision_history: List[Dict[str, Any]] = []
        self.expert_performance: Dict[str, Dict[str, float]] = {}
        
        # Scaling rules and policies
        self.expert_policies = {
            'require_unanimous_for_critical': True,
            'allow_minority_override': False,
            'escalate_on_disagreement': True,
            'max_consultation_time': 30,  # seconds
            'min_experts_required': 2
        }
    
    async def get_scaling_recommendation(
        self,
        current_metrics: Dict[str, Any],
        resource_config: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> ExpertConsensus:
        """
        Get expert-driven scaling recommendation
        
        Args:
            current_metrics: Current system metrics
            resource_config: Current resource configuration
            context: Additional context for scaling decision
            
        Returns:
            Expert consensus on scaling recommendation
        """
        try:
            # Prepare context for experts
            scaling_context = await self._prepare_scaling_context(
                current_metrics, resource_config, context
            )
            
            # Get individual expert recommendations
            expert_recommendations = await self._gather_expert_recommendations(
                scaling_context
            )
            
            # Analyze consensus
            consensus = await self._analyze_expert_consensus(
                expert_recommendations, scaling_context
            )
            
            # Apply expert policies
            final_consensus = await self._apply_expert_policies(
                consensus, expert_recommendations
            )
            
            # Update expert performance tracking
            await self._update_expert_performance(expert_recommendations, final_consensus)
            
            # Store decision
            decision_record = {
                'timestamp': datetime.now(),
                'context': scaling_context,
                'recommendations': expert_recommendations,
                'consensus': final_consensus,
                'applied': False
            }
            self.decision_history.append(decision_record)
            
            return final_consensus
            
        except Exception as e:
            self.logger.error(f"Expert scaling recommendation failed: {e}")
            return ExpertConsensus(
                consensus_reached=False,
                consensus_recommendation="maintain",
                confidence_level=ScalingConfidenceLevel.LOW,
                agreement_percentage=0.0,
                conflicting_opinions=[f"Error: {str(e)}"],
                final_decision={'action': 'maintain', 'error': str(e)},
                expert_votes={},
                reasoning_summary=f"Failed to get expert recommendation: {str(e)}"
            )
    
    async def execute_expert_scaling(
        self,
        consensus: ExpertConsensus,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Execute scaling based on expert consensus
        
        Args:
            consensus: Expert consensus result
            dry_run: Whether to perform a dry run
            
        Returns:
            Execution result
        """
        try:
            if not consensus.consensus_reached:
                return {
                    'success': False,
                    'reason': 'No expert consensus reached',
                    'action_taken': 'none',
                    'consensus': consensus
                }
            
            # Check confidence level
            if consensus.confidence_level == ScalingConfidenceLevel.LOW:
                if not await self._get_human_approval(consensus):
                    return {
                        'success': False,
                        'reason': 'Human approval required for low confidence decision',
                        'action_taken': 'none',
                        'requires_approval': True
                    }
            
            # Execute scaling decision
            if dry_run:
                execution_result = await self._simulate_expert_scaling(consensus)
            else:
                execution_result = await self._execute_expert_scaling_decision(consensus)
            
            # Update decision history
            if self.decision_history:
                self.decision_history[-1]['applied'] = execution_result.get('success', False)
                self.decision_history[-1]['execution_result'] = execution_result
            
            return execution_result
            
        except Exception as e:
            self.logger.error(f"Expert scaling execution failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'action_taken': 'none'
            }
    
    async def get_expert_insights(
        self,
        metrics_timeframe: timedelta = timedelta(hours=1)
    ) -> Dict[str, Any]:
        """
        Get expert insights on scaling patterns and recommendations
        
        Args:
            metrics_timeframe: Time frame for analysis
            
        Returns:
            Expert insights and analysis
        """
        try:
            # Analyze recent scaling decisions
            recent_decisions = [
                decision for decision in self.decision_history
                if datetime.now() - decision['timestamp'] <= metrics_timeframe
            ]
            
            # Get expert analysis of trends
            insights_query = QueryRequest(
                query=f"""
                Based on the recent scaling decisions and system behavior, provide insights on:
                
                Recent Decisions: {len(recent_decisions)} scaling decisions in the last {metrics_timeframe}
                
                Decision Summary:
                {json.dumps([{
                    'timestamp': d['timestamp'].isoformat(),
                    'recommendation': d['consensus'].consensus_recommendation,
                    'confidence': d['consensus'].confidence_level.value,
                    'agreement': d['consensus'].agreement_percentage
                } for d in recent_decisions[-5:]], indent=2)}
                
                Please analyze:
                1. Scaling pattern trends and effectiveness
                2. System capacity utilization patterns
                3. Potential optimization opportunities
                4. Risk factors and mitigation strategies
                5. Recommended policy adjustments
                """,
                experts=["scalability_expert", "performance_expert", "reliability_expert"],
                require_consensus=False
            )
            
            insights_response = await self.circle_of_experts.process_query(insights_query)
            
            # Compile insights
            insights = {
                'expert_insights': [resp.content for resp in insights_response.expert_responses],
                'decision_patterns': await self._analyze_decision_patterns(recent_decisions),
                'expert_performance': self.expert_performance,
                'consensus_trends': await self._analyze_consensus_trends(recent_decisions),
                'recommendations': await self._generate_policy_recommendations(recent_decisions)
            }
            
            return insights
            
        except Exception as e:
            self.logger.error(f"Failed to get expert insights: {e}")
            return {
                'error': str(e),
                'expert_insights': [],
                'decision_patterns': {},
                'expert_performance': {},
                'consensus_trends': {},
                'recommendations': []
            }
    
    async def _prepare_scaling_context(
        self,
        current_metrics: Dict[str, Any],
        resource_config: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Prepare comprehensive context for expert consultation"""
        scaling_context = {
            'current_metrics': current_metrics,
            'resource_config': resource_config,
            'timestamp': datetime.now().isoformat(),
            'historical_decisions': len(self.decision_history),
            'recent_trends': await self._analyze_recent_trends(),
            'system_health': await self._assess_system_health(current_metrics),
            'capacity_utilization': await self._calculate_capacity_utilization(
                current_metrics, resource_config
            )
        }
        
        if context:
            scaling_context.update(context)
        
        return scaling_context
    
    async def _gather_expert_recommendations(
        self,
        scaling_context: Dict[str, Any]
    ) -> List[ExpertRecommendation]:
        """Gather recommendations from individual experts"""
        expert_recommendations = []
        
        # Define expert consultation queries
        expert_queries = {
            "scalability_expert": self._build_scalability_query(scaling_context),
            "performance_expert": self._build_performance_query(scaling_context),
            "cost_optimization_expert": self._build_cost_optimization_query(scaling_context),
            "reliability_expert": self._build_reliability_query(scaling_context),
            "security_expert": self._build_security_query(scaling_context)
        }
        
        # Consult each expert
        for expert_id, query in expert_queries.items():
            try:
                query_request = QueryRequest(
                    query=query,
                    experts=[expert_id],
                    require_consensus=False
                )
                
                response = await self.circle_of_experts.process_query(query_request)
                
                if response.expert_responses:
                    expert_response = response.expert_responses[0]
                    recommendation = await self._parse_expert_response(
                        expert_id, expert_response.content
                    )
                    expert_recommendations.append(recommendation)
                    
            except Exception as e:
                self.logger.error(f"Failed to get recommendation from {expert_id}: {e}")
                # Add fallback recommendation
                expert_recommendations.append(ExpertRecommendation(
                    expert_id=expert_id,
                    recommendation_type="maintain",
                    confidence=0.1,
                    reasoning=f"Failed to get recommendation: {str(e)}",
                    risk_assessment={'error_risk': 1.0}
                ))
        
        return expert_recommendations
    
    async def _analyze_expert_consensus(
        self,
        recommendations: List[ExpertRecommendation],
        context: Dict[str, Any]
    ) -> ExpertConsensus:
        """Analyze expert recommendations to determine consensus"""
        if not recommendations:
            return ExpertConsensus(
                consensus_reached=False,
                consensus_recommendation="maintain",
                confidence_level=ScalingConfidenceLevel.LOW,
                agreement_percentage=0.0,
                conflicting_opinions=["No expert recommendations available"],
                final_decision={'action': 'maintain'},
                expert_votes={},
                reasoning_summary="No expert input available"
            )
        
        # Count votes by recommendation type
        vote_counts = {}
        expert_votes = {}
        total_confidence = 0.0
        
        for rec in recommendations:
            vote_type = rec.recommendation_type
            vote_counts[vote_type] = vote_counts.get(vote_type, 0) + 1
            expert_votes[rec.expert_id] = vote_type
            total_confidence += rec.confidence
        
        # Determine consensus
        total_votes = len(recommendations)
        if total_votes == 0:
            agreement_percentage = 0.0
            consensus_recommendation = "maintain"
        else:
            most_common_vote = max(vote_counts, key=vote_counts.get)
            agreement_percentage = (vote_counts[most_common_vote] / total_votes) * 100
            consensus_recommendation = most_common_vote
        
        # Check if consensus is reached
        consensus_reached = agreement_percentage >= (self.consensus_threshold * 100)
        
        # Calculate confidence level
        avg_confidence = total_confidence / max(1, total_votes)
        if avg_confidence >= 0.9:
            confidence_level = ScalingConfidenceLevel.HIGH
        elif avg_confidence >= 0.7:
            confidence_level = ScalingConfidenceLevel.MEDIUM
        else:
            confidence_level = ScalingConfidenceLevel.LOW
        
        # Identify conflicting opinions
        conflicting_opinions = []
        if len(vote_counts) > 1:
            for vote_type, count in vote_counts.items():
                if vote_type != consensus_recommendation:
                    experts_with_opinion = [
                        rec.expert_id for rec in recommendations
                        if rec.recommendation_type == vote_type
                    ]
                    conflicting_opinions.append(
                        f"{vote_type}: {count} votes from {experts_with_opinion}"
                    )
        
        # Build final decision
        final_decision = {
            'action': consensus_recommendation,
            'confidence': avg_confidence,
            'supporting_experts': [
                rec.expert_id for rec in recommendations
                if rec.recommendation_type == consensus_recommendation
            ],
            'reasoning': await self._synthesize_reasoning(recommendations, consensus_recommendation)
        }
        
        # Generate reasoning summary
        reasoning_summary = await self._generate_reasoning_summary(
            recommendations, consensus_recommendation, agreement_percentage
        )
        
        return ExpertConsensus(
            consensus_reached=consensus_reached,
            consensus_recommendation=consensus_recommendation,
            confidence_level=confidence_level,
            agreement_percentage=agreement_percentage,
            conflicting_opinions=conflicting_opinions,
            final_decision=final_decision,
            expert_votes=expert_votes,
            reasoning_summary=reasoning_summary
        )
    
    def _build_scalability_query(self, context: Dict[str, Any]) -> str:
        """Build query for scalability expert"""
        return f"""
        As a scalability expert, analyze this system state and provide scaling recommendations:
        
        Current Metrics:
        - CPU Utilization: {context['current_metrics'].get('cpu_utilization', 'N/A')}%
        - Memory Utilization: {context['current_metrics'].get('memory_utilization', 'N/A')}%
        - Response Time: {context['current_metrics'].get('response_time', 'N/A')}s
        - Active Connections: {context['current_metrics'].get('active_connections', 'N/A')}
        
        Resource Configuration:
        {json.dumps(context['resource_config'], indent=2)}
        
        System Health: {context.get('system_health', 'Unknown')}
        Capacity Utilization: {context.get('capacity_utilization', 'Unknown')}%
        
        Provide your recommendation in this format:
        RECOMMENDATION: [scale_up|scale_down|optimize|maintain]
        CONFIDENCE: [0.0-1.0]
        REASONING: [detailed explanation]
        SUGGESTED_CAPACITY: [specific capacity recommendations if applicable]
        RISKS: [potential risks and mitigation strategies]
        TIMELINE: [immediate|short_term|long_term]
        """
    
    def _build_performance_query(self, context: Dict[str, Any]) -> str:
        """Build query for performance expert"""
        return f"""
        As a performance expert, analyze this system and recommend scaling actions:
        
        Performance Metrics:
        - Response Time: {context['current_metrics'].get('response_time', 'N/A')}s
        - Throughput: {context['current_metrics'].get('throughput', 'N/A')} req/s
        - Error Rate: {context['current_metrics'].get('error_rate', 'N/A')}%
        - Queue Depth: {context['current_metrics'].get('queue_depth', 'N/A')}
        
        Recent Performance Trends: {context.get('recent_trends', 'No data')}
        
        Focus on:
        1. Performance bottleneck identification
        2. Optimal resource allocation for performance
        3. Performance vs cost trade-offs
        4. SLA compliance considerations
        
        Provide recommendation in the specified format.
        """
    
    def _build_cost_optimization_query(self, context: Dict[str, Any]) -> str:
        """Build query for cost optimization expert"""
        return f"""
        As a cost optimization expert, evaluate the scaling requirements:
        
        Current Resource Costs: {context['resource_config'].get('estimated_hourly_cost', 'N/A')}
        Utilization Efficiency: {context.get('capacity_utilization', 'N/A')}%
        
        Consider:
        1. Cost-effective scaling options
        2. Resource right-sizing opportunities
        3. Spot instance utilization potential
        4. Reserved capacity optimization
        
        Balance cost savings with performance requirements.
        Provide recommendation focusing on cost-performance optimization.
        """
    
    def _build_reliability_query(self, context: Dict[str, Any]) -> str:
        """Build query for reliability expert"""
        return f"""
        As a reliability expert, assess the scaling requirements:
        
        System Health: {context.get('system_health', 'Unknown')}
        Error Rate: {context['current_metrics'].get('error_rate', 'N/A')}%
        
        Focus on:
        1. System stability during scaling
        2. Fault tolerance considerations
        3. Disaster recovery implications
        4. Reliability vs performance trade-offs
        
        Ensure scaling decisions maintain or improve system reliability.
        """
    
    def _build_security_query(self, context: Dict[str, Any]) -> str:
        """Build query for security expert"""
        return f"""
        As a security expert, evaluate scaling from a security perspective:
        
        Current Configuration: {json.dumps(context['resource_config'], indent=2)}
        
        Consider:
        1. Security implications of scaling actions
        2. Attack surface changes
        3. Data protection during scaling
        4. Compliance requirements
        
        Ensure scaling maintains security posture.
        """
    
    async def _parse_expert_response(
        self,
        expert_id: str,
        response_content: str
    ) -> ExpertRecommendation:
        """Parse expert response into structured recommendation"""
        # Simple parsing logic - in practice would use more sophisticated NLP
        lines = response_content.split('\n')
        
        recommendation_type = "maintain"
        confidence = 0.5
        reasoning = response_content
        suggested_capacity = None
        risk_assessment = {}
        timeline = None
        conditions = []
        
        for line in lines:
            line = line.strip()
            if line.startswith('RECOMMENDATION:'):
                recommendation_type = line.split(':', 1)[1].strip().lower()
            elif line.startswith('CONFIDENCE:'):
                try:
                    confidence = float(line.split(':', 1)[1].strip())
                except ValueError:
                    confidence = 0.5
            elif line.startswith('REASONING:'):
                reasoning = line.split(':', 1)[1].strip()
            elif line.startswith('TIMELINE:'):
                timeline = line.split(':', 1)[1].strip()
        
        # Extract risk indicators from content
        if 'high risk' in response_content.lower():
            risk_assessment['high_risk'] = 0.8
        elif 'medium risk' in response_content.lower():
            risk_assessment['medium_risk'] = 0.5
        elif 'low risk' in response_content.lower():
            risk_assessment['low_risk'] = 0.2
        
        return ExpertRecommendation(
            expert_id=expert_id,
            recommendation_type=recommendation_type,
            confidence=confidence,
            reasoning=reasoning,
            suggested_capacity=suggested_capacity,
            risk_assessment=risk_assessment,
            timeline=timeline,
            conditions=conditions,
            metadata={'raw_response': response_content}
        )
    
    async def get_expert_scaling_status(self) -> Dict[str, Any]:
        """Get expert scaling system status"""
        recent_decisions = self.decision_history[-10:] if self.decision_history else []
        
        return {
            'scaling_mode': self.scaling_mode.value,
            'confidence_threshold': self.confidence_threshold,
            'consensus_threshold': self.consensus_threshold,
            'expert_weights': self.expert_weights,
            'total_decisions': len(self.decision_history),
            'recent_decisions': len(recent_decisions),
            'expert_performance': self.expert_performance,
            'policies': self.expert_policies,
            'circle_of_experts_available': self.circle_of_experts is not None
        }