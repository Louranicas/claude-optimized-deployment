"""
Consensus Engine - Multi-expert consensus for critical testing decisions
Aggregates expert opinions and reaches intelligent consensus
"""

import asyncio
import logging
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import statistics


class ConsensusMethod(Enum):
    WEIGHTED_AVERAGE = "weighted_average"
    MAJORITY_VOTE = "majority_vote"
    CONFIDENCE_WEIGHTED = "confidence_weighted"
    EXPERT_RANKING = "expert_ranking"
    HYBRID_CONSENSUS = "hybrid_consensus"


class ConsensusLevel(Enum):
    STRONG = "strong"      # >80% agreement
    MODERATE = "moderate"  # 60-80% agreement
    WEAK = "weak"         # 40-60% agreement
    CONFLICTED = "conflicted"  # <40% agreement


@dataclass
class ExpertWeight:
    """Expert weighting configuration"""
    expert_name: str
    domain_expertise: float  # 0-1
    historical_accuracy: float  # 0-1
    response_time_factor: float  # 0-1
    confidence_calibration: float  # 0-1
    overall_weight: float  # calculated


@dataclass
class ConsensusResult:
    """Result of consensus process"""
    primary_strategy: str
    confidence: float
    consensus_level: ConsensusLevel
    expert_agreement: Dict[str, float]
    disagreement_areas: List[str]
    fallback_strategy: Optional[str]
    decision_reasoning: str
    consensus_method_used: ConsensusMethod
    minority_opinions: List[Dict[str, Any]]


class ConsensusEngine:
    """
    Multi-expert consensus engine for intelligent decision making
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.name = "Consensus Engine"
        
        # Expert performance tracking
        self.expert_weights: Dict[str, ExpertWeight] = {}
        
        # Consensus methods configuration
        self.consensus_methods = {
            ConsensusMethod.WEIGHTED_AVERAGE: self._weighted_average_consensus,
            ConsensusMethod.MAJORITY_VOTE: self._majority_vote_consensus,
            ConsensusMethod.CONFIDENCE_WEIGHTED: self._confidence_weighted_consensus,
            ConsensusMethod.EXPERT_RANKING: self._expert_ranking_consensus,
            ConsensusMethod.HYBRID_CONSENSUS: self._hybrid_consensus
        }
        
        # Consensus thresholds
        self.consensus_thresholds = {
            ConsensusLevel.STRONG: 0.8,
            ConsensusLevel.MODERATE: 0.6,
            ConsensusLevel.WEAK: 0.4
        }
        
        # Domain expertise mapping
        self.domain_expertise = {
            'performance': ['performance_expert', 'scalability_expert'],
            'reliability': ['reliability_expert', 'chaos_expert'],
            'security': ['security_expert'],
            'scalability': ['scalability_expert', 'performance_expert'],
            'chaos_engineering': ['chaos_expert', 'reliability_expert']
        }
        
        # Historical consensus data
        self.consensus_history: List[Dict[str, Any]] = []
        
        # Default expert weights
        self._initialize_default_weights()
    
    def _initialize_default_weights(self):
        """Initialize default expert weights"""
        default_experts = [
            'performance_expert',
            'reliability_expert', 
            'scalability_expert',
            'security_expert',
            'chaos_expert'
        ]
        
        for expert in default_experts:
            self.expert_weights[expert] = ExpertWeight(
                expert_name=expert,
                domain_expertise=0.8,
                historical_accuracy=0.75,
                response_time_factor=0.9,
                confidence_calibration=0.7,
                overall_weight=0.8
            )
    
    async def reach_consensus(self, consensus_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main consensus method - aggregates expert opinions
        """
        self.logger.info("Starting multi-expert consensus process")
        
        try:
            # Extract consensus input data
            recommendations = consensus_data.get('recommendations', [])
            context = consensus_data.get('context', {})
            expert_performance = consensus_data.get('expert_performance', {})
            
            if not recommendations:
                return self._generate_default_consensus()
            
            # Update expert weights based on performance
            await self._update_expert_weights(expert_performance)
            
            # Preprocess recommendations
            processed_recommendations = self._preprocess_recommendations(recommendations)
            
            # Determine optimal consensus method
            consensus_method = self._select_consensus_method(processed_recommendations, context)
            
            # Execute consensus process
            consensus_result = await self._execute_consensus(
                processed_recommendations, consensus_method, context
            )
            
            # Post-process and validate consensus
            final_consensus = self._finalize_consensus(consensus_result, context)
            
            # Store consensus for learning
            self._store_consensus(final_consensus, recommendations, context)
            
            self.logger.info(f"Consensus reached: {final_consensus['primary_strategy']} with {final_consensus['confidence']:.2f} confidence")
            return final_consensus
            
        except Exception as e:
            self.logger.error(f"Consensus process failed: {str(e)}")
            return self._generate_fallback_consensus()
    
    async def _update_expert_weights(self, expert_performance: Dict[str, Any]):
        """Update expert weights based on recent performance"""
        for expert_name, performance in expert_performance.items():
            if expert_name in self.expert_weights:
                weight = self.expert_weights[expert_name]
                
                # Update components
                weight.historical_accuracy = performance.get('accuracy', weight.historical_accuracy)
                weight.confidence_calibration = performance.get('confidence_calibration', weight.confidence_calibration)
                weight.response_time_factor = min(1.0, performance.get('response_time', 1.0))
                
                # Recalculate overall weight
                weight.overall_weight = self._calculate_overall_weight(weight)
    
    def _calculate_overall_weight(self, weight: ExpertWeight) -> float:
        """Calculate overall expert weight from components"""
        components = [
            weight.domain_expertise * 0.3,
            weight.historical_accuracy * 0.3,
            weight.confidence_calibration * 0.2,
            weight.response_time_factor * 0.2
        ]
        return sum(components)
    
    def _preprocess_recommendations(self, recommendations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Preprocess and normalize expert recommendations"""
        processed = []
        
        for rec in recommendations:
            expert_name = rec.get('expert_name', 'unknown')
            
            # Normalize confidence
            confidence = rec.get('confidence', 0.5)
            confidence = max(0.0, min(1.0, confidence))
            
            # Extract strategy preference
            strategy = rec.get('strategy', 'default_strategy')
            
            # Get expert weight
            expert_weight = self.expert_weights.get(expert_name, ExpertWeight(
                expert_name=expert_name,
                domain_expertise=0.5,
                historical_accuracy=0.5,
                response_time_factor=0.5,
                confidence_calibration=0.5,
                overall_weight=0.5
            )).overall_weight
            
            # Extract expected outcomes
            expected_outcome = rec.get('expected_outcome', {})
            
            processed_rec = {
                'expert_name': expert_name,
                'strategy': strategy,
                'confidence': confidence,
                'expert_weight': expert_weight,
                'expected_outcome': expected_outcome,
                'reasoning': rec.get('reasoning', ''),
                'risk_assessment': rec.get('risk_assessment', 'medium'),
                'implementation_steps': rec.get('implementation_steps', []),
                'metrics_to_monitor': rec.get('metrics_to_monitor', [])
            }
            
            processed.append(processed_rec)
        
        return processed
    
    def _select_consensus_method(
        self,
        recommendations: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> ConsensusMethod:
        """Select optimal consensus method based on situation"""
        
        # Count unique strategies
        strategies = set(rec['strategy'] for rec in recommendations)
        num_strategies = len(strategies)
        
        # Calculate confidence variance
        confidences = [rec['confidence'] for rec in recommendations]
        confidence_variance = statistics.variance(confidences) if len(confidences) > 1 else 0
        
        # Check for critical context
        is_critical = context.get('critical_system', False) or context.get('production_like', False)
        
        # Selection logic
        if num_strategies == 1:
            # All experts agree on strategy - use confidence weighting
            return ConsensusMethod.CONFIDENCE_WEIGHTED
        elif num_strategies == 2 and confidence_variance < 0.1:
            # Two strategies with similar confidence - use expert ranking
            return ConsensusMethod.EXPERT_RANKING
        elif is_critical and num_strategies > 2:
            # Critical system with many strategies - use hybrid approach
            return ConsensusMethod.HYBRID_CONSENSUS
        elif confidence_variance > 0.3:
            # High confidence variance - use weighted average
            return ConsensusMethod.WEIGHTED_AVERAGE
        else:
            # Default to majority vote
            return ConsensusMethod.MAJORITY_VOTE
    
    async def _execute_consensus(
        self,
        recommendations: List[Dict[str, Any]],
        consensus_method: ConsensusMethod,
        context: Dict[str, Any]
    ) -> ConsensusResult:
        """Execute specific consensus method"""
        
        consensus_func = self.consensus_methods[consensus_method]
        return await consensus_func(recommendations, context)
    
    async def _weighted_average_consensus(
        self,
        recommendations: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> ConsensusResult:
        """Weighted average consensus method"""
        
        # Calculate strategy scores
        strategy_scores: Dict[str, float] = {}
        strategy_weights: Dict[str, float] = {}
        
        for rec in recommendations:
            strategy = rec['strategy']
            weight = rec['expert_weight']
            confidence = rec['confidence']
            
            # Weighted confidence score
            score = weight * confidence
            
            if strategy in strategy_scores:
                strategy_scores[strategy] += score
                strategy_weights[strategy] += weight
            else:
                strategy_scores[strategy] = score
                strategy_weights[strategy] = weight
        
        # Normalize scores
        normalized_scores = {}
        for strategy, total_score in strategy_scores.items():
            total_weight = strategy_weights[strategy]
            normalized_scores[strategy] = total_score / total_weight if total_weight > 0 else 0
        
        # Select highest scoring strategy
        primary_strategy = max(normalized_scores.keys(), key=lambda k: normalized_scores[k])
        primary_confidence = normalized_scores[primary_strategy]
        
        # Calculate expert agreement
        expert_agreement = self._calculate_expert_agreement(recommendations, primary_strategy)
        
        # Determine consensus level
        consensus_level = self._determine_consensus_level(expert_agreement)
        
        # Identify disagreement areas
        disagreement_areas = self._identify_disagreement_areas(recommendations)
        
        return ConsensusResult(
            primary_strategy=primary_strategy,
            confidence=primary_confidence,
            consensus_level=consensus_level,
            expert_agreement=expert_agreement,
            disagreement_areas=disagreement_areas,
            fallback_strategy=self._select_fallback_strategy(normalized_scores, primary_strategy),
            decision_reasoning=f"Weighted average consensus selected {primary_strategy} with {primary_confidence:.2f} score",
            consensus_method_used=ConsensusMethod.WEIGHTED_AVERAGE,
            minority_opinions=self._extract_minority_opinions(recommendations, primary_strategy)
        )
    
    async def _majority_vote_consensus(
        self,
        recommendations: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> ConsensusResult:
        """Majority vote consensus method"""
        
        # Count strategy votes
        strategy_votes: Dict[str, int] = {}
        strategy_confidences: Dict[str, List[float]] = {}
        
        for rec in recommendations:
            strategy = rec['strategy']
            confidence = rec['confidence']
            
            strategy_votes[strategy] = strategy_votes.get(strategy, 0) + 1
            
            if strategy not in strategy_confidences:
                strategy_confidences[strategy] = []
            strategy_confidences[strategy].append(confidence)
        
        # Find majority strategy
        total_votes = len(recommendations)
        primary_strategy = max(strategy_votes.keys(), key=lambda k: strategy_votes[k])
        primary_votes = strategy_votes[primary_strategy]
        
        # Calculate confidence as average of supporting experts
        primary_confidence = statistics.mean(strategy_confidences[primary_strategy])
        
        # Calculate expert agreement (vote percentage)
        agreement_percentage = primary_votes / total_votes
        expert_agreement = {expert: 1.0 if rec['strategy'] == primary_strategy else 0.0 
                          for rec in recommendations for expert in [rec['expert_name']]}
        
        # Determine consensus level
        if agreement_percentage >= 0.8:
            consensus_level = ConsensusLevel.STRONG
        elif agreement_percentage >= 0.6:
            consensus_level = ConsensusLevel.MODERATE
        elif agreement_percentage >= 0.4:
            consensus_level = ConsensusLevel.WEAK
        else:
            consensus_level = ConsensusLevel.CONFLICTED
        
        return ConsensusResult(
            primary_strategy=primary_strategy,
            confidence=primary_confidence,
            consensus_level=consensus_level,
            expert_agreement=expert_agreement,
            disagreement_areas=self._identify_disagreement_areas(recommendations),
            fallback_strategy=self._select_fallback_from_votes(strategy_votes, primary_strategy),
            decision_reasoning=f"Majority vote consensus: {primary_votes}/{total_votes} experts selected {primary_strategy}",
            consensus_method_used=ConsensusMethod.MAJORITY_VOTE,
            minority_opinions=self._extract_minority_opinions(recommendations, primary_strategy)
        )
    
    async def _confidence_weighted_consensus(
        self,
        recommendations: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> ConsensusResult:
        """Confidence-weighted consensus method"""
        
        # Weight by confidence and expert weight
        strategy_scores: Dict[str, float] = {}
        total_weight = 0
        
        for rec in recommendations:
            strategy = rec['strategy']
            confidence = rec['confidence']
            expert_weight = rec['expert_weight']
            
            # Combined weight
            combined_weight = confidence * expert_weight
            
            strategy_scores[strategy] = strategy_scores.get(strategy, 0) + combined_weight
            total_weight += combined_weight
        
        # Normalize scores
        if total_weight > 0:
            for strategy in strategy_scores:
                strategy_scores[strategy] /= total_weight
        
        # Select highest scoring strategy
        primary_strategy = max(strategy_scores.keys(), key=lambda k: strategy_scores[k])
        primary_confidence = strategy_scores[primary_strategy]
        
        # Calculate expert agreement based on confidence alignment
        expert_agreement = {}
        for rec in recommendations:
            expert_name = rec['expert_name']
            if rec['strategy'] == primary_strategy:
                expert_agreement[expert_name] = rec['confidence']
            else:
                # Partial agreement based on confidence
                expert_agreement[expert_name] = rec['confidence'] * 0.3
        
        # Determine consensus level
        avg_agreement = statistics.mean(expert_agreement.values())
        consensus_level = self._determine_consensus_level_from_score(avg_agreement)
        
        return ConsensusResult(
            primary_strategy=primary_strategy,
            confidence=primary_confidence,
            consensus_level=consensus_level,
            expert_agreement=expert_agreement,
            disagreement_areas=self._identify_disagreement_areas(recommendations),
            fallback_strategy=self._select_fallback_from_scores(strategy_scores, primary_strategy),
            decision_reasoning=f"Confidence-weighted consensus selected {primary_strategy} with {primary_confidence:.2f} weighted score",
            consensus_method_used=ConsensusMethod.CONFIDENCE_WEIGHTED,
            minority_opinions=self._extract_minority_opinions(recommendations, primary_strategy)
        )
    
    async def _expert_ranking_consensus(
        self,
        recommendations: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> ConsensusResult:
        """Expert ranking consensus method"""
        
        # Rank experts by overall weight and confidence
        ranked_experts = sorted(
            recommendations,
            key=lambda x: x['expert_weight'] * x['confidence'],
            reverse=True
        )
        
        # Primary strategy from top expert
        primary_recommendation = ranked_experts[0]
        primary_strategy = primary_recommendation['strategy']
        primary_confidence = primary_recommendation['confidence']
        
        # Calculate agreement based on expert rankings
        expert_agreement = {}
        for i, rec in enumerate(ranked_experts):
            expert_name = rec['expert_name']
            ranking_weight = 1.0 - (i / len(ranked_experts))  # Higher weight for better ranking
            
            if rec['strategy'] == primary_strategy:
                expert_agreement[expert_name] = ranking_weight
            else:
                expert_agreement[expert_name] = ranking_weight * 0.2  # Partial credit
        
        # Consensus level based on top experts' alignment
        top_3_experts = ranked_experts[:min(3, len(ranked_experts))]
        top_agreement = sum(1 for exp in top_3_experts if exp['strategy'] == primary_strategy) / len(top_3_experts)
        
        if top_agreement >= 0.8:
            consensus_level = ConsensusLevel.STRONG
        elif top_agreement >= 0.6:
            consensus_level = ConsensusLevel.MODERATE
        else:
            consensus_level = ConsensusLevel.WEAK
        
        return ConsensusResult(
            primary_strategy=primary_strategy,
            confidence=primary_confidence,
            consensus_level=consensus_level,
            expert_agreement=expert_agreement,
            disagreement_areas=self._identify_disagreement_areas(recommendations),
            fallback_strategy=ranked_experts[1]['strategy'] if len(ranked_experts) > 1 else None,
            decision_reasoning=f"Expert ranking consensus: Top expert {primary_recommendation['expert_name']} selected {primary_strategy}",
            consensus_method_used=ConsensusMethod.EXPERT_RANKING,
            minority_opinions=self._extract_minority_opinions(recommendations, primary_strategy)
        )
    
    async def _hybrid_consensus(
        self,
        recommendations: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> ConsensusResult:
        """Hybrid consensus method combining multiple approaches"""
        
        # Run multiple consensus methods
        weighted_result = await self._weighted_average_consensus(recommendations, context)
        majority_result = await self._majority_vote_consensus(recommendations, context)
        confidence_result = await self._confidence_weighted_consensus(recommendations, context)
        
        # Combine results
        method_votes = [
            weighted_result.primary_strategy,
            majority_result.primary_strategy,
            confidence_result.primary_strategy
        ]
        
        # Count votes for each strategy
        strategy_vote_count = {}
        for strategy in method_votes:
            strategy_vote_count[strategy] = strategy_vote_count.get(strategy, 0) + 1
        
        # Select strategy with most method votes
        primary_strategy = max(strategy_vote_count.keys(), key=lambda k: strategy_vote_count[k])
        
        # Use confidence from the method that selected this strategy
        if weighted_result.primary_strategy == primary_strategy:
            primary_confidence = weighted_result.confidence
        elif majority_result.primary_strategy == primary_strategy:
            primary_confidence = majority_result.confidence
        else:
            primary_confidence = confidence_result.confidence
        
        # Average expert agreements from all methods
        expert_agreement = {}
        all_experts = set()
        for result in [weighted_result, majority_result, confidence_result]:
            all_experts.update(result.expert_agreement.keys())
        
        for expert in all_experts:
            agreements = []
            for result in [weighted_result, majority_result, confidence_result]:
                if expert in result.expert_agreement:
                    agreements.append(result.expert_agreement[expert])
            expert_agreement[expert] = statistics.mean(agreements) if agreements else 0.5
        
        # Determine consensus level
        avg_agreement = statistics.mean(expert_agreement.values())
        consensus_level = self._determine_consensus_level_from_score(avg_agreement)
        
        # Count method agreement
        method_agreement = strategy_vote_count[primary_strategy]
        if method_agreement == 3:
            reasoning = f"Strong hybrid consensus: All 3 methods selected {primary_strategy}"
        elif method_agreement == 2:
            reasoning = f"Moderate hybrid consensus: 2/3 methods selected {primary_strategy}"
        else:
            reasoning = f"Weak hybrid consensus: Split decision favoring {primary_strategy}"
        
        return ConsensusResult(
            primary_strategy=primary_strategy,
            confidence=primary_confidence,
            consensus_level=consensus_level,
            expert_agreement=expert_agreement,
            disagreement_areas=self._identify_disagreement_areas(recommendations),
            fallback_strategy=self._select_hybrid_fallback(strategy_vote_count, primary_strategy),
            decision_reasoning=reasoning,
            consensus_method_used=ConsensusMethod.HYBRID_CONSENSUS,
            minority_opinions=self._extract_minority_opinions(recommendations, primary_strategy)
        )
    
    def _calculate_expert_agreement(
        self,
        recommendations: List[Dict[str, Any]],
        primary_strategy: str
    ) -> Dict[str, float]:
        """Calculate agreement level for each expert"""
        agreement = {}
        
        for rec in recommendations:
            expert_name = rec['expert_name']
            if rec['strategy'] == primary_strategy:
                agreement[expert_name] = rec['confidence']
            else:
                # Partial agreement based on confidence and similarity
                agreement[expert_name] = rec['confidence'] * 0.2
        
        return agreement
    
    def _determine_consensus_level(self, expert_agreement: Dict[str, float]) -> ConsensusLevel:
        """Determine consensus level from expert agreement"""
        if not expert_agreement:
            return ConsensusLevel.CONFLICTED
        
        avg_agreement = statistics.mean(expert_agreement.values())
        return self._determine_consensus_level_from_score(avg_agreement)
    
    def _determine_consensus_level_from_score(self, score: float) -> ConsensusLevel:
        """Determine consensus level from numeric score"""
        if score >= self.consensus_thresholds[ConsensusLevel.STRONG]:
            return ConsensusLevel.STRONG
        elif score >= self.consensus_thresholds[ConsensusLevel.MODERATE]:
            return ConsensusLevel.MODERATE
        elif score >= self.consensus_thresholds[ConsensusLevel.WEAK]:
            return ConsensusLevel.WEAK
        else:
            return ConsensusLevel.CONFLICTED
    
    def _identify_disagreement_areas(self, recommendations: List[Dict[str, Any]]) -> List[str]:
        """Identify areas of expert disagreement"""
        disagreements = []
        
        # Strategy disagreements
        strategies = set(rec['strategy'] for rec in recommendations)
        if len(strategies) > 1:
            strategy_list = ", ".join(strategies)
            disagreements.append(f"Strategy selection: {strategy_list}")
        
        # Risk assessment disagreements
        risk_assessments = set(rec['risk_assessment'] for rec in recommendations)
        if len(risk_assessments) > 1:
            risk_list = ", ".join(risk_assessments)
            disagreements.append(f"Risk assessment: {risk_list}")
        
        # Confidence variance
        confidences = [rec['confidence'] for rec in recommendations]
        if len(confidences) > 1:
            confidence_variance = statistics.variance(confidences)
            if confidence_variance > 0.2:
                disagreements.append(f"High confidence variance: {confidence_variance:.2f}")
        
        # Implementation approach disagreements
        all_steps = set()
        for rec in recommendations:
            all_steps.update(rec.get('implementation_steps', []))
        
        step_counts = {}
        for rec in recommendations:
            for step in rec.get('implementation_steps', []):
                step_counts[step] = step_counts.get(step, 0) + 1
        
        controversial_steps = [step for step, count in step_counts.items() 
                             if count < len(recommendations) * 0.5]
        
        if controversial_steps:
            disagreements.append(f"Implementation approaches vary on: {len(controversial_steps)} steps")
        
        return disagreements
    
    def _select_fallback_strategy(
        self,
        strategy_scores: Dict[str, float],
        primary_strategy: str
    ) -> Optional[str]:
        """Select fallback strategy from scores"""
        if len(strategy_scores) < 2:
            return None
        
        # Remove primary strategy and select next highest
        fallback_scores = {k: v for k, v in strategy_scores.items() if k != primary_strategy}
        if fallback_scores:
            return max(fallback_scores.keys(), key=lambda k: fallback_scores[k])
        
        return None
    
    def _select_fallback_from_votes(
        self,
        strategy_votes: Dict[str, int],
        primary_strategy: str
    ) -> Optional[str]:
        """Select fallback strategy from vote counts"""
        if len(strategy_votes) < 2:
            return None
        
        fallback_votes = {k: v for k, v in strategy_votes.items() if k != primary_strategy}
        if fallback_votes:
            return max(fallback_votes.keys(), key=lambda k: fallback_votes[k])
        
        return None
    
    def _select_fallback_from_scores(
        self,
        strategy_scores: Dict[str, float],
        primary_strategy: str
    ) -> Optional[str]:
        """Select fallback strategy from scores"""
        return self._select_fallback_strategy(strategy_scores, primary_strategy)
    
    def _select_hybrid_fallback(
        self,
        strategy_vote_count: Dict[str, int],
        primary_strategy: str
    ) -> Optional[str]:
        """Select fallback strategy for hybrid consensus"""
        fallback_votes = {k: v for k, v in strategy_vote_count.items() if k != primary_strategy}
        if fallback_votes:
            return max(fallback_votes.keys(), key=lambda k: fallback_votes[k])
        return None
    
    def _extract_minority_opinions(
        self,
        recommendations: List[Dict[str, Any]],
        primary_strategy: str
    ) -> List[Dict[str, Any]]:
        """Extract minority expert opinions"""
        minority_opinions = []
        
        for rec in recommendations:
            if rec['strategy'] != primary_strategy:
                minority_opinion = {
                    'expert_name': rec['expert_name'],
                    'preferred_strategy': rec['strategy'],
                    'confidence': rec['confidence'],
                    'reasoning': rec['reasoning'],
                    'key_concerns': rec.get('key_concerns', [])
                }
                minority_opinions.append(minority_opinion)
        
        return minority_opinions
    
    def _finalize_consensus(
        self,
        consensus_result: ConsensusResult,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Finalize and format consensus result"""
        
        # Additional validation for critical contexts
        if context.get('critical_system', False) and consensus_result.consensus_level == ConsensusLevel.CONFLICTED:
            # Override with safe default for critical systems
            consensus_result.primary_strategy = 'conservative_load_testing'
            consensus_result.confidence = 0.6
            consensus_result.decision_reasoning += " - OVERRIDDEN: Conservative strategy selected for critical system"
        
        # Format final consensus
        final_consensus = {
            'primary_strategy': consensus_result.primary_strategy,
            'confidence': consensus_result.confidence,
            'consensus_level': consensus_result.consensus_level.value,
            'expert_agreement': consensus_result.expert_agreement,
            'disagreement_areas': consensus_result.disagreement_areas,
            'fallback_strategy': consensus_result.fallback_strategy,
            'decision_reasoning': consensus_result.decision_reasoning,
            'consensus_method': consensus_result.consensus_method_used.value,
            'minority_opinions': consensus_result.minority_opinions,
            'expert_recommendations': self._summarize_expert_recommendations(consensus_result),
            'consensus_metadata': {
                'timestamp': time.time(),
                'num_experts': len(consensus_result.expert_agreement),
                'consensus_strength': consensus_result.consensus_level.value,
                'decision_complexity': len(consensus_result.disagreement_areas)
            }
        }
        
        return final_consensus
    
    def _summarize_expert_recommendations(self, consensus_result: ConsensusResult) -> Dict[str, Any]:
        """Summarize expert recommendations in consensus"""
        summary = {
            'total_experts': len(consensus_result.expert_agreement),
            'supporting_experts': sum(1 for score in consensus_result.expert_agreement.values() if score > 0.5),
            'average_confidence': statistics.mean(consensus_result.expert_agreement.values()),
            'unanimous_decision': all(score > 0.8 for score in consensus_result.expert_agreement.values()),
            'conflicted_decision': consensus_result.consensus_level == ConsensusLevel.CONFLICTED
        }
        
        return summary
    
    def _store_consensus(
        self,
        consensus: Dict[str, Any],
        recommendations: List[Dict[str, Any]],
        context: Dict[str, Any]
    ):
        """Store consensus result for learning and analysis"""
        record = {
            'timestamp': time.time(),
            'primary_strategy': consensus['primary_strategy'],
            'confidence': consensus['confidence'],
            'consensus_level': consensus['consensus_level'],
            'method_used': consensus['consensus_method'],
            'num_experts': len(recommendations),
            'num_disagreements': len(consensus['disagreement_areas']),
            'context_critical': context.get('critical_system', False),
            'expert_variance': statistics.variance([rec['confidence'] for rec in recommendations]) if len(recommendations) > 1 else 0
        }
        
        self.consensus_history.append(record)
        
        # Keep only last 100 records
        if len(self.consensus_history) > 100:
            self.consensus_history = self.consensus_history[-100:]
    
    def _generate_default_consensus(self) -> Dict[str, Any]:
        """Generate default consensus when no recommendations available"""
        return {
            'primary_strategy': 'basic_load_testing',
            'confidence': 0.5,
            'consensus_level': 'weak',
            'expert_agreement': {},
            'disagreement_areas': ['No expert recommendations available'],
            'fallback_strategy': None,
            'decision_reasoning': 'Default consensus due to lack of expert recommendations',
            'consensus_method': 'default',
            'minority_opinions': [],
            'expert_recommendations': {
                'total_experts': 0,
                'supporting_experts': 0,
                'average_confidence': 0.5,
                'unanimous_decision': False,
                'conflicted_decision': True
            },
            'consensus_metadata': {
                'timestamp': time.time(),
                'num_experts': 0,
                'consensus_strength': 'weak',
                'decision_complexity': 1
            }
        }
    
    def _generate_fallback_consensus(self) -> Dict[str, Any]:
        """Generate fallback consensus when consensus process fails"""
        return {
            'primary_strategy': 'conservative_testing',
            'confidence': 0.4,
            'consensus_level': 'weak',
            'expert_agreement': {},
            'disagreement_areas': ['Consensus process failed'],
            'fallback_strategy': 'basic_load_testing',
            'decision_reasoning': 'Fallback consensus due to consensus engine failure',
            'consensus_method': 'fallback',
            'minority_opinions': [],
            'expert_recommendations': {
                'total_experts': 0,
                'supporting_experts': 0,
                'average_confidence': 0.4,
                'unanimous_decision': False,
                'conflicted_decision': True
            },
            'consensus_metadata': {
                'timestamp': time.time(),
                'num_experts': 0,
                'consensus_strength': 'weak',
                'decision_complexity': 1
            }
        }
    
    # Public interface methods
    
    def update_expert_weight(self, expert_name: str, weight_updates: Dict[str, float]):
        """Update expert weight parameters"""
        if expert_name in self.expert_weights:
            weight = self.expert_weights[expert_name]
            
            if 'domain_expertise' in weight_updates:
                weight.domain_expertise = weight_updates['domain_expertise']
            if 'historical_accuracy' in weight_updates:
                weight.historical_accuracy = weight_updates['historical_accuracy']
            if 'confidence_calibration' in weight_updates:
                weight.confidence_calibration = weight_updates['confidence_calibration']
            
            # Recalculate overall weight
            weight.overall_weight = self._calculate_overall_weight(weight)
    
    def get_expert_weights(self) -> Dict[str, Dict[str, float]]:
        """Get current expert weights"""
        return {
            name: {
                'domain_expertise': weight.domain_expertise,
                'historical_accuracy': weight.historical_accuracy,
                'response_time_factor': weight.response_time_factor,
                'confidence_calibration': weight.confidence_calibration,
                'overall_weight': weight.overall_weight
            }
            for name, weight in self.expert_weights.items()
        }
    
    def get_consensus_history(self) -> List[Dict[str, Any]]:
        """Get consensus decision history"""
        return self.consensus_history.copy()
    
    def get_consensus_statistics(self) -> Dict[str, Any]:
        """Get consensus statistics and analytics"""
        if not self.consensus_history:
            return {'no_data': True}
        
        # Calculate statistics
        confidences = [record['confidence'] for record in self.consensus_history]
        consensus_levels = [record['consensus_level'] for record in self.consensus_history]
        methods_used = [record['method_used'] for record in self.consensus_history]
        
        stats = {
            'total_decisions': len(self.consensus_history),
            'average_confidence': statistics.mean(confidences),
            'confidence_variance': statistics.variance(confidences) if len(confidences) > 1 else 0,
            'consensus_level_distribution': {level: consensus_levels.count(level) for level in set(consensus_levels)},
            'method_usage': {method: methods_used.count(method) for method in set(methods_used)},
            'recent_performance': {
                'last_10_avg_confidence': statistics.mean(confidences[-10:]) if len(confidences) >= 10 else statistics.mean(confidences),
                'strong_consensus_rate': consensus_levels.count('strong') / len(consensus_levels)
            }
        }
        
        return stats