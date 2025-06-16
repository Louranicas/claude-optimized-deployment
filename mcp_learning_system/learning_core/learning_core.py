"""
Core Learning Framework - Central orchestrator for adaptive learning
"""

import asyncio
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import numpy as np
from concurrent.futures import ThreadPoolExecutor

from .pattern_recognition import PatternRecognizer, Patterns
from .prediction_engine import PredictionEngine, Prediction
from .optimization import OptimizationEngine
from .models import KnowledgeGraph, Learning, Interaction


@dataclass
class LearningMetrics:
    """Metrics for learning performance"""
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    learning_rate: float
    convergence_rate: float
    cross_instance_score: float
    timestamp: datetime


class LearningCore:
    """Central learning orchestrator"""
    
    def __init__(self):
        self.pattern_engine = PatternRecognizer()
        self.prediction_engine = PredictionEngine()
        self.optimization_engine = OptimizationEngine()
        self.knowledge_graph = KnowledgeGraph()
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.metrics_history: List[LearningMetrics] = []
        
    async def process_interaction(self, interaction: Interaction) -> Learning:
        """Process a single interaction and extract learning"""
        # Extract patterns
        patterns = await self.pattern_engine.recognize(interaction)
        
        # Update knowledge graph
        self.knowledge_graph.update_from_patterns(patterns)
        
        # Generate predictions
        predictions = await self.prediction_engine.predict(
            interaction.context,
            patterns,
            self.knowledge_graph
        )
        
        # Optimize learning parameters
        optimization_result = await self.optimization_engine.optimize(
            patterns,
            predictions,
            self.metrics_history
        )
        
        # Create learning object
        learning = Learning(
            patterns=patterns,
            predictions=predictions,
            optimization=optimization_result,
            source_interaction=interaction,
            timestamp=datetime.utcnow()
        )
        
        # Update metrics
        self._update_metrics(learning)
        
        return learning
    
    async def batch_learn(self, interactions: List[Interaction]) -> List[Learning]:
        """Process multiple interactions in parallel"""
        tasks = [self.process_interaction(interaction) for interaction in interactions]
        return await asyncio.gather(*tasks)
    
    def _update_metrics(self, learning: Learning):
        """Update learning metrics based on new learning"""
        # Calculate performance metrics
        metrics = LearningMetrics(
            accuracy=learning.calculate_accuracy(),
            precision=learning.calculate_precision(),
            recall=learning.calculate_recall(),
            f1_score=learning.calculate_f1_score(),
            learning_rate=self.optimization_engine.current_learning_rate,
            convergence_rate=self._calculate_convergence_rate(),
            cross_instance_score=learning.cross_instance_relevance,
            timestamp=learning.timestamp
        )
        
        self.metrics_history.append(metrics)
        
        # Keep only recent history
        if len(self.metrics_history) > 1000:
            self.metrics_history = self.metrics_history[-1000:]
    
    def _calculate_convergence_rate(self) -> float:
        """Calculate how fast the system is converging"""
        if len(self.metrics_history) < 2:
            return 0.0
        
        recent_metrics = self.metrics_history[-10:]
        if len(recent_metrics) < 2:
            return 0.0
        
        # Calculate rate of improvement
        improvements = []
        for i in range(1, len(recent_metrics)):
            prev = recent_metrics[i-1]
            curr = recent_metrics[i]
            improvement = (curr.f1_score - prev.f1_score) / max(prev.f1_score, 0.001)
            improvements.append(improvement)
        
        return np.mean(improvements) if improvements else 0.0
    
    async def get_system_insights(self) -> Dict[str, Any]:
        """Get current system insights and performance"""
        if not self.metrics_history:
            return {"status": "no_data"}
        
        recent_metrics = self.metrics_history[-100:]
        
        return {
            "current_performance": {
                "accuracy": recent_metrics[-1].accuracy,
                "precision": recent_metrics[-1].precision,
                "recall": recent_metrics[-1].recall,
                "f1_score": recent_metrics[-1].f1_score,
            },
            "trends": {
                "accuracy_trend": self._calculate_trend([m.accuracy for m in recent_metrics]),
                "convergence_trend": self._calculate_trend([m.convergence_rate for m in recent_metrics]),
                "cross_instance_trend": self._calculate_trend([m.cross_instance_score for m in recent_metrics]),
            },
            "optimization": {
                "current_learning_rate": self.optimization_engine.current_learning_rate,
                "architecture_version": self.optimization_engine.architecture_version,
                "last_optimization": self.optimization_engine.last_optimization_time,
            },
            "knowledge_graph": {
                "total_nodes": self.knowledge_graph.node_count(),
                "total_edges": self.knowledge_graph.edge_count(),
                "connected_components": self.knowledge_graph.connected_components_count(),
            }
        }
    
    def _calculate_trend(self, values: List[float]) -> str:
        """Calculate trend direction"""
        if len(values) < 2:
            return "stable"
        
        # Simple linear regression
        x = np.arange(len(values))
        y = np.array(values)
        
        # Calculate slope
        slope = np.polyfit(x, y, 1)[0]
        
        if slope > 0.01:
            return "improving"
        elif slope < -0.01:
            return "declining"
        else:
            return "stable"