"""
Rust Integration Utilities for Circle of Experts.

Provides detection, loading, and fallback mechanisms for Rust-accelerated modules.
"""

import logging
import os
from typing import Optional, Dict, Any, List, Tuple
import importlib.util

__all__ = [
    "RustIntegration",
    "get_rust_integration"
]


logger = logging.getLogger(__name__)


class RustIntegration:
    """Manages Rust module integration with automatic fallback."""
    
    def __init__(self):
        """Initialize Rust integration manager."""
        self.rust_available = False
        self.consensus_analyzer = None
        self.response_aggregator = None
        self.performance_stats = {
            "rust_calls": 0,
            "fallback_calls": 0,
            "total_time_saved": 0.0
        }
        
        self._detect_and_load_rust_modules()
    
    def _detect_and_load_rust_modules(self) -> None:
        """Detect and load available Rust modules."""
        try:
            # Try to import from installed package
            from circle_of_experts_rust import ConsensusAnalyzer, ResponseAggregator
            
            self.consensus_analyzer = ConsensusAnalyzer()
            self.response_aggregator = ResponseAggregator()
            self.rust_available = True
            
            logger.info("Rust-accelerated modules loaded successfully")
            
        except ImportError:
            # Try to load from local build
            try:
                rust_module_path = self._find_rust_module()
                if rust_module_path:
                    spec = importlib.util.spec_from_file_location(
                        "circle_of_experts_rust", 
                        rust_module_path
                    )
                    if spec and spec.loader:
                        rust_module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(rust_module)
                        
                        self.consensus_analyzer = rust_module.ConsensusAnalyzer()
                        self.response_aggregator = rust_module.ResponseAggregator()
                        self.rust_available = True
                        
                        logger.info(f"Rust modules loaded from local build: {rust_module_path}")
                else:
                    logger.info("Rust modules not available - using Python fallback")
                    
            except Exception as e:
                logger.warning(f"Failed to load Rust modules: {e}")
                logger.info("Using Python-only implementation")
    
    def _find_rust_module(self) -> Optional[str]:
        """Find the compiled Rust module in various locations."""
        possible_paths = [
            # Maturin default output locations
            "target/wheels/circle_of_experts_rust*.so",
            "target/wheels/circle_of_experts_rust*.pyd",
            "target/release/circle_of_experts_rust*.so",
            "target/release/circle_of_experts_rust*.pyd",
            # Installed in site-packages
            "venv/lib/python*/site-packages/circle_of_experts_rust*.so",
            "venv/lib/python*/site-packages/circle_of_experts_rust*.pyd",
            # Windows variants
            "venv/Lib/site-packages/circle_of_experts_rust*.pyd",
            # Development build locations
            "rust_core/target/release/deps/circle_of_experts_rust*.so",
            "rust_core/target/release/deps/circle_of_experts_rust*.pyd",
        ]
        
        import glob
        for pattern in possible_paths:
            matches = glob.glob(pattern)
            if matches:
                return matches[0]
        
        return None
    
    def set_custom_modules(self, analyzer: Optional[Any], validator: Optional[Any]) -> None:
        """
        Set custom Rust modules for testing or override purposes.
        
        Args:
            analyzer: Custom analyzer module
            validator: Custom validator module
        """
        if analyzer:
            self.consensus_analyzer = analyzer
            self.rust_available = True
            logger.info("Custom Rust analyzer module set")
        
        if validator:
            # Store validator if we add support for it
            self.validator = validator
            logger.info("Custom Rust validator module set")
    
    def analyze_consensus(
        self, 
        responses: List[Dict[str, Any]], 
        config: Optional[Dict[str, Any]] = None
    ) -> Tuple[Dict[str, Any], bool]:
        """
        Analyze consensus with Rust acceleration if available.
        
        Args:
            responses: List of response data
            config: Optional configuration for analysis
            
        Returns:
            Tuple of (result, used_rust)
        """
        if self.rust_available and self.consensus_analyzer:
            try:
                import time
                start = time.time()
                
                result = self.consensus_analyzer.analyze(
                    responses, 
                    config or {"threshold": 0.7, "min_agreement": 0.5}
                )
                
                elapsed = time.time() - start
                self.performance_stats["rust_calls"] += 1
                self.performance_stats["total_time_saved"] += max(0, elapsed * 0.8)  # Estimate
                
                return result, True
                
            except Exception as e:
                logger.debug(f"Rust consensus analysis failed: {e}")
                self.performance_stats["fallback_calls"] += 1
        
        # Python fallback
        return self._python_consensus_analysis(responses, config), False
    
    def aggregate_responses(
        self, 
        responses: List[Dict[str, Any]]
    ) -> Tuple[Dict[str, Any], bool]:
        """
        Aggregate responses with Rust acceleration if available.
        
        Args:
            responses: List of response data
            
        Returns:
            Tuple of (result, used_rust)
        """
        if self.rust_available and self.response_aggregator:
            try:
                import time
                start = time.time()
                
                result = self.response_aggregator.aggregate(responses)
                
                elapsed = time.time() - start
                self.performance_stats["rust_calls"] += 1
                self.performance_stats["total_time_saved"] += max(0, elapsed * 0.8)  # Estimate
                
                return result, True
                
            except Exception as e:
                logger.debug(f"Rust response aggregation failed: {e}")
                self.performance_stats["fallback_calls"] += 1
        
        # Python fallback
        return self._python_response_aggregation(responses), False
    
    def analyze_responses(
        self,
        responses: List[Dict[str, Any]]
    ) -> Tuple[Dict[str, Any], bool]:
        """
        Analyze expert responses with Rust acceleration if available.
        
        Args:
            responses: List of response dictionaries
            
        Returns:
            Tuple of (analysis_result, used_rust)
        """
        if self.rust_available and self.consensus_analyzer:
            try:
                # Try to use Rust analyzer
                if hasattr(self.consensus_analyzer, 'analyze_responses'):
                    result = self.consensus_analyzer.analyze_responses(responses)
                    self.performance_stats["rust_calls"] += 1
                    return result, True
            except Exception as e:
                logger.warning(f"Rust analyze_responses failed: {e}, using fallback")
                self.performance_stats["fallback_calls"] += 1
        
        # Python fallback
        return self._python_analyze_responses(responses), False
    
    def _python_analyze_responses(
        self,
        responses: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Python fallback for response analysis."""
        if not responses:
            return {
                "total_responses": 0,
                "average_confidence": 0.0,
                "consensus_score": 0.0,
                "high_confidence_count": 0,
                "common_recommendations": [],
                "unique_limitations": []
            }
        
        # Calculate metrics
        confidences = [r.get("confidence", 0.0) for r in responses]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0
        high_confidence_count = sum(1 for c in confidences if c >= 0.7)
        
        # Find common recommendations
        all_recs = []
        for r in responses:
            all_recs.extend(r.get("recommendations", []))
        
        from collections import Counter
        rec_counts = Counter(rec.lower() for rec in all_recs)
        threshold = len(responses) / 2
        common_recs = [rec for rec, count in rec_counts.items() if count >= threshold]
        
        # Collect unique limitations
        all_limitations = set()
        for r in responses:
            all_limitations.update(lim.lower() for lim in r.get("limitations", []))
        
        # Calculate consensus score
        if len(responses) > 1:
            variance = sum((c - avg_confidence) ** 2 for c in confidences) / len(confidences)
            normalized_variance = 1.0 - min(variance, 1.0)
            consensus_score = (avg_confidence * 0.6 + normalized_variance * 0.4)
        else:
            consensus_score = avg_confidence
        
        return {
            "total_responses": len(responses),
            "average_confidence": round(avg_confidence, 3),
            "consensus_score": round(consensus_score, 3),
            "high_confidence_count": high_confidence_count,
            "common_recommendations": common_recs,
            "unique_limitations": list(all_limitations)
        }
    
    def _python_consensus_analysis(
        self, 
        responses: List[Dict[str, Any]], 
        config: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Python fallback for consensus analysis."""
        config = config or {"threshold": 0.7, "min_agreement": 0.5}
        
        if not responses:
            return {
                "consensus_score": 0.0,
                "agreement_level": "none",
                "key_points": [],
                "dissenting_views": []
            }
        
        # Calculate basic consensus metrics
        confidences = [r.get("confidence", 0.5) for r in responses]
        avg_confidence = sum(confidences) / len(confidences)
        
        # Find common recommendations
        all_recommendations = []
        for r in responses:
            all_recommendations.extend(r.get("recommendations", []))
        
        recommendation_counts = {}
        for rec in all_recommendations:
            rec_lower = rec.lower()
            recommendation_counts[rec_lower] = recommendation_counts.get(rec_lower, 0) + 1
        
        # Key points are recommendations that appear in at least half the responses
        min_count = len(responses) * config["min_agreement"]
        key_points = [
            rec for rec, count in recommendation_counts.items() 
            if count >= min_count
        ]
        
        # Dissenting views are unique recommendations
        dissenting_views = [
            rec for rec, count in recommendation_counts.items() 
            if count == 1
        ]
        
        # Calculate consensus score
        if len(responses) > 1:
            agreement_ratio = len(key_points) / max(1, len(set(all_recommendations)))
            consensus_score = (avg_confidence * 0.6 + agreement_ratio * 0.4)
        else:
            consensus_score = avg_confidence
        
        # Determine agreement level
        if consensus_score >= config["threshold"]:
            agreement_level = "high"
        elif consensus_score >= 0.5:
            agreement_level = "medium"
        else:
            agreement_level = "low"
        
        return {
            "consensus_score": round(consensus_score, 3),
            "agreement_level": agreement_level,
            "key_points": key_points[:10],  # Top 10
            "dissenting_views": dissenting_views[:5],  # Top 5
            "average_confidence": round(avg_confidence, 3),
            "response_count": len(responses)
        }
    
    def _python_response_aggregation(
        self, 
        responses: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Python fallback for response aggregation."""
        if not responses:
            return {
                "response_count": 0,
                "experts": [],
                "average_confidence": 0.0,
                "common_recommendations": [],
                "all_recommendations": []
            }
        
        # Aggregate data
        experts = [r.get("expert_type", "unknown") for r in responses]
        confidences = [r.get("confidence", 0.5) for r in responses]
        avg_confidence = sum(confidences) / len(confidences)
        
        # Collect recommendations
        all_recommendations = []
        for r in responses:
            all_recommendations.extend(r.get("recommendations", []))
        
        # Find common recommendations
        from collections import Counter
        rec_counter = Counter(rec.lower() for rec in all_recommendations)
        common_threshold = len(responses) / 2
        common_recommendations = [
            rec for rec, count in rec_counter.items() 
            if count >= common_threshold
        ]
        
        # Collect code snippets
        code_snippets = []
        for r in responses:
            code_snippets.extend(r.get("code_snippets", []))
        
        # Collect limitations
        limitations = []
        for r in responses:
            limitations.extend(r.get("limitations", []))
        
        return {
            "response_count": len(responses),
            "experts": experts,
            "average_confidence": round(avg_confidence, 3),
            "consensus_level": self._calculate_consensus_level(confidences),
            "common_recommendations": common_recommendations,
            "all_recommendations": list(set(all_recommendations)),
            "code_examples_count": len(code_snippets),
            "limitations": list(set(limitations)),
            "processing_times": {
                r.get("expert_type", f"expert_{i}"): r.get("processing_time", 0.0)
                for i, r in enumerate(responses)
            }
        }
    
    def _calculate_consensus_level(self, confidences: List[float]) -> str:
        """Calculate consensus level from confidence scores."""
        if len(confidences) < 2:
            return "n/a"
        
        avg = sum(confidences) / len(confidences)
        variance = sum((c - avg) ** 2 for c in confidences) / len(confidences)
        
        if variance < 0.05 and avg > 0.7:
            return "high"
        elif variance < 0.1 and avg > 0.5:
            return "medium"
        else:
            return "low"
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics for Rust integration."""
        total_calls = self.performance_stats["rust_calls"] + self.performance_stats["fallback_calls"]
        
        if total_calls == 0:
            rust_usage_percent = 0.0
        else:
            rust_usage_percent = (self.performance_stats["rust_calls"] / total_calls) * 100
        
        return {
            "rust_available": self.rust_available,
            "rust_calls": self.performance_stats["rust_calls"],
            "fallback_calls": self.performance_stats["fallback_calls"],
            "rust_usage_percent": round(rust_usage_percent, 1),
            "estimated_time_saved_seconds": round(self.performance_stats["total_time_saved"], 3)
        }


# Global instance for easy access
rust_integration = RustIntegration()


def get_rust_integration() -> RustIntegration:
    """Get the global Rust integration instance."""
    return rust_integration