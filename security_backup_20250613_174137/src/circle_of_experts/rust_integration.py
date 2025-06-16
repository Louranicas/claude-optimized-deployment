"""
Rust Integration for Circle of Experts
=====================================

This module provides seamless integration between the Python Circle of Experts
implementation and the high-performance Rust acceleration module.

Key features:
- Automatic fallback to Python if Rust module is not available
- Transparent API that works with both implementations
- Performance monitoring and comparison utilities
"""

import time
import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass

from src.circle_of_experts.models import Response

__all__ = [
    "ConsensusResult",
    "RustAcceleratedConsensus",
    "get_consensus_processor",
    "process_expert_consensus"
]


# Try to import Rust acceleration
try:
    import code_rust_core
    RUST_AVAILABLE = True
except ImportError:
    RUST_AVAILABLE = False
    logging.warning("Rust acceleration not available. Using Python implementation.")


@dataclass
class ConsensusResult:
    """Unified consensus result format."""
    consensus_text: str
    confidence_score: float
    agreement_matrix: List[List[float]]
    dissenting_opinions: List[str]
    key_insights: List[str]
    processing_time: float
    implementation: str  # "rust" or "python"


class RustAcceleratedConsensus:
    """Wrapper for Rust-accelerated consensus operations."""
    
    def __init__(self, 
                 enable_rust: bool = True,
                 min_consensus_threshold: float = 0.7,
                 similarity_algorithm: str = "cosine",
                 max_threads: Optional[int] = None):
        """
        Initialize the Rust-accelerated consensus processor.
        
        Args:
            enable_rust: Whether to use Rust acceleration if available
            min_consensus_threshold: Minimum similarity for consensus
            similarity_algorithm: Algorithm to use ("cosine", "jaccard", "levenshtein")
            max_threads: Maximum threads for parallel processing
        """
        self.use_rust = enable_rust and RUST_AVAILABLE
        self.min_consensus_threshold = min_consensus_threshold
        self.similarity_algorithm = similarity_algorithm
        self.max_threads = max_threads
        
        if self.use_rust:
            self.rust_config = code_rust_core.circle_of_experts.RustCircleConfig(
                min_consensus_threshold=min_consensus_threshold,
                enable_parallel_processing=True,
                max_threads=max_threads,
                similarity_algorithm=similarity_algorithm
            )
        
        self.logger = logging.getLogger(__name__)
    
    def process_responses(self, responses: List[Response]) -> ConsensusResult:
        """
        Process expert responses to find consensus.
        
        Args:
            responses: List of expert responses
            
        Returns:
            ConsensusResult with consensus information
        """
        start_time = time.time()
        
        if self.use_rust:
            result = self._process_with_rust(responses)
            implementation = "rust"
        else:
            result = self._process_with_python(responses)
            implementation = "python"
        
        processing_time = time.time() - start_time
        
        return ConsensusResult(
            consensus_text=result["consensus_text"],
            confidence_score=result["confidence_score"],
            agreement_matrix=result["agreement_matrix"],
            dissenting_opinions=result["dissenting_opinions"],
            key_insights=result["key_insights"],
            processing_time=processing_time,
            implementation=implementation
        )
    
    def _process_with_rust(self, responses: List[Response]) -> Dict[str, Any]:
        """Process responses using Rust implementation."""
        
        # Convert to Rust format
        rust_responses = [
            {
                "expert_name": r.expert_name,
                "content": r.content,
                "confidence": r.confidence,
                "metadata": r.metadata,
                "timestamp": int(r.timestamp.timestamp()) if r.timestamp else 0
            }
            for r in responses
        ]
        
        # Process with Rust
        try:
            result = code_rust_core.circle_of_experts.rust_process_expert_responses(
                rust_responses,
                self.rust_config
            )
            
            return {
                "consensus_text": result.consensus_text,
                "confidence_score": result.confidence_score,
                "agreement_matrix": result.agreement_matrix,
                "dissenting_opinions": result.dissenting_opinions,
                "key_insights": result.key_insights
            }
        except Exception as e:
            self.logger.error(f"Rust processing failed: {e}, falling back to Python")
            return self._process_with_python(responses)
    
    def _process_with_python(self, responses: List[Response]) -> Dict[str, Any]:
        """Process responses using Python implementation (simplified)."""
        
        # Simple Python consensus - take highest confidence response
        if not responses:
            return {
                "consensus_text": "",
                "confidence_score": 0.0,
                "agreement_matrix": [],
                "dissenting_opinions": [],
                "key_insights": []
            }
        
        # Sort by confidence
        sorted_responses = sorted(responses, key=lambda r: r.confidence, reverse=True)
        
        # Build consensus from top responses
        consensus_text = sorted_responses[0].content
        avg_confidence = sum(r.confidence for r in responses) / len(responses)
        
        # Simple agreement matrix (placeholder)
        n = len(responses)
        agreement_matrix = [[1.0 if i == j else 0.5 for j in range(n)] for i in range(n)]
        
        # Extract dissenting opinions (lower confidence responses)
        dissenting = [
            f"{r.expert_name}: {r.content[:100]}..."
            for r in sorted_responses[len(sorted_responses)//2:]
        ]
        
        # Simple insights
        insights = [
            f"Consensus based on {len(responses)} expert responses",
            f"Average confidence: {avg_confidence:.2%}",
            f"Highest confidence expert: {sorted_responses[0].expert_name}"
        ]
        
        return {
            "consensus_text": consensus_text,
            "confidence_score": avg_confidence,
            "agreement_matrix": agreement_matrix,
            "dissenting_opinions": dissenting[:3],
            "key_insights": insights
        }
    
    def compute_similarity(self, text1: str, text2: str) -> float:
        """
        Compute similarity between two texts.
        
        Args:
            text1: First text
            text2: Second text
            
        Returns:
            Similarity score between 0 and 1
        """
        if self.use_rust:
            try:
                return code_rust_core.circle_of_experts.rust_compute_text_similarity(
                    text1, text2, self.similarity_algorithm
                )
            except Exception as e:
                self.logger.error(f"Rust similarity computation failed: {e}")
        
        # Fallback to simple Python implementation
        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())
        
        if not words1 or not words2:
            return 0.0
        
        intersection = len(words1 & words2)
        union = len(words1 | words2)
        
        return intersection / union if union > 0 else 0.0
    
    def benchmark(self, responses: List[Response], iterations: int = 10) -> Dict[str, Any]:
        """
        Benchmark Rust vs Python performance.
        
        Args:
            responses: Test responses
            iterations: Number of iterations
            
        Returns:
            Benchmark results
        """
        results = {
            "rust_available": RUST_AVAILABLE,
            "iterations": iterations,
            "response_count": len(responses)
        }
        
        # Benchmark Python
        python_times = []
        original_use_rust = self.use_rust
        self.use_rust = False
        
        for _ in range(iterations):
            start = time.perf_counter()
            self._process_with_python(responses)
            python_times.append(time.perf_counter() - start)
        
        results["python_avg_time"] = sum(python_times) / len(python_times)
        results["python_min_time"] = min(python_times)
        results["python_max_time"] = max(python_times)
        
        # Benchmark Rust if available
        if RUST_AVAILABLE:
            self.use_rust = True
            rust_times = []
            
            for _ in range(iterations):
                start = time.perf_counter()
                self._process_with_rust(responses)
                rust_times.append(time.perf_counter() - start)
            
            results["rust_avg_time"] = sum(rust_times) / len(rust_times)
            results["rust_min_time"] = min(rust_times)
            results["rust_max_time"] = max(rust_times)
            results["speedup"] = results["python_avg_time"] / results["rust_avg_time"]
        
        self.use_rust = original_use_rust
        return results


# Global instance for convenience
_consensus_processor = None


def get_consensus_processor(**kwargs) -> RustAcceleratedConsensus:
    """Get or create a global consensus processor instance."""
    global _consensus_processor
    if _consensus_processor is None:
        _consensus_processor = RustAcceleratedConsensus(**kwargs)
    return _consensus_processor


def process_expert_consensus(responses: List[Response], **kwargs) -> ConsensusResult:
    """
    Convenience function to process expert consensus.
    
    Uses Rust acceleration if available, falls back to Python.
    """
    processor = get_consensus_processor(**kwargs)
    return processor.process_responses(responses)