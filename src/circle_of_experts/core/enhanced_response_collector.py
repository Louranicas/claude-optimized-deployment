"""
Enhanced Response Collector with Rust acceleration support.

This module extends the base ResponseCollector to provide Rust-accelerated
consensus building when available.
"""

from __future__ import annotations
from typing import List, Dict, Any, Optional
import logging

from .response_collector import ResponseCollector
from src.circle_of_experts.models.response import ExpertResponse, ConsensusResponse
from src.circle_of_experts.drive.manager import DriveManager
from src.circle_of_experts.utils.rust_integration import get_rust_integration

logger = logging.getLogger(__name__)


class EnhancedResponseCollector(ResponseCollector):
    """
    Enhanced Response Collector with Rust acceleration support.
    
    This class extends ResponseCollector to use Rust modules for
    performance-critical operations when available.
    """
    
    def __init__(
        self,
        drive_manager: Optional[DriveManager] = None,
        use_rust_acceleration: bool = True
    ):
        """
        Initialize the Enhanced Response Collector.
        
        Args:
            drive_manager: Optional DriveManager instance
            use_rust_acceleration: Whether to use Rust acceleration
        """
        # Create a mock drive manager if none provided (for testing)
        if drive_manager is None:
            from unittest.mock import Mock
            drive_manager = Mock()
            
        super().__init__(drive_manager)
        self.use_rust_acceleration = use_rust_acceleration
        
    def build_consensus(self, responses: List[ExpertResponse]) -> ConsensusResponse:
        """
        Build consensus using Rust acceleration when available.
        
        Args:
            responses: List of expert responses
            
        Returns:
            ConsensusResponse object
        """
        if not self.use_rust_acceleration:
            # Use base Python implementation
            return super().build_consensus(responses)
            
        # Try to use Rust acceleration
        try:
            if self._rust_integration and self._rust_integration.rust_available:
                # Prepare data for Rust processing
                response_data = [
                    {
                        "confidence": r.confidence,
                        "expert_type": r.expert_type.value,
                        "recommendations": r.recommendations,
                        "limitations": r.limitations
                    }
                    for r in responses
                ]
                
                # Use Rust analyzer
                analysis_result, used_rust = self._rust_integration.analyze_responses(response_data)
                
                if used_rust and analysis_result:
                    # Build consensus from Rust results
                    return ConsensusResponse(
                        query_id=responses[0].query_id if responses else "",
                        average_confidence=analysis_result.get("average_confidence", 0.0),
                        participating_experts=[r.expert_type for r in responses],
                        common_recommendations=analysis_result.get("common_recommendations", []),
                        unique_limitations=analysis_result.get("unique_limitations", []),
                        consensus_level=self._map_consensus_score_to_level(
                            analysis_result.get("consensus_score", 0.5)
                        ),
                        consensus_analysis=analysis_result
                    )
        except Exception as e:
            logger.warning(f"Failed to use Rust acceleration: {e}, falling back to Python")
            
        # Fallback to Python implementation
        return super().build_consensus(responses)
    
    def _map_consensus_score_to_level(self, score: float) -> str:
        """Map numerical consensus score to level string."""
        if score >= 0.8:
            return "high"
        elif score >= 0.5:
            return "medium"
        else:
            return "low"