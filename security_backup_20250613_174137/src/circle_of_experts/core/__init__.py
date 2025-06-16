"""Core components for Circle of Experts system."""

from .expert_manager import ExpertManager
from .enhanced_expert_manager import EnhancedExpertManager, BatchConsultation
from .query_handler import QueryHandler
from .response_collector import ResponseCollector

__all__ = [
    "ExpertManager",
    "EnhancedExpertManager",
    "BatchConsultation",
    "QueryHandler",
    "ResponseCollector",
]

# Import Rust-accelerated components if available
try:
    from .rust_accelerated import (
        ConsensusAnalyzer,
        ResponseAggregator,
        PatternMatcher,
        AsyncConsensusAnalyzer,
        AsyncResponseAggregator,
        AsyncPatternMatcher,
        create_consensus_analyzer,
        create_response_aggregator,
        create_pattern_matcher,
        get_performance_metrics,
        RUST_AVAILABLE
    )
    __all__.extend([
        "ConsensusAnalyzer",
        "ResponseAggregator",
        "PatternMatcher",
        "AsyncConsensusAnalyzer",
        "AsyncResponseAggregator",
        "AsyncPatternMatcher",
        "create_consensus_analyzer",
        "create_response_aggregator",
        "create_pattern_matcher",
        "get_performance_metrics",
        "RUST_AVAILABLE"
    ])
except ImportError:
    # Rust extensions not available
    RUST_AVAILABLE = False
