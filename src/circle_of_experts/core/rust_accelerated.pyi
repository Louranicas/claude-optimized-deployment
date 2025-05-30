"""
Type stubs for rust_accelerated module.

Provides type hints for IDE support and static type checking.
"""

from typing import List, Dict, Any, Optional, Tuple

# Rust-accelerated classes

class ConsensusAnalyzer:
    confidence_threshold: float
    consensus_threshold: float
    
    def __init__(self, confidence_threshold: float = 0.7, consensus_threshold: float = 0.8) -> None: ...
    
    def analyze_consensus(self, responses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Returns dict with keys:
        - consensus_score: float
        - agreement_level: str
        - confidence_distribution: List[float]
        - expert_agreements: List[str]
        - recommendation_frequency: Dict[str, int]
        - high_confidence_experts: List[str]
        """
        ...
    
    def find_agreements(self, responses: List[Dict[str, Any]]) -> List[str]: ...
    
    def calculate_confidence_stats(self, responses: List[Dict[str, Any]]) -> Dict[str, float]:
        """
        Returns dict with keys:
        - mean: float
        - std_dev: float
        - min: float
        - max: float
        - variance: float
        """
        ...

class ResponseAggregator:
    weight_by_confidence: bool
    deduplication_threshold: float
    
    def __init__(self, weight_by_confidence: bool = True, deduplication_threshold: float = 0.85) -> None: ...
    
    def aggregate_responses(self, responses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Returns dict with keys:
        - aggregated_content: str
        - recommendations: List[str]
        - overall_confidence: float
        - expert_count: int
        - aggregation_method: str
        """
        ...
    
    def merge_recommendations(self, responses: List[Dict[str, Any]]) -> List[str]: ...

class PatternMatcher:
    patterns: List[str]
    case_sensitive: bool
    
    def __init__(self, patterns: List[str], case_sensitive: bool = False) -> None: ...
    
    def find_patterns(self, responses: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """
        Returns dict mapping pattern to:
        - count: int
        - locations: List[Tuple[int, int]]
        """
        ...
    
    def extract_key_phrases(self, responses: List[Dict[str, Any]]) -> List[str]: ...

# Async variants

class AsyncConsensusAnalyzer(ConsensusAnalyzer):
    async def analyze_consensus_async(self, responses: List[Dict[str, Any]]) -> Dict[str, Any]: ...
    async def find_agreements_async(self, responses: List[Dict[str, Any]]) -> List[str]: ...

class AsyncResponseAggregator(ResponseAggregator):
    async def aggregate_responses_async(self, responses: List[Dict[str, Any]]) -> Dict[str, Any]: ...
    async def merge_recommendations_async(self, responses: List[Dict[str, Any]]) -> List[str]: ...

class AsyncPatternMatcher(PatternMatcher):
    async def find_patterns_async(self, responses: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]: ...
    async def extract_key_phrases_async(self, responses: List[Dict[str, Any]]) -> List[str]: ...

# Factory functions

def create_consensus_analyzer(
    confidence_threshold: float = 0.7,
    consensus_threshold: float = 0.8,
    async_mode: bool = False
) -> ConsensusAnalyzer | AsyncConsensusAnalyzer: ...

def create_response_aggregator(
    weight_by_confidence: bool = True,
    deduplication_threshold: float = 0.85,
    async_mode: bool = False
) -> ResponseAggregator | AsyncResponseAggregator: ...

def create_pattern_matcher(
    patterns: List[str],
    case_sensitive: bool = False,
    async_mode: bool = False
) -> PatternMatcher | AsyncPatternMatcher: ...

def get_performance_metrics() -> Dict[str, Any]: ...

# Module constants
RUST_AVAILABLE: bool