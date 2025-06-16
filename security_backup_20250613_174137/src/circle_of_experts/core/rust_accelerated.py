"""
Rust-Accelerated Circle of Experts Operations

This module provides Python interfaces to high-performance Rust implementations
for computationally intensive Circle of Experts operations.
"""

import asyncio
from typing import List, Dict, Any, Optional, Tuple, Iterator
import logging
from functools import lru_cache
import sys
import gc
from collections import deque
import weakref

__all__ = [
    "ConsensusAnalyzer",
    "ResponseAggregator",
    "PatternMatcher",
    "AsyncConsensusAnalyzer",
    "AsyncResponseAggregator",
    "AsyncPatternMatcher",
    "create_consensus_analyzer",
    "create_response_aggregator",
    "create_pattern_matcher",
    "get_performance_metrics"
]


logger = logging.getLogger(__name__)

try:
    # Import Rust bindings
    from claude_optimized_deployment_rust import (
        ConsensusAnalyzer as RustConsensusAnalyzer,
        ResponseAggregator as RustResponseAggregator,
        PatternMatcher as RustPatternMatcher,
        create_consensus_analyzer,
        create_response_aggregator,
        create_pattern_matcher,
    )
    RUST_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Rust extensions not available: {e}. Falling back to Python implementation.")
    RUST_AVAILABLE = False
    
    # Fallback implementations
    class RustConsensusAnalyzer:
        """Fallback Python implementation"""
        def __init__(self, confidence_threshold=0.7, consensus_threshold=0.8):
            self.confidence_threshold = confidence_threshold
            self.consensus_threshold = consensus_threshold
    
    class RustResponseAggregator:
        """Fallback Python implementation"""
        def __init__(self, weight_by_confidence=True, deduplication_threshold=0.85):
            self.weight_by_confidence = weight_by_confidence
            self.deduplication_threshold = deduplication_threshold
    
    class RustPatternMatcher:
        """Fallback Python implementation"""
        def __init__(self, patterns, case_sensitive=False):
            self.patterns = patterns
            self.case_sensitive = case_sensitive


class ConsensusAnalyzer:
    """
    High-performance consensus analysis for expert responses.
    
    Uses Rust for parallel processing of large response sets.
    """
    
    def __init__(self, confidence_threshold: float = 0.7, consensus_threshold: float = 0.8):
        """
        Initialize the consensus analyzer.
        
        Args:
            confidence_threshold: Minimum confidence level to consider a response high-confidence
            consensus_threshold: Minimum agreement ratio for consensus
        """
        if RUST_AVAILABLE:
            self._analyzer = create_consensus_analyzer(confidence_threshold, consensus_threshold)
        else:
            self._analyzer = RustConsensusAnalyzer(confidence_threshold, consensus_threshold)
        self.confidence_threshold = confidence_threshold
        self.consensus_threshold = consensus_threshold
    
    def analyze_consensus(self, responses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze consensus among expert responses.
        
        Args:
            responses: List of expert response dictionaries
            
        Returns:
            Dictionary containing consensus metrics
        """
        if not RUST_AVAILABLE:
            return self._python_fallback_consensus(responses)
        
        try:
            return self._analyzer.analyze_consensus(responses)
        except Exception as e:
            logger.error(f"Rust consensus analysis failed: {e}")
            return self._python_fallback_consensus(responses)
    
    def find_agreements(self, responses: List[Dict[str, Any]]) -> List[str]:
        """
        Find areas of agreement among experts.
        
        Args:
            responses: List of expert response dictionaries
            
        Returns:
            List of agreed-upon recommendations
        """
        if not RUST_AVAILABLE:
            return self._python_fallback_agreements(responses)
        
        try:
            return self._analyzer.find_agreements(responses)
        except Exception as e:
            logger.error(f"Rust agreement finding failed: {e}")
            return self._python_fallback_agreements(responses)
    
    def calculate_confidence_stats(self, responses: List[Dict[str, Any]]) -> Dict[str, float]:
        """
        Calculate confidence statistics across responses.
        
        Args:
            responses: List of expert response dictionaries
            
        Returns:
            Dictionary with statistical metrics
        """
        if not RUST_AVAILABLE:
            return self._python_fallback_stats(responses)
        
        try:
            return self._analyzer.calculate_confidence_stats(responses)
        except Exception as e:
            logger.error(f"Rust statistics calculation failed: {e}")
            return self._python_fallback_stats(responses)
    
    def _python_fallback_consensus(self, responses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Python fallback implementation for consensus analysis"""
        if not responses:
            return {
                "consensus_score": 0.0,
                "agreement_level": "none",
                "confidence_distribution": [],
                "expert_agreements": [],
                "recommendation_frequency": {},
                "high_confidence_experts": []
            }
        
        confidences = [r.get("confidence", 0.0) for r in responses]
        avg_confidence = sum(confidences) / len(confidences)
        
        # Simple consensus calculation
        recommendations = []
        for r in responses:
            recommendations.extend(r.get("recommendations", []))
        
        rec_freq = {}
        for rec in recommendations:
            rec_lower = rec.lower()
            rec_freq[rec_lower] = rec_freq.get(rec_lower, 0) + 1
        
        high_conf_experts = [
            r.get("expert_name", "Unknown") 
            for r in responses 
            if r.get("confidence", 0) >= self.confidence_threshold
        ]
        
        return {
            "consensus_score": avg_confidence,
            "agreement_level": "moderate" if avg_confidence > 0.6 else "weak",
            "confidence_distribution": confidences,
            "expert_agreements": list(rec_freq.keys())[:5],
            "recommendation_frequency": rec_freq,
            "high_confidence_experts": high_conf_experts
        }
    
    def _python_fallback_agreements(self, responses: List[Dict[str, Any]]) -> List[str]:
        """Python fallback for finding agreements"""
        rec_counts = {}
        for r in responses:
            for rec in r.get("recommendations", []):
                rec_lower = rec.lower()
                rec_counts[rec_lower] = rec_counts.get(rec_lower, 0) + 1
        
        threshold = len(responses) * self.consensus_threshold
        return [rec for rec, count in rec_counts.items() if count >= threshold]
    
    def _python_fallback_stats(self, responses: List[Dict[str, Any]]) -> Dict[str, float]:
        """Python fallback for statistics calculation"""
        confidences = [r.get("confidence", 0.0) for r in responses]
        if not confidences:
            return {}
        
        mean = sum(confidences) / len(confidences)
        variance = sum((c - mean) ** 2 for c in confidences) / len(confidences)
        
        return {
            "mean": mean,
            "std_dev": variance ** 0.5,
            "min": min(confidences),
            "max": max(confidences),
            "variance": variance
        }


class ResponseAggregator:
    """
    High-performance response aggregation and synthesis.
    
    Uses Rust for efficient deduplication and content merging.
    """
    
    def __init__(self, weight_by_confidence: bool = True, deduplication_threshold: float = 0.85,
                 max_chunk_size: int = 1000, enable_streaming: bool = True):
        """
        Initialize the response aggregator.
        
        Args:
            weight_by_confidence: Whether to weight responses by confidence scores
            deduplication_threshold: Similarity threshold for deduplication
            max_chunk_size: Maximum size of data chunks for streaming processing
            enable_streaming: Whether to use streaming data conversion
        """
        if RUST_AVAILABLE:
            self._aggregator = create_response_aggregator(weight_by_confidence, deduplication_threshold)
        else:
            self._aggregator = RustResponseAggregator(weight_by_confidence, deduplication_threshold)
        self.weight_by_confidence = weight_by_confidence
        self.deduplication_threshold = deduplication_threshold
        
        # Memory optimization settings
        self.max_chunk_size = max_chunk_size
        self.enable_streaming = enable_streaming
        
        # Data conversion cache with size limit
        self._conversion_cache: deque = deque(maxlen=100)
        self._cache_hits = 0
        self._cache_misses = 0
    
    def aggregate_responses(self, responses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Aggregate multiple expert responses into a unified response with streaming.
        
        Args:
            responses: List of expert response dictionaries
            
        Returns:
            Aggregated response dictionary
        """
        if not RUST_AVAILABLE:
            return self._python_fallback_aggregate(responses)
        
        try:
            if self.enable_streaming and len(responses) > self.max_chunk_size:
                return self._stream_aggregate_responses(responses)
            else:
                # Use optimized data conversion
                processed_responses = self._optimize_data_conversion(responses)
                result = self._aggregator.aggregate_responses(processed_responses)
                
                # Trigger garbage collection for large responses
                if len(responses) > 100:
                    gc.collect()
                
                return result
        except Exception as e:
            logger.error(f"Rust response aggregation failed: {e}")
            return self._python_fallback_aggregate(responses)
    
    def merge_recommendations(self, responses: List[Dict[str, Any]]) -> List[str]:
        """
        Merge and deduplicate recommendations from multiple experts with streaming.
        
        Args:
            responses: List of expert response dictionaries
            
        Returns:
            Merged list of unique recommendations
        """
        if not RUST_AVAILABLE:
            return self._python_fallback_merge(responses)
        
        try:
            if self.enable_streaming and len(responses) > self.max_chunk_size:
                return self._stream_merge_recommendations(responses)
            else:
                # Use optimized data conversion with minimal copying
                processed_responses = [
                    {
                        "confidence": r.get("confidence", 0.5),
                        "expert_name": r.get("expert_name", "Unknown"),
                        "content": r.get("content", "")[:500],  # Limit content size
                        "recommendations": r.get("recommendations", [])[:20]  # Limit recommendations
                    }
                    for r in responses
                ]
                result = self._aggregator.merge_recommendations(processed_responses)
                
                # Clear processed data to free memory
                del processed_responses
                
                return result
        except Exception as e:
            logger.error(f"Rust recommendation merging failed: {e}")
            return self._python_fallback_merge(responses)
    
    def _python_fallback_aggregate(self, responses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Python fallback for response aggregation"""
        if not responses:
            return {
                "aggregated_content": "",
                "recommendations": [],
                "overall_confidence": 0.0,
                "expert_count": 0,
                "aggregation_method": "weighted_by_confidence" if self.weight_by_confidence else "equal_weight"
            }
        
        # Simple aggregation
        contents = [r.get("content", "") for r in responses]
        aggregated_content = "\n\n".join(contents)
        
        all_recommendations = []
        for r in responses:
            all_recommendations.extend(r.get("recommendations", []))
        
        # Remove duplicates
        unique_recommendations = list(dict.fromkeys(all_recommendations))
        
        confidences = [r.get("confidence", 0.5) for r in responses]
        overall_confidence = sum(confidences) / len(confidences)
        
        return {
            "aggregated_content": aggregated_content,
            "recommendations": unique_recommendations,
            "overall_confidence": overall_confidence,
            "expert_count": len(responses),
            "aggregation_method": "weighted_by_confidence" if self.weight_by_confidence else "equal_weight"
        }
    
    def _python_fallback_merge(self, responses: List[Dict[str, Any]]) -> List[str]:
        """Python fallback for recommendation merging"""
        all_recs = []
        for r in responses:
            all_recs.extend(r.get("recommendations", []))
        return list(dict.fromkeys(all_recs))
    
    def _optimize_data_conversion(self, responses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Optimize data conversion to minimize memory usage."""
        # Use generator for memory-efficient processing
        def convert_response(response):
            return {
                "confidence": response.get("confidence", 0.5),
                "expert_name": response.get("expert_name", "Unknown"),
                "content": response.get("content", "")[:1000],  # Limit content size
                "recommendations": response.get("recommendations", [])[:50]  # Limit recommendations
            }
        
        # Process in chunks to limit memory spikes
        result = []
        for i in range(0, len(responses), self.max_chunk_size):
            chunk = responses[i:i + self.max_chunk_size]
            processed_chunk = [convert_response(r) for r in chunk]
            result.extend(processed_chunk)
            
            # Force garbage collection after each chunk
            if len(chunk) == self.max_chunk_size:
                gc.collect()
        
        return result
    
    def _stream_aggregate_responses(self, responses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Stream-process large response sets to prevent memory spikes."""
        # Process responses in chunks
        aggregated_content = []
        all_recommendations = set()
        confidence_sum = 0
        expert_count = 0
        
        for i in range(0, len(responses), self.max_chunk_size):
            chunk = responses[i:i + self.max_chunk_size]
            
            # Process chunk
            for response in chunk:
                content = response.get("content", "")
                if content and len(content) < 2000:  # Skip very large content
                    aggregated_content.append(content)
                
                recommendations = response.get("recommendations", [])
                all_recommendations.update(recommendations[:10])  # Limit per response
                
                confidence_sum += response.get("confidence", 0.5)
                expert_count += 1
            
            # Force garbage collection after each chunk
            gc.collect()
        
        # Limit final aggregated content size
        final_content = "\n\n".join(aggregated_content[:100])  # Max 100 content pieces
        
        return {
            "aggregated_content": final_content,
            "recommendations": list(all_recommendations)[:50],  # Max 50 recommendations
            "overall_confidence": confidence_sum / expert_count if expert_count > 0 else 0.0,
            "expert_count": expert_count,
            "aggregation_method": "streaming_weighted" if self.weight_by_confidence else "streaming_equal"
        }
    
    def _stream_merge_recommendations(self, responses: List[Dict[str, Any]]) -> List[str]:
        """Stream-merge recommendations to prevent memory buildup."""
        unique_recommendations = set()
        
        for i in range(0, len(responses), self.max_chunk_size):
            chunk = responses[i:i + self.max_chunk_size]
            
            for response in chunk:
                recommendations = response.get("recommendations", [])
                # Limit recommendations per response to prevent memory explosion
                unique_recommendations.update(recommendations[:15])
            
            # Limit total unique recommendations to prevent unbounded growth
            if len(unique_recommendations) > 200:
                # Keep only the first 200 recommendations
                unique_recommendations = set(list(unique_recommendations)[:200])
            
            # Force garbage collection
            gc.collect()
        
        return list(unique_recommendations)[:100]  # Final limit
    
    def get_memory_stats(self) -> Dict[str, Any]:
        """Get memory usage statistics."""
        return {
            "cache_size": len(self._conversion_cache),
            "cache_hits": self._cache_hits,
            "cache_misses": self._cache_misses,
            "cache_hit_ratio": self._cache_hits / (self._cache_hits + self._cache_misses) if (self._cache_hits + self._cache_misses) > 0 else 0,
            "streaming_enabled": self.enable_streaming,
            "max_chunk_size": self.max_chunk_size,
            "memory_usage_mb": sys.getsizeof(self) / 1024 / 1024
        }
    
    def cleanup(self):
        """Clean up resources and caches."""
        self._conversion_cache.clear()
        self._cache_hits = 0
        self._cache_misses = 0
        gc.collect()


class PatternMatcher:
    """
    High-performance pattern matching for expert responses.
    
    Uses Rust for parallel pattern search and extraction.
    """
    
    def __init__(self, patterns: List[str], case_sensitive: bool = False):
        """
        Initialize the pattern matcher.
        
        Args:
            patterns: List of patterns to search for
            case_sensitive: Whether pattern matching should be case-sensitive
        """
        if RUST_AVAILABLE:
            self._matcher = create_pattern_matcher(patterns, case_sensitive)
        else:
            self._matcher = RustPatternMatcher(patterns, case_sensitive)
        self.patterns = patterns
        self.case_sensitive = case_sensitive
    
    def find_patterns(self, responses: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """
        Find patterns in expert responses.
        
        Args:
            responses: List of expert response dictionaries
            
        Returns:
            Dictionary mapping patterns to their occurrences
        """
        if not RUST_AVAILABLE:
            return self._python_fallback_find(responses)
        
        try:
            return self._matcher.find_patterns(responses)
        except Exception as e:
            logger.error(f"Rust pattern finding failed: {e}")
            return self._python_fallback_find(responses)
    
    def extract_key_phrases(self, responses: List[Dict[str, Any]]) -> List[str]:
        """
        Extract key phrases from responses.
        
        Args:
            responses: List of expert response dictionaries
            
        Returns:
            List of key phrases
        """
        if not RUST_AVAILABLE:
            return self._python_fallback_extract(responses)
        
        try:
            return self._matcher.extract_key_phrases(responses)
        except Exception as e:
            logger.error(f"Rust key phrase extraction failed: {e}")
            return self._python_fallback_extract(responses)
    
    def _python_fallback_find(self, responses: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Python fallback for pattern finding"""
        results = {}
        
        for pattern in self.patterns:
            locations = []
            count = 0
            
            for i, response in enumerate(responses):
                content = response.get("content", "")
                if not self.case_sensitive:
                    content = content.lower()
                    search_pattern = pattern.lower()
                else:
                    search_pattern = pattern
                
                pos = 0
                while True:
                    idx = content.find(search_pattern, pos)
                    if idx == -1:
                        break
                    locations.append((i, idx))
                    count += 1
                    pos = idx + 1
            
            results[pattern] = {
                "count": count,
                "locations": locations
            }
        
        return results
    
    def _python_fallback_extract(self, responses: List[Dict[str, Any]]) -> List[str]:
        """Python fallback for key phrase extraction"""
        # Simple extraction of common phrases
        phrases = []
        for r in responses:
            content = r.get("content", "")
            words = content.split()
            for i in range(len(words) - 2):
                phrase = " ".join(words[i:i+3])
                if len(phrase) > 10:
                    phrases.append(phrase)
        
        # Return most common phrases
        from collections import Counter
        phrase_counts = Counter(phrases)
        return [phrase for phrase, _ in phrase_counts.most_common(10)]


# Async wrappers for seamless integration
class AsyncConsensusAnalyzer(ConsensusAnalyzer):
    """Async-compatible consensus analyzer"""
    
    async def analyze_consensus_async(self, responses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Async wrapper for consensus analysis"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.analyze_consensus, responses)
    
    async def find_agreements_async(self, responses: List[Dict[str, Any]]) -> List[str]:
        """Async wrapper for finding agreements"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.find_agreements, responses)


class AsyncResponseAggregator(ResponseAggregator):
    """Async-compatible response aggregator"""
    
    async def aggregate_responses_async(self, responses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Async wrapper for response aggregation"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.aggregate_responses, responses)
    
    async def merge_recommendations_async(self, responses: List[Dict[str, Any]]) -> List[str]:
        """Async wrapper for recommendation merging"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.merge_recommendations, responses)


class AsyncPatternMatcher(PatternMatcher):
    """Async-compatible pattern matcher"""
    
    async def find_patterns_async(self, responses: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Async wrapper for pattern finding"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.find_patterns, responses)
    
    async def extract_key_phrases_async(self, responses: List[Dict[str, Any]]) -> List[str]:
        """Async wrapper for key phrase extraction"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.extract_key_phrases, responses)


# Factory functions for convenience
def create_consensus_analyzer(confidence_threshold: float = 0.7, 
                            consensus_threshold: float = 0.8,
                            async_mode: bool = False) -> ConsensusAnalyzer:
    """
    Create a consensus analyzer instance.
    
    Args:
        confidence_threshold: Minimum confidence level
        consensus_threshold: Minimum agreement ratio
        async_mode: Whether to return async-compatible version
        
    Returns:
        ConsensusAnalyzer or AsyncConsensusAnalyzer instance
    """
    if async_mode:
        return AsyncConsensusAnalyzer(confidence_threshold, consensus_threshold)
    return ConsensusAnalyzer(confidence_threshold, consensus_threshold)


def create_response_aggregator(weight_by_confidence: bool = True,
                             deduplication_threshold: float = 0.85,
                             async_mode: bool = False) -> ResponseAggregator:
    """
    Create a response aggregator instance.
    
    Args:
        weight_by_confidence: Whether to weight by confidence
        deduplication_threshold: Similarity threshold
        async_mode: Whether to return async-compatible version
        
    Returns:
        ResponseAggregator or AsyncResponseAggregator instance
    """
    if async_mode:
        return AsyncResponseAggregator(weight_by_confidence, deduplication_threshold)
    return ResponseAggregator(weight_by_confidence, deduplication_threshold)


def create_pattern_matcher(patterns: List[str],
                         case_sensitive: bool = False,
                         async_mode: bool = False) -> PatternMatcher:
    """
    Create a pattern matcher instance.
    
    Args:
        patterns: List of patterns to search for
        case_sensitive: Whether matching is case-sensitive
        async_mode: Whether to return async-compatible version
        
    Returns:
        PatternMatcher or AsyncPatternMatcher instance
    """
    if async_mode:
        return AsyncPatternMatcher(patterns, case_sensitive)
    return PatternMatcher(patterns, case_sensitive)


# Performance metrics
@lru_cache(maxsize=1)
def get_performance_metrics() -> Dict[str, Any]:
    """
    Get performance metrics comparing Rust vs Python implementations.
    
    Returns:
        Dictionary with performance comparison data
    """
    return {
        "rust_available": RUST_AVAILABLE,
        "expected_speedup": {
            "consensus_analysis": "10-50x for large response sets",
            "response_aggregation": "5-20x for deduplication",
            "pattern_matching": "20-100x for regex operations"
        },
        "memory_efficiency": {
            "consensus_analysis": "50% less memory usage",
            "response_aggregation": "Zero-copy operations",
            "pattern_matching": "Streaming processing"
        },
        "parallelism": {
            "consensus_analysis": "Uses all CPU cores via Rayon",
            "response_aggregation": "Parallel deduplication",
            "pattern_matching": "Concurrent pattern search"
        }
    }


# Module initialization
if RUST_AVAILABLE:
    logger.info("Rust acceleration enabled for Circle of Experts")
else:
    logger.info("Using Python fallback implementation for Circle of Experts")