"""
Response Collector for Circle of Experts.

Collects and aggregates responses from multiple experts.
"""

from __future__ import annotations
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging
from collections import defaultdict

from src.core.object_pool import DictPool, ListPool, pooled
from src.core.memory_monitor import with_memory_monitoring
from src.core.stream_processor import MemoryEfficientBuffer

from src.circle_of_experts.models.response import ExpertResponse, ExpertType, ResponseStatus, ConsensusResponse
from src.circle_of_experts.models.query import ExpertQuery
from src.circle_of_experts.drive.manager import DriveManager
from src.circle_of_experts.utils.logging import LogContext
from src.circle_of_experts.utils.rust_integration import get_rust_integration
from src.circle_of_experts.utils.validation import (
    validate_string, validate_list, validate_number,
    ValidationError
)

__all__ = [
    "ResponseCollector"
]
from src.core.lru_cache import create_ttl_dict
from src.core.cleanup_scheduler import get_cleanup_scheduler

logger = logging.getLogger(__name__)


class ResponseCollector:
    """
    Collects and manages responses from the circle of experts.
    
    This class handles monitoring for responses, collecting them from Drive,
    and providing aggregation and analysis capabilities.
    """
    
    def __init__(self, drive_manager: DriveManager):
        """
        Initialize the ResponseCollector.
        
        Args:
            drive_manager: DriveManager instance for Google Drive operations
        """
        if drive_manager is None:
            raise ValidationError("drive_manager", None, "DriveManager cannot be None")
        self.drive_manager = drive_manager
        
        # Use bounded TTL dicts for responses (TTL: 4 hours, max: 500 queries)
        self._responses = create_ttl_dict(
            max_size=500,
            ttl=14400.0,  # 4 hours
            cleanup_interval=600.0  # 10 minutes
        )
        
        # Response file mapping with TTL (TTL: 4 hours, max: 2000 entries)
        self._response_files = create_ttl_dict(
            max_size=2000,
            ttl=14400.0,  # 4 hours
            cleanup_interval=600.0  # 10 minutes
        )
        
        # Memory-efficient buffer for response aggregation
        self._response_buffer = MemoryEfficientBuffer(
            max_size=1000,
            flush_threshold=0.8,
            auto_flush_handler=self._process_buffered_responses
        )
        
        # Get Rust integration manager
        self._rust_integration = get_rust_integration()
        
        # Register cleanup with scheduler
        try:
            cleanup_scheduler = get_cleanup_scheduler()
            cleanup_scheduler.register_cleanable_object(self._responses)
            cleanup_scheduler.register_cleanable_object(self._response_files)
            cleanup_scheduler.register_task(
                name=f"response_collector_{id(self)}_cleanup",
                callback=self._cleanup_expired_responses,
                interval_seconds=600.0,  # 10 minutes
                priority=cleanup_scheduler.TaskPriority.MEDIUM
            )
        except Exception as e:
            logger.warning(f"Could not register with cleanup scheduler: {e}")
    
    @with_memory_monitoring
    async def collect_responses(
        self,
        query_id: str,
        timeout: float = 300.0,
        min_responses: int = 1,
        required_experts: Optional[List[ExpertType]] = None
    ) -> List[ExpertResponse]:
        """
        Collect responses for a specific query.
        
        Args:
            query_id: ID of the query to collect responses for
            timeout: Maximum time to wait for responses (seconds)
            min_responses: Minimum number of responses to collect
            required_experts: Specific experts that must respond
            
        Returns:
            List of collected responses
        """
        # Validate parameters
        query_id = validate_string(query_id, "query_id", required=True)
        timeout = validate_number(timeout, "timeout", min_value=1.0, max_value=3600.0)
        min_responses = validate_number(min_responses, "min_responses", min_value=0, max_value=20, allow_float=False)
        required_experts = validate_list(required_experts, "required_experts", item_type=ExpertType)
        
        with LogContext(query_id=query_id, action="collect_responses"):
            logger.info(
                f"Starting response collection for query {query_id} "
                f"(timeout={timeout}s, min_responses={min_responses})"
            )
            
            # Watch for responses
            responses = await self.drive_manager.watch_for_responses(
                query_id=query_id,
                timeout=timeout,
                poll_interval=10.0
            )
            
            # Store collected responses using memory-efficient buffer
            self._response_buffer.add_batch(responses)
            existing = self._responses.get(query_id, [])
            existing.extend(responses)
            self._responses[query_id] = existing
            
            # Check if we have minimum responses
            if len(responses) < min_responses:
                logger.warning(
                    f"Only collected {len(responses)}/{min_responses} responses "
                    f"for query {query_id}"
                )
            
            # Check if required experts responded
            if required_experts:
                responded_experts = {r.expert_type for r in responses}
                missing_experts = set(required_experts) - responded_experts
                
                if missing_experts:
                    logger.warning(
                        f"Missing responses from required experts: {missing_experts}"
                    )
            
            logger.info(f"Collected {len(responses)} responses for query {query_id}")
            return responses
    
    async def get_responses(self, query_id: str) -> List[ExpertResponse]:
        """
        Get all collected responses for a query.
        
        Args:
            query_id: ID of the query
            
        Returns:
            List of responses for the query
        """
        # Validate parameter
        query_id = validate_string(query_id, "query_id", required=True)
        
        return self._responses.get(query_id, [])
    
    async def aggregate_responses(self, query_id: str) -> Dict[str, Any]:
        """
        Aggregate responses from multiple experts.
        Uses Rust-accelerated aggregation if available, falls back to Python.
        
        Args:
            query_id: ID of the query
            
        Returns:
            Aggregated analysis of responses
        """
        # Validate parameter
        query_id = validate_string(query_id, "query_id", required=True)
        
        responses = await self.get_responses(query_id)
        
        if not responses:
            return {
                "status": "no_responses",
                "summary": "No responses collected yet"
            }
        
        # Try Rust-accelerated aggregation first
        if len(responses) > 1:
            # Convert responses to format expected by Rust
            rust_responses = [
                {
                    "expert_type": r.expert_type.value,
                    "content": r.content,
                    "confidence": r.confidence,
                    "recommendations": r.recommendations,
                    "code_snippets": r.code_snippets,
                    "limitations": r.limitations,
                    "processing_time": r.processing_time or 0.0
                }
                for r in responses
            ]
            
            # Use Rust integration manager
            aggregation, used_rust = self._rust_integration.aggregate_responses(rust_responses)
            
            # Add query-specific metadata
            aggregation["query_id"] = query_id
            aggregation["accelerated"] = used_rust
            
            if used_rust:
                logger.debug(f"Using Rust-accelerated aggregation for query {query_id}")
            
            return aggregation
        
        # Python fallback implementation
        # Calculate consensus metrics
        total_confidence = sum(r.confidence for r in responses)
        avg_confidence = total_confidence / len(responses) if responses else 0
        
        # Collect all recommendations
        all_recommendations = []
        for response in responses:
            all_recommendations.extend(response.recommendations)
        
        # Find common recommendations (appearing in multiple responses)
        recommendation_counts = defaultdict(int)
        for rec in all_recommendations:
            recommendation_counts[rec.lower()] += 1
        
        common_recommendations = [
            rec for rec, count in recommendation_counts.items()
            if count >= len(responses) / 2  # At least half agree
        ]
        
        # Aggregate code snippets
        all_code_snippets = []
        for response in responses:
            all_code_snippets.extend(response.code_snippets)
        
        # Aggregate limitations
        all_limitations = []
        for response in responses:
            all_limitations.extend(response.limitations)
        
        # Build aggregated response
        aggregation = {
            "query_id": query_id,
            "response_count": len(responses),
            "experts": [r.expert_type.value for r in responses],
            "average_confidence": round(avg_confidence, 2),
            "consensus_level": self._calculate_consensus(responses),
            "common_recommendations": common_recommendations,
            "all_recommendations": list(set(all_recommendations)),
            "code_examples_count": len(all_code_snippets),
            "limitations": list(set(all_limitations)),
            "processing_times": {
                r.expert_type.value: r.processing_time
                for r in responses
                if r.processing_time
            },
            "summary": self._generate_summary(responses),
            "accelerated": False
        }
        
        return aggregation
    
    def _calculate_consensus(self, responses: List[ExpertResponse]) -> str:
        """
        Calculate consensus level among responses.
        Uses Rust-accelerated calculation if available.
        
        Args:
            responses: List of responses to analyze
            
        Returns:
            Consensus level (high/medium/low)
        """
        if len(responses) < 2:
            return "n/a"
        
        # Use Rust integration for consensus calculation
        response_data = [
            {
                "expert_type": r.expert_type.value,
                "confidence": r.confidence,
                "content": r.content,
                "recommendations": r.recommendations
            }
            for r in responses
        ]
        
        consensus_result, used_rust = self._rust_integration.analyze_consensus(response_data)
        
        if used_rust:
            return consensus_result.get("agreement_level", "low")
        
        # Python fallback
        confidences = [r.confidence for r in responses]
        avg_confidence = sum(confidences) / len(confidences)
        confidence_variance = sum((c - avg_confidence) ** 2 for c in confidences) / len(confidences)
        
        if confidence_variance < 0.05 and avg_confidence > 0.7:
            return "high"
        elif confidence_variance < 0.1 and avg_confidence > 0.5:
            return "medium"
        else:
            return "low"
    
    def _generate_summary(self, responses: List[ExpertResponse]) -> str:
        """
        Generate a summary of the responses.
        
        Args:
            responses: List of responses to summarize
            
        Returns:
            Summary text
        """
        if not responses:
            return "No responses to summarize."
        
        expert_types = [r.expert_type.value for r in responses]
        avg_confidence = sum(r.confidence for r in responses) / len(responses)
        
        summary_parts = [
            f"Received {len(responses)} responses from {', '.join(expert_types)}.",
            f"Average confidence: {avg_confidence:.2f}.",
        ]
        
        # Add consensus information
        if len(responses) > 1:
            consensus = self._calculate_consensus(responses)
            summary_parts.append(f"Consensus level: {consensus}.")
        
        # Add recommendation count
        total_recommendations = sum(len(r.recommendations) for r in responses)
        if total_recommendations > 0:
            summary_parts.append(f"Total recommendations: {total_recommendations}.")
        
        return " ".join(summary_parts)
    
    async def create_consensus_report(
        self,
        query: ExpertQuery,
        responses: List[ExpertResponse]
    ) -> str:
        """
        Create a consensus report from multiple expert responses.
        
        Args:
            query: Original query
            responses: List of expert responses
            
        Returns:
            Markdown-formatted consensus report
        """
        # Validate parameters
        if query is None:
            raise ValidationError("query", None, "Query cannot be None")
        if not isinstance(query, ExpertQuery):
            raise ValidationError("query", query, f"Expected ExpertQuery, got {type(query).__name__}")
        responses = validate_list(responses, "responses", min_items=0)
        
        aggregation = await self.aggregate_responses(query.id)
        
        report_lines = [
            f"# Consensus Report: {query.title}",
            f"",
            f"**Query ID:** {query.id}",
            f"**Created:** {query.created_at.isoformat()}",
            f"**Responses:** {len(responses)} from {', '.join(aggregation['experts'])}",
            f"",
            f"## Summary",
            f"",
            aggregation['summary'],
            f"",
            f"## Consensus Analysis",
            f"",
            f"- **Consensus Level:** {aggregation['consensus_level']}",
            f"- **Average Confidence:** {aggregation['average_confidence']}",
            f"",
        ]
        
        if aggregation['common_recommendations']:
            report_lines.extend([
                f"## Common Recommendations",
                f"",
                f"The following recommendations were mentioned by multiple experts:",
                f"",
            ])
            for rec in aggregation['common_recommendations']:
                report_lines.append(f"- {rec}")
            report_lines.append("")
        
        if aggregation['all_recommendations']:
            report_lines.extend([
                f"## All Recommendations",
                f"",
            ])
            for rec in sorted(set(aggregation['all_recommendations'])):
                report_lines.append(f"- {rec}")
            report_lines.append("")
        
        # Add individual expert responses
        report_lines.extend([
            f"## Individual Expert Responses",
            f"",
        ])
        
        for response in responses:
            report_lines.extend([
                f"### {response.expert_type.value.upper()}",
                f"",
                f"**Confidence:** {response.confidence:.2f}",
                f"**Processing Time:** {response.processing_time:.2f}s" if response.processing_time else "",
                f"",
                f"{response.content[:500]}..." if len(response.content) > 500 else response.content,
                f"",
            ])
        
        return "
".join(report_lines)
    
    async def save_consensus_report(
        self,
        query: ExpertQuery,
        responses: List[ExpertResponse]
    ) -> str:
        """
        Create and save a consensus report to Drive.
        
        Args:
            query: Original query
            responses: List of expert responses
            
        Returns:
            File ID of the saved report
        """
        # Validate parameters - consensus report creation will validate these too
        if query is None:
            raise ValidationError("query", None, "Query cannot be None")
        if not isinstance(query, ExpertQuery):
            raise ValidationError("query", query, f"Expected ExpertQuery, got {type(query).__name__}")
        responses = validate_list(responses, "responses", min_items=0)
        
        report_content = await self.create_consensus_report(query, responses)
        
        # Create a special response object for the consensus
        consensus_response = ExpertResponse(
            query_id=query.id,
            expert_type=ExpertType.HUMAN,  # Mark as human-generated consensus
            content=report_content,
            confidence=1.0,
            status=ResponseStatus.COMPLETED,
            metadata={"type": "consensus_report"}
        )
        
        # Upload to Drive
        file_id = await self.drive_manager.upload_response(consensus_response)
        
        logger.info(f"Saved consensus report for query {query.id} as file {file_id}")
        return file_id
    
    def build_consensus(self, responses: List[ExpertResponse]) -> ConsensusResponse:
        """
        Build a consensus from multiple expert responses.
        
        Args:
            responses: List of expert responses
            
        Returns:
            ConsensusResponse object
        """
        # Validate parameters
        responses = validate_list(responses, "responses", min_items=1)
        for i, response in enumerate(responses):
            if not isinstance(response, ExpertResponse):
                raise ValidationError(f"responses[{i}]", response, f"Expected ExpertResponse, got {type(response).__name__}")
        
        # Calculate average confidence
        avg_confidence = sum(r.confidence for r in responses) / len(responses)
        
        # Get participating experts
        participating_experts = list(set(r.expert_type for r in responses))
        
        # Find common recommendations
        recommendation_counts = defaultdict(int)
        for response in responses:
            for rec in response.recommendations:
                recommendation_counts[rec.lower()] += 1
        
        threshold = len(responses) / 2
        common_recommendations = [
            rec for rec, count in recommendation_counts.items()
            if count >= threshold
        ]
        
        # Collect unique limitations
        all_limitations = set()
        for response in responses:
            all_limitations.update(limitation.lower() for limitation in response.limitations)
        
        # Determine consensus level
        consensus_level = self._calculate_consensus(responses)
        
        # Try to use Rust acceleration for detailed analysis
        consensus_analysis = None
        if self._rust_integration:
            response_data = [
                {
                    "confidence": r.confidence,
                    "expert_type": r.expert_type.value,
                    "recommendations": r.recommendations,
                    "limitations": r.limitations
                }
                for r in responses
            ]
            
            analysis_result, used_rust = self._rust_integration.analyze_responses(response_data)
            if used_rust and analysis_result:
                consensus_analysis = analysis_result
        
        return ConsensusResponse(
            query_id=responses[0].query_id if responses else "",
            average_confidence=avg_confidence,
            participating_experts=participating_experts,
            common_recommendations=common_recommendations,
            unique_limitations=list(all_limitations),
            consensus_level=consensus_level,
            consensus_analysis=consensus_analysis
        )
    
    def _cleanup_expired_responses(self) -> int:
        """
        Clean up expired responses and file mappings.
        
        Returns:
            Number of expired entries removed
        """
        try:
            response_cleanup = self._responses.cleanup()
            file_cleanup = self._response_files.cleanup()
            total_cleanup = response_cleanup + file_cleanup
            
            if total_cleanup > 0:
                logger.info(f"Cleaned up {response_cleanup} response entries and {file_cleanup} file mappings")
            
            return total_cleanup
        except Exception as e:
            logger.error(f"Error during response cleanup: {e}")
            return 0
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics for monitoring."""
        try:
            response_stats = self._responses.get_stats()
            file_stats = self._response_files.get_stats()
            
            return {
                "responses_cache": response_stats.to_dict(),
                "response_files_cache": file_stats.to_dict(),
                "response_cache_size": len(self._responses),
                "file_cache_size": len(self._response_files),
                "buffer_size": self._response_buffer.size(),
                "cache_type": "TTLDict with LRU eviction"
            }
        except Exception as e:
            logger.error(f"Error getting cache stats: {e}")
            return {}
            
    def _process_buffered_responses(self, buffered_responses: List[ExpertResponse]):
        """
        Process buffered responses efficiently using object pools.
        
        Args:
            buffered_responses: List of responses to process
        """
        if not buffered_responses:
            return
            
        # Use pooled objects for processing
        with pooled(DictPool) as analysis_results:
            for response in buffered_responses:
                # Process response efficiently
                query_id = response.query_id
                
                # Aggregate buffered data
                if query_id not in analysis_results:
                    analysis_results[query_id] = {
                        "count": 0,
                        "total_confidence": 0.0,
                        "expert_types": set()
                    }
                    
                analysis_results[query_id]["count"] += 1
                analysis_results[query_id]["total_confidence"] += response.confidence
                analysis_results[query_id]["expert_types"].add(response.expert_type)
                
            # Log aggregated results
            for query_id, results in analysis_results.items():
                avg_confidence = results["total_confidence"] / results["count"]
                logger.debug(
                    f"Processed {results['count']} buffered responses for query {query_id}, "
                    f"avg confidence: {avg_confidence:.2f}"
                )
                
    def optimize_memory_usage(self):
        """
        Optimize memory usage by clearing caches and triggering GC.
        """
        # Flush buffer
        self._response_buffer.flush()
        
        # Clear expired entries
        self._cleanup_expired_responses()
        
        # Force garbage collection if we have integration
        from src.core.gc_optimization import gc_optimizer
        gc_optimizer.trigger_gc(force=True)
        
        logger.info("Optimized response collector memory usage")
