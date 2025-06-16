"""
Expert Manager for Circle of Experts system.

Handles expert consultation workflow including:
- Query submission to Google Drive
- Expert response collection
- Consensus building
"""

from __future__ import annotations
from typing import Optional, List, Dict, Any
from pathlib import Path
import asyncio
import logging
from uuid import uuid4
import time

from src.circle_of_experts.models.query import ExpertQuery, QueryPriority, QueryType
from src.circle_of_experts.models.response import ExpertResponse, ExpertType
from src.circle_of_experts.drive.manager import DriveManager
from .query_handler import QueryHandler
from .response_collector import ResponseCollector
from src.circle_of_experts.utils.logging import setup_logging, LogContext
from src.circle_of_experts.utils.rust_integration import get_rust_integration
__all__ = [
    "ExpertManager"
]

from src.circle_of_experts.utils.validation import (
    validate_string, validate_dict, validate_list, 
    validate_query_parameters, ValidationError
)
from src.core.lru_cache import create_ttl_dict
from src.core.cleanup_scheduler import get_cleanup_scheduler

logger = logging.getLogger(__name__)


class ExpertManager:
    """
    Manages the Circle of Experts workflow.
    
    This class handles:
    - Query submission to Google Drive
    - Response collection from experts
    - Consensus aggregation
    - Query status tracking
    """
    
    def __init__(
        self,
        credentials_path: Optional[str] = None,
        queries_folder_id: str = "1ob-NYNWMXaE3oiyPzRAk2-VpNbMvfFMS",
        responses_folder_id: str = "1YWh7lD1x8z8HrF-1FS6qPCw64ZQwvUHv",
        log_level: str = "INFO",
        log_file: Optional[Path] = None
    ):
        """
        Initialize the Expert Manager.
        
        Args:
            credentials_path: Path to Google Drive credentials JSON
            queries_folder_id: ID of the queries folder in Drive
            responses_folder_id: ID of the responses folder in Drive
            log_level: Logging level
            log_file: Optional log file path
        """
        # Validate parameters
        queries_folder_id = validate_string(queries_folder_id, "queries_folder_id", required=True)
        responses_folder_id = validate_string(responses_folder_id, "responses_folder_id", required=True)
        log_level = validate_string(log_level, "log_level", required=True)
        
        # Setup logging
        setup_logging(log_level, log_file)
        
        # Initialize Drive manager
        self.drive_manager = DriveManager(
            credentials_path=credentials_path,
            queries_folder_id=queries_folder_id,
            responses_folder_id=responses_folder_id
        )
        
        # Initialize handlers
        self.query_handler = QueryHandler(self.drive_manager)
        self.response_collector = ResponseCollector(self.drive_manager)
        
        # Get Rust integration manager
        self._rust_integration = get_rust_integration()
        
        # Track active queries with LRU cache (TTL: 2 hours, max: 1000 queries)
        self.active_queries = create_ttl_dict(
            max_size=1000,
            ttl=7200.0,  # 2 hours
            cleanup_interval=300.0  # 5 minutes
        )
        
        # Register cleanup with scheduler
        try:
            cleanup_scheduler = get_cleanup_scheduler()
            cleanup_scheduler.register_cleanable_object(self.active_queries)
            cleanup_scheduler.register_task(
                name=f"expert_manager_{id(self)}_query_cleanup",
                callback=self._cleanup_expired_queries,
                interval_seconds=300.0,  # 5 minutes
                priority=cleanup_scheduler.TaskPriority.MEDIUM
            )
        except Exception as e:
            logger.warning(f"Could not register with cleanup scheduler: {e}")
        
        logger.info("Expert Manager initialized")
    
    async def consult_experts(
        self,
        title: str,
        content: str,
        requester: str,
        query_type: QueryType = QueryType.GENERAL,
        priority: QueryPriority = QueryPriority.MEDIUM,
        context: Optional[Dict[str, Any]] = None,
        constraints: Optional[List[str]] = None,
        deadline_hours: Optional[float] = None,
        tags: Optional[List[str]] = None,
        wait_for_responses: bool = True,
        response_timeout: float = 300.0,
        min_responses: int = 1,
        required_experts: Optional[List[ExpertType]] = None
    ) -> Dict[str, Any]:
        """
        Submit a query to the circle of experts and optionally wait for responses.
        
        Args:
            title: Query title
            content: Query content
            requester: Who is making the request
            query_type: Type of query
            priority: Priority level
            context: Additional context
            constraints: Any constraints
            deadline_hours: Hours until deadline
            tags: Query tags
            wait_for_responses: Whether to wait for responses
            response_timeout: Maximum time to wait for responses
            min_responses: Minimum number of responses to wait for
            required_experts: Specific experts that must respond
            
        Returns:
            Dictionary containing:
            - query_id: Unique ID for the query
            - query: The submitted query
            - status: Current status
            - responses: List of responses (if wait_for_responses is True)
            - aggregation: Consensus analysis (if multiple responses)
        """
        with LogContext(operation="consult_experts", query_title=title):
            # Validate and normalize parameters
            validated_params = validate_query_parameters(
                title=title,
                content=content,
                requester=requester,
                query_type=query_type,
                priority=priority,
                context=context,
                constraints=constraints,
                deadline_hours=deadline_hours,
                tags=tags
            )
            
            # Create query with validated parameters
            query = ExpertQuery(
                id=str(uuid4()),
                title=validated_params["title"],
                content=validated_params["content"],
                requester=validated_params["requester"],
                query_type=validated_params["query_type"],
                priority=validated_params["priority"],
                context=validated_params["context"],
                constraints=validated_params["constraints"],
                deadline=validated_params["deadline"],
                tags=validated_params["tags"]
            )
            
            # Track active query
            self.active_queries[query.id] = query
            
            # Submit query
            file_id = await self.query_handler.submit_query(query)
            
            result = {
                "query_id": query.id,
                "query": query.dict(),
                "file_id": file_id,
                "status": "submitted"
            }
            
            if wait_for_responses:
                # Wait for responses
                responses = await self.response_collector.collect_responses(
                    query.id,
                    timeout=response_timeout,
                    min_responses=min_responses,
                    required_experts=required_experts
                )
                
                # Aggregate responses
                aggregation = await self.response_collector.aggregate_responses(query.id)
                
                # Perform advanced consensus analysis if multiple responses
                if len(responses) > 1:
                    start_time = time.time()
                    
                    # Prepare data for consensus analysis
                    response_data = [
                        {
                            "expert_type": r.expert_type.value,
                            "content": r.content,
                            "confidence": r.confidence,
                            "recommendations": r.recommendations
                        }
                        for r in responses
                    ]
                    
                    # Run consensus analysis (Rust-accelerated if available)
                    consensus_result, used_rust = self._rust_integration.analyze_consensus(
                        response_data,
                        {"threshold": 0.7, "min_agreement": 0.5}
                    )
                    
                    # Add analysis to aggregation
                    aggregation["advanced_consensus"] = consensus_result
                    aggregation["consensus_computation_time"] = time.time() - start_time
                    aggregation["consensus_accelerated"] = used_rust
                    
                    logger.info(
                        f"Consensus analysis completed in "
                        f"{aggregation['consensus_computation_time']:.3f}s "
                        f"(Rust: {used_rust})"
                    )
                
                # Create consensus report if we have multiple responses
                if len(responses) > 1:
                    consensus_file_id = await self.response_collector.save_consensus_report(
                        query, responses
                    )
                    aggregation["consensus_report_file_id"] = consensus_file_id
                
                result.update({
                    "status": "completed",
                    "responses": [r.dict() for r in responses],
                    "aggregation": aggregation
                })
            
            return result
    
    async def get_query_status(self, query_id: str) -> Dict[str, Any]:
        """
        Get the status of a submitted query.
        
        Args:
            query_id: The query ID to check
            
        Returns:
            Dictionary with query status and any available responses
        """
        # Validate parameters
        query_id = validate_string(query_id, "query_id", required=True)
        
        with LogContext(operation="get_query_status", query_id=query_id):
            if query_id not in self.active_queries:
                return {
                    "status": "not_found",
                    "error": f"Query {query_id} not found"
                }
            
            query = self.active_queries[query_id]
            
            # Check for responses
            responses = await self.response_collector.get_responses(query_id)
            
            status = {
                "query_id": query_id,
                "query": query.dict(),
                "status": "waiting" if not responses else "has_responses",
                "response_count": len(responses),
                "responses": [r.dict() for r in responses],
                "rust_acceleration": self._rust_integration.rust_available
            }
            
            # If we have responses, add consensus preview
            if responses and len(responses) > 1:
                # Quick consensus calculation
                confidences = [r.confidence for r in responses]
                avg_confidence = sum(confidences) / len(confidences)
                variance = sum((c - avg_confidence) ** 2 for c in confidences) / len(confidences)
                
                if variance < 0.05:
                    consensus_preview = "high"
                elif variance < 0.1:
                    consensus_preview = "medium"
                else:
                    consensus_preview = "low"
                
                status["consensus_preview"] = consensus_preview
            
            return status
    
    async def list_active_queries(self) -> List[Dict[str, Any]]:
        """
        List all active queries.
        
        Returns:
            List of active query summaries
        """
        queries = []
        for query_id, query in self.active_queries.items():
            queries.append({
                "query_id": query_id,
                "title": query.title,
                "requester": query.requester,
                "priority": query.priority.value,
                "created_at": query.created_at.isoformat()
            })
        
        return queries
    
    def _cleanup_expired_queries(self) -> int:
        """
        Clean up expired queries from active_queries cache.
        
        Returns:
            Number of expired queries removed
        """
        try:
            removed_count = self.active_queries.cleanup()
            if removed_count > 0:
                logger.info(f"Cleaned up {removed_count} expired queries")
            return removed_count
        except Exception as e:
            logger.error(f"Error during query cleanup: {e}")
            return 0
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics for monitoring."""
        try:
            stats = self.active_queries.get_stats()
            return {
                "active_queries_cache": stats.to_dict(),
                "cache_size": len(self.active_queries),
                "cache_type": "TTLDict with LRU eviction"
            }
        except Exception as e:
            logger.error(f"Error getting cache stats: {e}")
            return {}
    
    async def check_for_new_responses(self) -> Dict[str, List[ExpertResponse]]:
        """
        Check all active queries for new responses.
        
        Returns:
            Dictionary mapping query_id to list of new responses
        """
        new_responses = {}
        
        for query_id in self.active_queries:
            responses = await self.response_collector.get_responses(query_id)
            if responses:
                new_responses[query_id] = responses
        
        return new_responses
    
    async def submit_code_review(
        self,
        code: str,
        language: str,
        requester: str,
        focus_areas: Optional[List[str]] = None,
        wait_for_responses: bool = True
    ) -> Dict[str, Any]:
        """
        Submit a code review request.
        
        Args:
            code: The code to review
            language: Programming language
            requester: Who is requesting the review
            focus_areas: Specific areas to focus on
            wait_for_responses: Whether to wait for responses
            
        Returns:
            Query result with responses
        """
        # Validate parameters
        code = validate_string(code, "code", required=True, min_length=1)
        language = validate_string(language, "language", required=True)
        requester = validate_string(requester, "requester", required=True)
        focus_areas = validate_list(focus_areas, "focus_areas", item_type=str)
        
        title = f"Code Review Request: {language}"
        content = f"Please review the following {language} code:\n\n```{language}\n{code}\n```"
        
        if focus_areas:
            content += f"\n\nPlease focus on: {', '.join(focus_areas)}"
        
        return await self.consult_experts(
            title=title,
            content=content,
            query_type=QueryType.CODE_REVIEW,
            priority=QueryPriority.HIGH,
            requester=requester,
            wait_for_responses=wait_for_responses
        )
    
    # Backwards compatibility methods
    async def submit_query(
        self,
        query: ExpertQuery,
        wait_for_responses: bool = True,
        response_timeout: float = 300.0,
        min_responses: int = 1,
        required_experts: Optional[List[ExpertType]] = None
    ) -> Dict[str, Any]:
        """
        Submit a query (backwards compatibility method).
        
        This method provides backwards compatibility with the old API.
        It delegates to consult_experts internally.
        """
        logger.warning(
            "submit_query is deprecated. Use consult_experts instead."
        )
        
        return await self.consult_experts(
            title=query.title,
            content=query.content,
            requester=query.requester,
            query_type=query.query_type,
            priority=query.priority,
            context=query.context,
            constraints=query.constraints,
            deadline_hours=(query.deadline - query.created_at).total_seconds() / 3600 if query.deadline else None,
            tags=query.tags,
            wait_for_responses=wait_for_responses,
            response_timeout=response_timeout,
            min_responses=min_responses,
            required_experts=required_experts
        )
    
    async def get_expert_health(self) -> Dict[str, Any]:
        """
        Get health status of all experts (backwards compatibility method).
        
        Returns mock health data for backwards compatibility.
        """
        logger.warning(
            "get_expert_health is deprecated. Expert health monitoring has been redesigned."
        )
        
        # Return mock health data for backwards compatibility
        # Include all expert types for backwards compatibility
        experts_health = {}
        for expert_type in ExpertType:
            experts_health[expert_type.value] = {
                "status": "available",
                "response_time": 0.5 + (hash(expert_type.value) % 5) * 0.1
            }
        
        return {
            "status": "healthy",
            "experts": experts_health,
            "total_experts": len(ExpertType),
            "available_experts": len(ExpertType),
            "rust_acceleration": self._rust_integration.rust_available
        }