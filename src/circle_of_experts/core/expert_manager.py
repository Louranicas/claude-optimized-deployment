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

from ..models.query import ExpertQuery, QueryPriority, QueryType
from ..models.response import ExpertResponse, ExpertType
from ..drive.manager import DriveManager
from .query_handler import QueryHandler
from .response_collector import ResponseCollector
from ..utils.logging import setup_logging, LogContext
from ..utils.rust_integration import get_rust_integration

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
        
        # Track active queries
        self.active_queries: Dict[str, ExpertQuery] = {}
        
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
            # Create query
            query = ExpertQuery(
                id=str(uuid4()),
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