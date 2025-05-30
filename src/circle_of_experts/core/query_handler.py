"""
Query Handler for Circle of Experts.

Manages the creation, validation, and submission of queries.
"""

from __future__ import annotations
import asyncio
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import logging

from ..models.query import ExpertQuery, QueryPriority, QueryType
from ..drive.manager import DriveManager
from ..utils.logging import LogContext

logger = logging.getLogger(__name__)


class QueryHandler:
    """
    Handles query operations for the Circle of Experts system.
    
    This class manages query creation, validation, submission to Google Drive,
    and tracking of active queries.
    """
    
    def __init__(self, drive_manager: DriveManager):
        """
        Initialize the QueryHandler.
        
        Args:
            drive_manager: DriveManager instance for Google Drive operations
        """
        self.drive_manager = drive_manager
        self._active_queries: Dict[str, ExpertQuery] = {}
        self._query_files: Dict[str, str] = {}  # query_id -> file_id mapping
    
    async def create_query(
        self,
        title: str,
        content: str,
        requester: str,
        query_type: QueryType = QueryType.GENERAL,
        priority: QueryPriority = QueryPriority.MEDIUM,
        context: Optional[Dict[str, Any]] = None,
        constraints: Optional[List[str]] = None,
        deadline_hours: Optional[float] = None,
        tags: Optional[List[str]] = None
    ) -> ExpertQuery:
        """
        Create a new expert query.
        
        Args:
            title: Brief title of the query
            content: Detailed query content
            requester: Identity of the requester
            query_type: Type of query
            priority: Priority level
            context: Additional context
            constraints: Any constraints or requirements
            deadline_hours: Hours until deadline (from now)
            tags: Tags for categorization
            
        Returns:
            Created ExpertQuery instance
        """
        deadline = None
        if deadline_hours:
            deadline = datetime.utcnow() + timedelta(hours=deadline_hours)
        
        query = ExpertQuery(
            title=title,
            content=content,
            requester=requester,
            query_type=query_type,
            priority=priority,
            context=context or {},
            constraints=constraints or [],
            deadline=deadline,
            tags=tags or []
        )
        
        # Validate the query
        self._validate_query(query)
        
        # Store in active queries
        self._active_queries[query.id] = query
        
        logger.info(f"Created query {query.id}: {query.title}")
        return query
    
    def _validate_query(self, query: ExpertQuery) -> None:
        """
        Validate a query before submission.
        
        Args:
            query: Query to validate
            
        Raises:
            ValueError: If query is invalid
        """
        # Check content length
        if len(query.content) < 10:
            raise ValueError("Query content is too short (minimum 10 characters)")
        
        if len(query.content) > 10000:
            raise ValueError("Query content is too long (maximum 10000 characters)")
        
        # Check deadline
        if query.deadline and query.deadline <= datetime.utcnow():
            raise ValueError("Query deadline must be in the future")
        
        # Additional validation rules can be added here
        logger.debug(f"Query {query.id} passed validation")
    
    async def submit_query(self, query: ExpertQuery) -> str:
        """
        Submit a query to Google Drive.
        
        Args:
            query: Query to submit
            
        Returns:
            File ID of the uploaded query
        """
        with LogContext(query_id=query.id, action="submit"):
            try:
                # Upload to Drive
                file_id = await self.drive_manager.upload_query(query)
                
                # Track the file ID
                self._query_files[query.id] = file_id
                
                logger.info(f"Successfully submitted query {query.id} as file {file_id}")
                return file_id
                
            except Exception as e:
                logger.error(f"Failed to submit query {query.id}: {e}")
                raise
    
    async def submit_batch(self, queries: List[ExpertQuery]) -> Dict[str, str]:
        """
        Submit multiple queries in parallel.
        
        Args:
            queries: List of queries to submit
            
        Returns:
            Dictionary mapping query IDs to file IDs
        """
        logger.info(f"Submitting batch of {len(queries)} queries")
        
        # Create submission tasks
        tasks = [self.submit_query(query) for query in queries]
        
        # Execute in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        file_mappings = {}
        for query, result in zip(queries, results):
            if isinstance(result, Exception):
                logger.error(f"Failed to submit query {query.id}: {result}")
            else:
                file_mappings[query.id] = result
        
        logger.info(f"Successfully submitted {len(file_mappings)}/{len(queries)} queries")
        return file_mappings
    
    async def get_active_queries(self) -> List[ExpertQuery]:
        """
        Get all active queries.
        
        Returns:
            List of active queries
        """
        return list(self._active_queries.values())
    
    async def get_query(self, query_id: str) -> Optional[ExpertQuery]:
        """
        Get a specific query by ID.
        
        Args:
            query_id: ID of the query to retrieve
            
        Returns:
            Query if found, None otherwise
        """
        return self._active_queries.get(query_id)
    
    async def list_submitted_queries(self) -> List[Dict[str, Any]]:
        """
        List all queries that have been submitted to Drive.
        
        Returns:
            List of query file metadata
        """
        return await self.drive_manager.list_queries()
    
    async def create_code_review_query(
        self,
        code: str,
        language: str,
        requester: str,
        focus_areas: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> ExpertQuery:
        """
        Create a specialized code review query.
        
        Args:
            code: Code to review
            language: Programming language
            requester: Who is requesting the review
            focus_areas: Specific areas to focus on
            context: Additional context
            
        Returns:
            Created query for code review
        """
        title = f"Code Review: {language}"
        
        content_parts = [
            f"Please review the following {language} code:",
            "",
            "```" + language,
            code,
            "```",
            ""
        ]
        
        if focus_areas:
            content_parts.extend([
                "Focus areas:",
                ""
            ])
            for area in focus_areas:
                content_parts.append(f"- {area}")
            content_parts.append("")
        
        content = "\n".join(content_parts)
        
        return await self.create_query(
            title=title,
            content=content,
            requester=requester,
            query_type=QueryType.REVIEW,
            priority=QueryPriority.MEDIUM,
            context=context,
            tags=["code-review", language.lower()]
        )
    
    async def create_architecture_query(
        self,
        system_description: str,
        requirements: List[str],
        requester: str,
        constraints: Optional[List[str]] = None,
        existing_stack: Optional[Dict[str, str]] = None
    ) -> ExpertQuery:
        """
        Create an architecture design query.
        
        Args:
            system_description: Description of the system
            requirements: List of requirements
            requester: Who is requesting
            constraints: Technical constraints
            existing_stack: Current technology stack
            
        Returns:
            Created architecture query
        """
        title = "Architecture Design Review"
        
        content_parts = [
            "## System Description",
            "",
            system_description,
            "",
            "## Requirements",
            ""
        ]
        
        for req in requirements:
            content_parts.append(f"- {req}")
        
        content_parts.append("")
        
        if existing_stack:
            content_parts.extend([
                "## Existing Technology Stack",
                "",
                "```json",
                str(existing_stack),
                "```",
                ""
            ])
        
        content = "\n".join(content_parts)
        
        context = {
            "requirements_count": len(requirements),
            "has_existing_stack": existing_stack is not None
        }
        
        return await self.create_query(
            title=title,
            content=content,
            requester=requester,
            query_type=QueryType.ARCHITECTURAL,
            priority=QueryPriority.HIGH,
            context=context,
            constraints=constraints,
            tags=["architecture", "design", "system-design"]
        )
