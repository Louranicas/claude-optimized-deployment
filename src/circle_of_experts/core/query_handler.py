"""
Query Handler for Circle of Experts.

Manages the creation, validation, and submission of queries.
"""

from __future__ import annotations
import asyncio
import gc
import sys
from typing import Optional, List, Dict, Any, AsyncIterator
from datetime import datetime, timedelta
import logging
from collections import OrderedDict
from weakref import WeakValueDictionary

from src.core.object_pool import DictPool, ListPool, pooled
from src.core.memory_monitor import with_memory_monitoring

from src.circle_of_experts.models.query import ExpertQuery, QueryPriority, QueryType
from src.circle_of_experts.drive.manager import DriveManager
from src.circle_of_experts.utils.logging import LogContext
from src.circle_of_experts.utils.validation import (
    validate_string, validate_dict, validate_list,
    validate_enum, validate_number, validate_deadline_hours,
    ValidationError
)

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

logger = logging.getLogger(__name__)


class QueryHandler:
    """
    Handles query operations for the Circle of Experts system.
    
    This class manages query creation, validation, submission to Google Drive,
    and tracking of active queries.
    """
    
    def __init__(self, drive_manager: DriveManager, query_ttl_hours: float = 24.0, max_cached_queries: int = 1000):
        """
        Initialize the QueryHandler.
        
        Args:
            drive_manager: DriveManager instance for Google Drive operations
            query_ttl_hours: Time-to-live for cached queries in hours
            max_cached_queries: Maximum number of queries to keep in memory
        """
        if drive_manager is None:
            raise ValidationError("drive_manager", None, "DriveManager cannot be None")
        self.drive_manager = drive_manager
        self.query_ttl_hours = query_ttl_hours
        self.max_cached_queries = max_cached_queries
        
        # Use OrderedDict for LRU-like behavior
        self._active_queries: OrderedDict[str, Dict[str, Any]] = OrderedDict()
        self._query_files: Dict[str, str] = {}  # query_id -> file_id mapping
        self._query_timestamps: Dict[str, datetime] = {}  # query_id -> creation timestamp
        self._memory_usage_tracker = {}
        
        logger.info(f"QueryHandler initialized with {query_ttl_hours}h TTL and {max_cached_queries} max cached queries")
    
    @with_memory_monitoring
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
        # Validate parameters using pooled objects for temporary processing
        with pooled(DictPool) as temp_context:
            title = validate_string(title, "title", required=True, min_length=1, max_length=200)
            content = validate_string(content, "content", required=True, min_length=10, max_length=10000)
            requester = validate_string(requester, "requester", required=True, min_length=1)
            query_type = validate_enum(query_type, "query_type", QueryType, required=False) or QueryType.GENERAL
            priority = validate_enum(priority, "priority", QueryPriority, required=False) or QueryPriority.MEDIUM
            context = validate_dict(context, "context")
            constraints = validate_list(constraints, "constraints", item_type=str)
            tags = validate_list(tags, "tags", item_type=str, unique=True)
            deadline = validate_deadline_hours(deadline_hours)
        
        query = ExpertQuery(
            title=title,
            content=content,
            requester=requester,
            query_type=query_type,
            priority=priority,
            context=context,
            constraints=constraints,
            deadline=deadline,
            tags=tags
        )
        
        # Validate the query
        self._validate_query(query)
        
        # Store in active queries with memory tracking
        self._store_query_with_limits(query)
        
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
        # Validate parameter
        if query is None:
            raise ValidationError("query", None, "Query cannot be None")
        if not isinstance(query, ExpertQuery):
            raise ValidationError("query", query, f"Expected ExpertQuery, got {type(query).__name__}")
        
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
    
    @with_memory_monitoring
    async def submit_batch(self, queries: List[ExpertQuery]) -> Dict[str, str]:
        """
        Submit multiple queries in parallel.
        
        Args:
            queries: List of queries to submit
            
        Returns:
            Dictionary mapping query IDs to file IDs
        """
        # Validate parameters
        queries = validate_list(queries, "queries", min_items=1)
        for i, query in enumerate(queries):
            if not isinstance(query, ExpertQuery):
                raise ValidationError(f"queries[{i}]", query, f"Expected ExpertQuery, got {type(query).__name__}")
        
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
    
    def _store_query_with_limits(self, query: ExpertQuery) -> None:
        """Store query with memory and TTL limits."""
        # Clean up expired queries first
        self._cleanup_expired_queries()
        
        # Enforce cache size limit
        while len(self._active_queries) >= self.max_cached_queries:
            # Remove oldest query (LRU eviction)
            oldest_id = next(iter(self._active_queries))
            self._remove_query(oldest_id)
            logger.debug(f"Evicted query {oldest_id} due to cache size limit")
        
        # Store query data instead of full object to reduce memory
        query_data = {
            "id": query.id,
            "title": query.title,
            "query_type": query.query_type,
            "priority": query.priority,
            "created_at": query.created_at,
            "deadline": query.deadline,
            "requester": query.requester,
            # Store minimal content to reduce memory usage
            "content_size": len(query.content),
            "has_context": query.context is not None,
            "tags_count": len(query.tags) if query.tags else 0
        }
        
        self._active_queries[query.id] = query_data
        self._query_timestamps[query.id] = datetime.utcnow()
        
        # Track memory usage if available
        if PSUTIL_AVAILABLE:
            memory_mb = self._get_current_memory_mb()
            self._memory_usage_tracker[query.id] = memory_mb
    
    def _remove_query(self, query_id: str) -> None:
        """Remove query from all tracking structures."""
        self._active_queries.pop(query_id, None)
        self._query_files.pop(query_id, None)
        self._query_timestamps.pop(query_id, None)
        self._memory_usage_tracker.pop(query_id, None)
    
    def _cleanup_expired_queries(self) -> None:
        """Remove expired queries based on TTL."""
        current_time = datetime.utcnow()
        ttl_delta = timedelta(hours=self.query_ttl_hours)
        
        expired_ids = [
            query_id for query_id, timestamp in self._query_timestamps.items()
            if current_time - timestamp > ttl_delta
        ]
        
        for query_id in expired_ids:
            self._remove_query(query_id)
            logger.debug(f"Expired query {query_id} after {self.query_ttl_hours} hours")
        
        if expired_ids:
            logger.info(f"Cleaned up {len(expired_ids)} expired queries")
            # Force garbage collection after cleanup
            gc.collect()
    
    def _get_current_memory_mb(self) -> float:
        """Get current memory usage in MB."""
        if not PSUTIL_AVAILABLE:
            return 0.0
        try:
            process = psutil.Process()
            return process.memory_info().rss / 1024 / 1024
        except Exception:
            return 0.0
    
    async def get_active_queries(self, page: int = 1, page_size: int = 50) -> Dict[str, Any]:
        """
        Get active queries with pagination.
        
        Args:
            page: Page number (1-based)
            page_size: Number of queries per page
            
        Returns:
            Dictionary with paginated query data and metadata
        """
        # Clean up expired queries first
        self._cleanup_expired_queries()
        
        # Calculate pagination
        total_queries = len(self._active_queries)
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        
        # Get paginated query IDs
        query_ids = list(self._active_queries.keys())[start_idx:end_idx]
        paginated_queries = [self._active_queries[qid] for qid in query_ids]
        
        return {
            "queries": paginated_queries,
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total_queries": total_queries,
                "total_pages": (total_queries + page_size - 1) // page_size,
                "has_next": end_idx < total_queries,
                "has_previous": page > 1
            },
            "memory_info": {
                "cached_queries": len(self._active_queries),
                "memory_mb": self._get_current_memory_mb(),
                "ttl_hours": self.query_ttl_hours
            }
        }
    
    async def get_query(self, query_id: str) -> Optional[ExpertQuery]:
        """
        Get a specific query by ID.
        
        Args:
            query_id: ID of the query to retrieve
            
        Returns:
            Query if found, None otherwise
        """
        # Validate parameter
        query_id = validate_string(query_id, "query_id", required=True)
        
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
        # Validate parameters
        code = validate_string(code, "code", required=True, min_length=1)
        language = validate_string(language, "language", required=True)
        requester = validate_string(requester, "requester", required=True)
        focus_areas = validate_list(focus_areas, "focus_areas", item_type=str)
        context = validate_dict(context, "context")
        
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
        # Validate parameters
        system_description = validate_string(system_description, "system_description", required=True, min_length=10)
        requirements = validate_list(requirements, "requirements", item_type=str, min_items=1)
        requester = validate_string(requester, "requester", required=True)
        constraints = validate_list(constraints, "constraints", item_type=str)
        existing_stack = validate_dict(existing_stack, "existing_stack")
        
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
    
    async def stream_queries(self, query_type: Optional[QueryType] = None) -> AsyncIterator[Dict[str, Any]]:
        """
        Stream active queries to avoid loading all into memory at once.
        
        Args:
            query_type: Optional filter by query type
            
        Yields:
            Query data dictionaries
        """
        # Clean up expired queries first
        self._cleanup_expired_queries()
        
        for query_id, query_data in self._active_queries.items():
            if query_type is None or query_data.get("query_type") == query_type:
                yield query_data
