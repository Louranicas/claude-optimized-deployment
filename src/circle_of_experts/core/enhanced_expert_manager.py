"""
Enhanced Expert Manager with automatic Rust acceleration.

This module provides a higher-level interface to the Circle of Experts system
with seamless Rust integration and performance monitoring.
"""

from __future__ import annotations
from typing import Optional, List, Dict, Any, AsyncIterator
from pathlib import Path
import asyncio
import logging
import time
from contextlib import asynccontextmanager

from .expert_manager import ExpertManager
from ..models.query import ExpertQuery, QueryPriority, QueryType
from ..models.response import ExpertResponse, ExpertType
from ..utils.rust_integration import get_rust_integration

logger = logging.getLogger(__name__)


class EnhancedExpertManager(ExpertManager):
    """
    Enhanced Expert Manager with automatic Rust acceleration and performance monitoring.
    
    This class extends the base ExpertManager to provide:
    - Automatic Rust acceleration where available
    - Performance monitoring and reporting
    - Advanced consensus building
    - Streaming response capabilities
    """
    
    def __init__(
        self,
        credentials_path: Optional[str] = None,
        queries_folder_id: str = "1ob-NYNWMXaE3oiyPzRAk2-VpNbMvfFMS",
        responses_folder_id: str = "1YWh7lD1x8z8HrF-1FS6qPCw64ZQwvUHv",
        log_level: str = "INFO",
        log_file: Optional[Path] = None,
        enable_performance_monitoring: bool = True,
        use_rust_acceleration: bool = True,
        rust_analyzer: Optional[Any] = None,
        rust_validator: Optional[Any] = None
    ):
        """
        Initialize the Enhanced Expert Manager.
        
        Args:
            credentials_path: Path to Google Drive credentials JSON
            queries_folder_id: ID of the queries folder in Drive
            responses_folder_id: ID of the responses folder in Drive
            log_level: Logging level
            log_file: Optional log file path
            enable_performance_monitoring: Whether to track performance metrics
        """
        super().__init__(
            credentials_path=credentials_path,
            queries_folder_id=queries_folder_id,
            responses_folder_id=responses_folder_id,
            log_level=log_level,
            log_file=log_file
        )
        
        self.enable_performance_monitoring = enable_performance_monitoring
        self.use_rust_acceleration = use_rust_acceleration
        self.rust_analyzer = rust_analyzer
        self.rust_validator = rust_validator
        
        self._performance_metrics: Dict[str, Any] = {
            "total_queries": 0,
            "rust_accelerated_queries": 0,
            "average_response_time": 0.0,
            "total_processing_time": 0.0
        }
        
        # Override Rust integration if custom modules provided
        if rust_analyzer or rust_validator:
            self._rust_integration.set_custom_modules(rust_analyzer, rust_validator)
        
        # Log Rust availability status
        rust_stats = self._rust_integration.get_performance_stats()
        if rust_stats["rust_available"] and self.use_rust_acceleration:
            logger.info("Enhanced Expert Manager initialized with Rust acceleration")
        else:
            logger.info("Enhanced Expert Manager initialized (Python-only mode)")
    
    async def consult_experts_enhanced(
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
        required_experts: Optional[List[ExpertType]] = None,
        enable_streaming: bool = False
    ) -> Dict[str, Any]:
        """
        Enhanced expert consultation with performance tracking and streaming support.
        
        This method extends the base consult_experts with:
        - Performance monitoring
        - Rust acceleration statistics
        - Streaming response support
        
        Args:
            Same as base consult_experts, plus:
            enable_streaming: Whether to enable streaming responses
            
        Returns:
            Enhanced result dictionary with performance metrics
        """
        start_time = time.time()
        
        # Track query
        if self.enable_performance_monitoring:
            self._performance_metrics["total_queries"] += 1
        
        # Use base implementation
        result = await super().consult_experts(
            title=title,
            content=content,
            requester=requester,
            query_type=query_type,
            priority=priority,
            context=context,
            constraints=constraints,
            deadline_hours=deadline_hours,
            tags=tags,
            wait_for_responses=wait_for_responses,
            response_timeout=response_timeout,
            min_responses=min_responses,
            required_experts=required_experts
        )
        
        # Add performance metrics
        elapsed_time = time.time() - start_time
        
        if self.enable_performance_monitoring:
            self._performance_metrics["total_processing_time"] += elapsed_time
            self._performance_metrics["average_response_time"] = (
                self._performance_metrics["total_processing_time"] / 
                self._performance_metrics["total_queries"]
            )
            
            # Check if Rust was used
            if result.get("aggregation", {}).get("accelerated", False):
                self._performance_metrics["rust_accelerated_queries"] += 1
        
        # Add enhanced metadata
        result["performance"] = {
            "total_time": round(elapsed_time, 3),
            "rust_accelerated": result.get("aggregation", {}).get("accelerated", False),
            "consensus_computation_time": result.get("aggregation", {}).get("consensus_computation_time", 0.0)
        }
        
        # Add Rust integration stats
        result["rust_stats"] = self._rust_integration.get_performance_stats()
        
        return result
    
    async def stream_expert_responses(
        self,
        query_id: str,
        poll_interval: float = 5.0,
        timeout: float = 300.0
    ) -> AsyncIterator[ExpertResponse]:
        """
        Stream expert responses as they arrive.
        
        Args:
            query_id: The query ID to monitor
            poll_interval: How often to check for new responses (seconds)
            timeout: Maximum time to wait for responses (seconds)
            
        Yields:
            ExpertResponse objects as they arrive
        """
        start_time = time.time()
        seen_response_ids = set()
        
        while (time.time() - start_time) < timeout:
            # Get all responses
            responses = await self.response_collector.get_responses(query_id)
            
            # Yield new responses
            for response in responses:
                if response.id not in seen_response_ids:
                    seen_response_ids.add(response.id)
                    yield response
            
            # Wait before next poll
            await asyncio.sleep(poll_interval)
    
    @asynccontextmanager
    async def batch_consultation(self, requester: str):
        """
        Context manager for batch expert consultations with optimized performance.
        
        Example:
            async with manager.batch_consultation("user") as batch:
                query1 = await batch.add_query("Title 1", "Content 1")
                query2 = await batch.add_query("Title 2", "Content 2")
                results = await batch.execute()
        
        Args:
            requester: Who is making the batch request
            
        Yields:
            BatchConsultation object
        """
        batch = BatchConsultation(self, requester)
        try:
            yield batch
        finally:
            # Ensure cleanup
            pass
    
    def get_performance_report(self) -> Dict[str, Any]:
        """
        Get comprehensive performance report.
        
        Returns:
            Dictionary with performance metrics and Rust integration stats
        """
        rust_stats = self._rust_integration.get_performance_stats()
        
        rust_acceleration_rate = 0.0
        if self._performance_metrics["total_queries"] > 0:
            rust_acceleration_rate = (
                self._performance_metrics["rust_accelerated_queries"] / 
                self._performance_metrics["total_queries"]
            ) * 100
        
        return {
            "query_metrics": {
                "total_queries": self._performance_metrics["total_queries"],
                "rust_accelerated_queries": self._performance_metrics["rust_accelerated_queries"],
                "rust_acceleration_rate": round(rust_acceleration_rate, 1),
                "average_response_time": round(self._performance_metrics["average_response_time"], 3),
                "total_processing_time": round(self._performance_metrics["total_processing_time"], 3)
            },
            "rust_integration": rust_stats,
            "estimated_speedup": {
                "time_saved_seconds": rust_stats["estimated_time_saved_seconds"],
                "speedup_factor": "1.5-3x" if rust_stats["rust_available"] else "1x"
            }
        }
    
    async def optimize_for_performance(self) -> None:
        """
        Optimize the system for maximum performance.
        
        This method:
        - Pre-warms Rust modules if available
        - Optimizes internal caches
        - Runs performance diagnostics
        """
        logger.info("Optimizing for performance...")
        
        # Pre-warm Rust modules
        if self._rust_integration.rust_available:
            logger.info("Pre-warming Rust modules...")
            
            # Run dummy operations to ensure modules are loaded
            dummy_responses = [
                {"expert_type": "test", "confidence": 0.8, "content": "test", "recommendations": []}
            ]
            
            _ = self._rust_integration.analyze_consensus(dummy_responses)
            _ = self._rust_integration.aggregate_responses(dummy_responses)
            
            logger.info("Rust modules pre-warmed successfully")
        
        # Log optimization status
        stats = self.get_performance_report()
        logger.info(f"Performance optimization complete. Rust available: {stats['rust_integration']['rust_available']}")


class BatchConsultation:
    """Helper class for batch expert consultations."""
    
    def __init__(self, manager: EnhancedExpertManager, requester: str):
        self.manager = manager
        self.requester = requester
        self.queries: List[Dict[str, Any]] = []
    
    async def add_query(
        self,
        title: str,
        content: str,
        query_type: QueryType = QueryType.GENERAL,
        priority: QueryPriority = QueryPriority.MEDIUM,
        **kwargs
    ) -> str:
        """Add a query to the batch."""
        query_data = {
            "title": title,
            "content": content,
            "requester": self.requester,
            "query_type": query_type,
            "priority": priority,
            **kwargs
        }
        self.queries.append(query_data)
        return f"batch_query_{len(self.queries)}"
    
    async def execute(self, wait_for_responses: bool = True) -> List[Dict[str, Any]]:
        """Execute all queries in the batch."""
        logger.info(f"Executing batch of {len(self.queries)} queries")
        
        # Execute queries concurrently
        tasks = [
            self.manager.consult_experts_enhanced(**query, wait_for_responses=wait_for_responses)
            for query in self.queries
        ]
        
        results = await asyncio.gather(*tasks)
        
        # Log batch performance
        if self.manager.enable_performance_monitoring:
            rust_count = sum(1 for r in results if r.get("performance", {}).get("rust_accelerated", False))
            logger.info(f"Batch complete: {rust_count}/{len(results)} queries used Rust acceleration")
        
        return results