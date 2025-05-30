"""
Circle of Experts Feature - Multi-AI Collaboration System

This module enables queries to be submitted to multiple AI experts (Claude, GPT-4, Gemini)
through a Google Drive folder system for collaborative problem-solving.
"""

from .core.enhanced_expert_manager import EnhancedExpertManager as ExpertManager  # Using enhanced version due to file corruption
from .core.query_handler import QueryHandler
from .core.response_collector import ResponseCollector
from .models.query import ExpertQuery, QueryType, QueryPriority
from .models.response import ExpertResponse, ExpertType, ConsensusResponse, ResponseStatus

__version__ = "0.1.0"
__all__ = [
    "ExpertManager",
    "QueryHandler", 
    "ResponseCollector",
    "ExpertQuery",
    "ExpertResponse",
    "ConsensusResponse",
    "QueryType",
    "QueryPriority",
    "ExpertType",
    "ResponseStatus"
]
