"""Model package initialization."""

from .query import ExpertQuery, QueryPriority, QueryType
from .response import ExpertResponse, ExpertType, ResponseStatus, ConsensusResponse

# Alias for backward compatibility
Response = ExpertResponse

__all__ = [
    "ExpertQuery",
    "QueryPriority", 
    "QueryType",
    "ExpertResponse",
    "Response",  # Alias for ExpertResponse
    "ConsensusResponse",
    "ExpertType",
    "ResponseStatus"
]
