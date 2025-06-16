"""
MCP Learning System - Python Learning Layer

High-performance machine learning algorithms and orchestration
for adaptive MCP server behavior.
"""

__version__ = "0.1.0"

from .algorithms import (
    OnlineLearner,
    PatternRecognizer,
    AdaptationEngine,
)

from .orchestrator import (
    LearningOrchestrator,
    WorkflowManager,
)

from .shared_memory import (
    SharedMemoryInterface,
    MessageQueue,
    StateCache,
)

__all__ = [
    # Algorithms
    "OnlineLearner",
    "PatternRecognizer", 
    "AdaptationEngine",
    
    # Orchestration
    "LearningOrchestrator",
    "WorkflowManager",
    
    # Shared Memory
    "SharedMemoryInterface",
    "MessageQueue",
    "StateCache",
]