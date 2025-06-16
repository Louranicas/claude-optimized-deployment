"""
MCP Learning System - Adaptive Learning with Cross-Instance Intelligence

This system provides sophisticated adaptive learning algorithms that enable
cross-instance intelligence sharing and continuous improvement across all MCP servers.
"""

from .learning_core import (
    AdaptiveLearningSystem,
    CrossInstanceLearning,
    LearningCore,
    PatternRecognizer,
    PredictionEngine,
)

__version__ = "1.0.0"
__all__ = [
    "AdaptiveLearningSystem",
    "CrossInstanceLearning",
    "LearningCore",
    "PatternRecognizer",
    "PredictionEngine",
]