"""
Utility modules for Claude Optimized Deployment Engine.

This package consolidates various utility scripts into modular, reusable components
following enterprise development standards.
"""

from .imports import ImportManager
from .git import GitManager
from .security import SecurityValidator
from .monitoring import MemoryAnalyzer

# Import database with fallback
try:
    from .database import DatabaseManager
    __all__ = [
        "ImportManager",
        "GitManager", 
        "SecurityValidator",
        "MemoryAnalyzer",
        "DatabaseManager"
    ]
except ImportError:
    __all__ = [
        "ImportManager",
        "GitManager", 
        "SecurityValidator",
        "MemoryAnalyzer"
    ]

# Version of the utils package
__version__ = "1.0.0"