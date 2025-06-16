"""
Academic MCP Integration for Hyper Narrative Synthor
High-performance academic search and citation management
"""

from .bridge import AcademicMCPBridge
from .synthor_integration import SynthorAcademicIntegration
from .assistant import AcademicAssistant

__version__ = "1.0.0"
__all__ = ["AcademicMCPBridge", "SynthorAcademicIntegration", "AcademicAssistant"]
