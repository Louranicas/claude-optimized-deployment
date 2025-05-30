"""
Expert implementations for the Circle of Experts system.

This package provides various AI expert clients including:
- Commercial APIs (Claude, GPT-4, Gemini, Groq)
- Open source alternatives (Ollama, LocalAI, HuggingFace)
- Expert factory and orchestration
"""

from .claude_expert import ClaudeExpertClient, BaseExpertClient
from .commercial_experts import (
    GPT4ExpertClient,
    GeminiExpertClient,
    GroqExpertClient,
    DeepSeekExpertClient
)
from .open_source_experts import (
    OllamaExpertClient,
    LocalAIExpertClient,
    HuggingFaceExpertClient
)
from .expert_factory import (
    ExpertFactory,
    ExpertHealthCheck,
    ExpertOrchestrator,
    ExpertPriority,
    ExpertConfig,
    EXPERT_REGISTRY,
    get_expert,
    create_expert
)

__all__ = [
    # Base class
    "BaseExpertClient",
    
    # Commercial experts
    "ClaudeExpertClient",
    "GPT4ExpertClient",
    "GeminiExpertClient",
    "GroqExpertClient",
    "DeepSeekExpertClient",
    
    # Open source experts
    "OllamaExpertClient",
    "LocalAIExpertClient",
    "HuggingFaceExpertClient",
    
    # Factory and management
    "ExpertFactory",
    "ExpertHealthCheck",
    "ExpertOrchestrator",
    "ExpertPriority",
    "ExpertConfig",
    "EXPERT_REGISTRY",
    "get_expert",
    "create_expert"
]
