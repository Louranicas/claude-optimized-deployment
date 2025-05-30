"""
Expert factory for creating and managing Circle of Experts clients.

Handles registration, creation, and orchestration of AI expert clients.
"""

from __future__ import annotations
import os
import asyncio
from typing import Optional, Dict, Any, List, Type
from enum import Enum
from dataclasses import dataclass
import logging

from ..models.response import ExpertResponse, ExpertType
from ..models.query import ExpertQuery
from .claude_expert import BaseExpertClient, ClaudeExpertClient
from .commercial_experts import (
    GPT4ExpertClient,
    GeminiExpertClient,
    GroqExpertClient,
    DeepSeekExpertClient
)
from .openrouter_expert import OpenRouterExpertClient
from .open_source_experts import (
    OllamaExpertClient,
    LocalAIExpertClient,
    HuggingFaceExpertClient
)

logger = logging.getLogger(__name__)


class ExpertPriority(Enum):
    """Priority levels for experts."""
    PRIMARY = "primary"      # High-quality, preferred experts
    SECONDARY = "secondary"  # Good alternatives
    FALLBACK = "fallback"    # Local/free alternatives
    EXPERIMENTAL = "experimental"  # Testing/development


@dataclass
class ExpertConfig:
    """Configuration for an expert."""
    expert_class: Type[BaseExpertClient]
    priority: ExpertPriority
    requires_api_key: bool
    env_var_name: Optional[str]
    cost_per_1k_tokens: float
    supported_query_types: List[str]


# Expert registry - maps expert names to their configurations
EXPERT_REGISTRY: Dict[str, ExpertConfig] = {
    "claude": ExpertConfig(
        expert_class=ClaudeExpertClient,
        priority=ExpertPriority.PRIMARY,
        requires_api_key=True,
        env_var_name="ANTHROPIC_API_KEY",
        cost_per_1k_tokens=0.015,  # Claude-3 Sonnet pricing
        supported_query_types=["all"]
    ),
    "gpt4": ExpertConfig(
        expert_class=GPT4ExpertClient,
        priority=ExpertPriority.PRIMARY,
        requires_api_key=True,
        env_var_name="OPENAI_API_KEY",
        cost_per_1k_tokens=0.030,  # GPT-4 pricing
        supported_query_types=["all"]
    ),
    "deepseek": ExpertConfig(
        expert_class=DeepSeekExpertClient,
        priority=ExpertPriority.PRIMARY,
        requires_api_key=True,
        env_var_name="DEEPSEEK_API_KEY",
        cost_per_1k_tokens=0.002,  # DeepSeek competitive pricing
        supported_query_types=["all"]
    ),
    "gemini": ExpertConfig(
        expert_class=GeminiExpertClient,
        priority=ExpertPriority.SECONDARY,
        requires_api_key=True,
        env_var_name="GOOGLE_GEMINI_API_KEY",
        cost_per_1k_tokens=0.001,  # Gemini Pro pricing
        supported_query_types=["all"]
    ),
    "groq": ExpertConfig(
        expert_class=GroqExpertClient,
        priority=ExpertPriority.SECONDARY,
        requires_api_key=True,
        env_var_name="GROQ_API_KEY",
        cost_per_1k_tokens=0.0001,  # Groq fast inference
        supported_query_types=["general", "analysis"]
    ),
    "ollama": ExpertConfig(
        expert_class=OllamaExpertClient,
        priority=ExpertPriority.FALLBACK,
        requires_api_key=False,
        env_var_name=None,
        cost_per_1k_tokens=0.0,  # Free local inference
        supported_query_types=["general", "analysis"]
    ),
    "localai": ExpertConfig(
        expert_class=LocalAIExpertClient,
        priority=ExpertPriority.FALLBACK,
        requires_api_key=False,
        env_var_name=None,
        cost_per_1k_tokens=0.0,  # Free local inference
        supported_query_types=["general", "analysis"]
    ),
    "huggingface": ExpertConfig(
        expert_class=HuggingFaceExpertClient,
        priority=ExpertPriority.EXPERIMENTAL,
        requires_api_key=True,
        env_var_name="HUGGINGFACE_API_KEY",
        cost_per_1k_tokens=0.0,  # Free tier available
        supported_query_types=["experimental"]
    ),
    "openrouter": ExpertConfig(
        expert_class=OpenRouterExpertClient,
        priority=ExpertPriority.PRIMARY,
        requires_api_key=True,
        env_var_name="OPENROUTER_API_KEY",
        cost_per_1k_tokens=0.005,  # Average OpenRouter pricing
        supported_query_types=["all"]
    )
}


class ExpertFactory:
    """
    Factory for creating and managing expert clients.
    
    Handles client creation, caching, health checks, and selection.
    """
    
    def __init__(self):
        """Initialize the expert factory."""
        self._client_cache: Dict[str, BaseExpertClient] = {}
    
    async def create_expert(self, expert_name: str) -> Optional[BaseExpertClient]:
        """
        Create an expert client by name.
        
        Args:
            expert_name: Name of the expert to create
            
        Returns:
            Expert client instance or None if creation fails
        """
        # Check cache first
        if expert_name in self._client_cache:
            return self._client_cache[expert_name]
        
        # Get configuration
        config = EXPERT_REGISTRY.get(expert_name)
        if not config:
            logger.error(f"Unknown expert: {expert_name}")
            return None
        
        # Get API key if required
        if config.requires_api_key:
            api_key = os.getenv(config.env_var_name)
            if not api_key:
                logger.warning(f"No API key found for {expert_name} ({config.env_var_name})")
                return None
        else:
            api_key = None
        
        try:
            # Create client
            client = config.expert_class(api_key=api_key)
            
            # Perform health check
            if await client.health_check():
                self._client_cache[expert_name] = client
                logger.info(f"Successfully created {expert_name} client")
                return client
            else:
                logger.warning(f"Health check failed for {expert_name}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to create {expert_name} client: {e}")
            return None
    
    async def select_experts_for_query(
        self,
        query: ExpertQuery,
        max_experts: int = 3
    ) -> List[BaseExpertClient]:
        """
        Select appropriate experts for a query.
        
        Args:
            query: The query to process
            max_experts: Maximum number of experts to select
            
        Returns:
            List of expert clients
        """
        selected_experts = []
        
        # Sort experts by priority and preference
        sorted_experts = self._sort_experts_for_query(query)
        
        for expert_name in sorted_experts:
            if len(selected_experts) >= max_experts:
                break
                
            client = await self.create_expert(expert_name)
            if client:
                selected_experts.append(client)
        
        return selected_experts
    
    def _sort_experts_for_query(self, query: ExpertQuery) -> List[str]:
        """Sort experts by preference for a specific query."""
        expert_scores = []
        
        for expert_name, config in EXPERT_REGISTRY.items():
            score = 0
            
            # Base score by priority
            priority_scores = {
                ExpertPriority.PRIMARY: 100,
                ExpertPriority.SECONDARY: 75,
                ExpertPriority.FALLBACK: 50,
                ExpertPriority.EXPERIMENTAL: 25
            }
            score += priority_scores[config.priority]
            
            # Adjust for query type compatibility
            if "all" in config.supported_query_types or query.query_type in config.supported_query_types:
                score += 10
            
            # Prefer free experts for low priority queries
            if query.priority == "low" and config.cost_per_1k_tokens == 0.0:
                score += 15
            
            # Prefer high-quality experts for critical queries
            if query.priority == "critical" and config.priority == ExpertPriority.PRIMARY:
                score += 20
            
            expert_scores.append((expert_name, score))
        
        # Sort by score (descending)
        expert_scores.sort(key=lambda x: x[1], reverse=True)
        
        return [name for name, _ in expert_scores]
    
    def get_available_experts(self) -> List[str]:
        """Get list of all available expert names."""
        return list(EXPERT_REGISTRY.keys())
    
    def get_expert_config(self, expert_name: str) -> Optional[ExpertConfig]:
        """Get configuration for a specific expert."""
        return EXPERT_REGISTRY.get(expert_name)


def estimate_cost(expert_name: str, tokens: int) -> float:
    """
    Estimate cost for processing tokens with a specific expert.
    
    Args:
        expert_name: Name of the expert
        tokens: Number of tokens to process
        
    Returns:
        Estimated cost in USD
    """
    config = EXPERT_REGISTRY.get(expert_name)
    if not config:
        return 0.0
    
    return (tokens / 1000) * config.cost_per_1k_tokens


class ExpertHealthCheck:
    """Health check system for all experts."""
    
    def __init__(self, factory: Optional[ExpertFactory] = None):
        """Initialize health checker."""
        self.factory = factory or ExpertFactory()
    
    async def check_all_experts(self) -> Dict[str, Dict[str, Any]]:
        """
        Check health of all configured experts.
        
        Returns:
            Dictionary with health status for each expert
        """
        results = {}
        
        for expert_name, config in EXPERT_REGISTRY.items():
            result = {
                "available": False,
                "priority": config.priority.name,
                "requires_api_key": config.requires_api_key,
                "cost_per_1k_tokens": config.cost_per_1k_tokens,
                "error": None
            }
            
            try:
                client = await self.factory.create_expert(expert_name)
                if client:
                    result["available"] = True
                else:
                    result["error"] = "Failed to create client or health check failed"
            except Exception as e:
                result["error"] = str(e)
            
            results[expert_name] = result
        
        return results
    
    async def get_summary(self) -> Dict[str, Any]:
        """Get summary of expert availability."""
        all_status = await self.check_all_experts()
        
        available_experts = [
            name for name, status in all_status.items()
            if status["available"]
        ]
        
        # Group by priority
        by_priority = {
            "PRIMARY": [],
            "SECONDARY": [],
            "FALLBACK": [],
            "EXPERIMENTAL": []
        }
        
        for name, status in all_status.items():
            if status["available"]:
                by_priority[status["priority"]].append(name)
        
        # Calculate costs
        free_experts = [
            name for name in available_experts
            if all_status[name]["cost_per_1k_tokens"] == 0.0
        ]
        
        paid_experts = [
            name for name in available_experts
            if all_status[name]["cost_per_1k_tokens"] > 0.0
        ]
        
        return {
            "total_configured": len(EXPERT_REGISTRY),
            "total_available": len(available_experts),
            "by_priority": by_priority,
            "free_experts": free_experts,
            "paid_experts": paid_experts,
            "recommended_setup": self._get_recommendations(all_status)
        }
    
    def _get_recommendations(self, all_status: Dict[str, Dict[str, Any]]) -> List[str]:
        """Get setup recommendations based on current status."""
        recommendations = []
        
        # Check if any primary experts are available
        primary_available = any(
            status["available"] and status["priority"] == "PRIMARY"
            for status in all_status.values()
        )
        
        if not primary_available:
            recommendations.append(
                "No primary experts available. Consider setting up Claude, GPT-4, or DeepSeek for best results."
            )
        
        # Check for local alternatives
        local_available = any(
            name.startswith("ollama") and status["available"]
            for name, status in all_status.items()
        )
        
        if not local_available:
            recommendations.append(
                "No local models available. Install Ollama for free, private inference."
            )
        
        # Check for diversity
        available_count = sum(1 for s in all_status.values() if s["available"])
        if available_count < 3:
            recommendations.append(
                f"Only {available_count} experts available. Add more for better consensus."
            )
        
        # Cost optimization
        free_available = any(
            status["available"] and status["cost_per_1k_tokens"] == 0.0
            for status in all_status.values()
        )
        
        if not free_available:
            recommendations.append(
                "No free experts available. Consider Ollama or HuggingFace for cost savings."
            )
        
        if not recommendations:
            recommendations.append("Expert setup looks good! You have diverse options available.")
        
        return recommendations


def get_expert(expert_name: str) -> BaseExpertClient:
    """
    Get an expert instance by name.
    
    Args:
        expert_name: Name of the expert to create
        
    Returns:
        Expert client instance
        
    Raises:
        ValueError: If expert name is unknown or creation fails
    """
    config = EXPERT_REGISTRY.get(expert_name)
    if not config:
        raise ValueError(f"Unknown expert: {expert_name}")
    
    # Get API key if required
    if config.requires_api_key:
        api_key = os.getenv(config.env_var_name)
        if not api_key:
            raise ValueError(f"No API key found for {expert_name} ({config.env_var_name})")
    else:
        api_key = None
    
    # Create and return client
    return config.expert_class(api_key=api_key)


def create_expert(expert_type: ExpertType, config: Optional[Dict[str, Any]] = None) -> BaseExpertClient:
    """
    Create an expert by type.
    
    This is a compatibility function for backward compatibility.
    
    Args:
        expert_type: Type of expert to create
        config: Optional configuration dict
        
    Returns:
        Expert client instance
        
    Raises:
        ValueError: If expert type is unknown or creation fails
    """
    # Map ExpertType enum to expert names
    type_mapping = {
        ExpertType.CLAUDE: "claude",
        ExpertType.GPT4: "gpt4",
        ExpertType.GEMINI: "gemini",
        ExpertType.SUPERGROK: "groq",
        ExpertType.DEEPSEEK: "deepseek",
        ExpertType.HUMAN: "ollama"  # Default to ollama for human/fallback
    }
    
    expert_name = type_mapping.get(expert_type)
    if not expert_name:
        raise ValueError(f"Unknown expert type: {expert_type}")
    
    # Get expert configuration
    expert_config = EXPERT_REGISTRY.get(expert_name)
    if not expert_config:
        raise ValueError(f"No configuration found for expert: {expert_name}")
    
    # Use config if provided, otherwise use environment
    if config and "api_key" in config:
        api_key = config["api_key"]
    elif expert_config.requires_api_key:
        api_key = os.getenv(expert_config.env_var_name)
        if not api_key:
            raise ValueError(f"No API key found for {expert_name} ({expert_config.env_var_name})")
    else:
        api_key = None
    
    # Create and return client
    return expert_config.expert_class(api_key=api_key)


class ExpertOrchestrator:
    """
    Orchestrates multiple experts for consensus responses.
    
    Implements smart routing and fallback strategies.
    """
    
    def __init__(self, factory: Optional[ExpertFactory] = None):
        """Initialize orchestrator."""
        self.factory = factory or ExpertFactory()
    
    async def get_consensus_response(
        self,
        query: ExpertQuery,
        min_experts: int = 2,
        max_experts: int = 4,
        timeout: float = 300.0
    ) -> List[ExpertResponse]:
        """
        Get consensus response from multiple experts.
        
        Args:
            query: Query to process
            min_experts: Minimum number of responses required
            max_experts: Maximum number of experts to consult
            timeout: Total timeout for all responses
            
        Returns:
            List of expert responses
        """
        # Select experts
        experts = await self.factory.select_experts_for_query(query, max_experts)
        
        if len(experts) < min_experts:
            logger.warning(
                f"Only {len(experts)} experts available, "
                f"less than minimum {min_experts}"
            )
        
        # Create tasks for parallel execution
        tasks = []
        for expert in experts:
            task = asyncio.create_task(
                self._get_expert_response_with_timeout(expert, query, timeout / 2)
            )
            tasks.append((expert, task))
        
        # Collect responses
        responses = []
        
        for expert, task in tasks:
            try:
                response = await task
                if response and response.status == "completed":
                    responses.append(response)
                    logger.info(
                        f"Got response from {response.expert_type} "
                        f"with confidence {response.confidence}"
                    )
            except asyncio.TimeoutError:
                logger.warning(f"Expert {type(expert).__name__} timed out")
            except Exception as e:
                logger.error(f"Expert {type(expert).__name__} failed: {e}")
        
        # Ensure minimum responses
        if len(responses) < min_experts:
            logger.warning(
                f"Only got {len(responses)} responses, "
                f"less than minimum {min_experts}"
            )
        
        return responses
    
    async def _get_expert_response_with_timeout(
        self,
        expert: BaseExpertClient,
        query: ExpertQuery,
        timeout: float
    ) -> Optional[ExpertResponse]:
        """Get response from expert with timeout."""
        try:
            return await asyncio.wait_for(
                expert.generate_response(query),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            logger.error(f"Expert {type(expert).__name__} timed out after {timeout}s")
            raise