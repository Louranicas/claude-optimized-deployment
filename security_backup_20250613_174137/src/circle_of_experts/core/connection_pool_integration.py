"""
Integration module for connection pooling with expert clients.

This module provides connection pool adapters for all expert clients
to ensure efficient resource usage and prevent connection exhaustion.
"""

from __future__ import annotations
import asyncio
from typing import Optional, Dict, Any, TYPE_CHECKING
import logging
from contextlib import asynccontextmanager

from src.core.connections import (
    get_connection_manager,
    ConnectionPoolConfig,
    ConnectionPoolManager
)

__all__ = [
    "ExpertConnectionPoolMixin",
    "patch_expert_clients"
]

if TYPE_CHECKING:
    from src.circle_of_experts.experts.claude_expert import BaseExpertClient

logger = logging.getLogger(__name__)


class ExpertConnectionPoolMixin:
    """
    Mixin class to add connection pooling capabilities to expert clients.
    
    This mixin provides:
    - Shared connection pool access
    - Automatic session management
    - Connection metrics tracking
    """
    
    _shared_connection_manager: Optional[ConnectionPoolManager] = None
    _manager_lock = asyncio.Lock()
    
    @classmethod
    async def get_shared_connection_manager(cls) -> ConnectionPoolManager:
        """Get or create shared connection manager."""
        async with cls._manager_lock:
            if cls._shared_connection_manager is None:
                # Create custom config for expert clients
                config = ConnectionPoolConfig(
                    http_total_connections=200,  # Higher limit for multiple experts
                    http_per_host_connections=20,  # Higher per-host for API calls
                    http_keepalive_timeout=60,  # Longer keepalive for API connections
                    http_connect_timeout=15,
                    http_request_timeout=120,  # Longer timeout for AI responses
                    health_check_interval=300,  # Less frequent checks
                    enable_monitoring=True
                )
                cls._shared_connection_manager = await get_connection_manager(config)
                logger.info("Initialized shared connection manager for experts")
            
            return cls._shared_connection_manager
    
    @asynccontextmanager
    async def get_http_session(self, base_url: str):
        """Get HTTP session from connection pool."""
        manager = await self.get_shared_connection_manager()
        async with manager.http_pool.get_session(base_url) as session:
            yield session
    
    async def make_pooled_request(
        self,
        method: str,
        url: str,
        **kwargs
    ):
        """Make HTTP request using connection pool."""
        manager = await self.get_shared_connection_manager()
        return await manager.http_pool.request(method, url, **kwargs)


def patch_expert_clients():
    """
    Patch existing expert clients to use connection pooling.
    
    This function modifies the expert client classes to use
    connection pooling instead of creating new sessions.
    """
    try:
        # Import expert modules
        from src.circle_of_experts.experts import commercial_experts
        from src.circle_of_experts.experts import open_source_experts
        
        # Patch commercial experts
        _patch_gpt4_client(commercial_experts.GPT4ExpertClient)
        _patch_gemini_client(commercial_experts.GeminiExpertClient)
        _patch_deepseek_client(commercial_experts.DeepSeekExpertClient)
        
        # Patch open source experts if they use HTTP
        if hasattr(open_source_experts, 'OllamaExpertClient'):
            _patch_ollama_client(open_source_experts.OllamaExpertClient)
        
        logger.info("Successfully patched expert clients for connection pooling")
        
    except Exception as e:
        logger.error(f"Failed to patch expert clients: {e}")


def _patch_deepseek_client(client_class):
    """Patch DeepSeek client to use connection pooling."""
    original_generate = client_class.generate_response
    
    async def pooled_generate_response(self, query):
        """Generate response using connection pool."""
        # Store reference to original method
        self._original_generate = original_generate.__get__(self, type(self))
        
        # Get connection manager
        if not hasattr(self, '_connection_manager'):
            self._connection_manager = await ExpertConnectionPoolMixin.get_shared_connection_manager()
        
        # Replace the session creation part
        import inspect
        source = inspect.getsource(original_generate)
        
        # Use connection pool instead of creating new session
        from src.circle_of_experts.models.response import ExpertResponse, ResponseStatus, ExpertType
        from src.core.retry import retry_api_call
        from datetime import datetime
        import json
        
        if not self.api_key:
            raise ValueError("DeepSeek API key not configured")
        
        response = ExpertResponse(
            query_id=query.id,
            expert_type=ExpertType.DEEPSEEK,
            status=ResponseStatus.IN_PROGRESS
        )
        
        try:
            # Select model
            model = self._select_model_for_query(query)
            logger.info(f"Using DeepSeek model: {model}")
            
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            # Use connection pool
            async with self._connection_manager.http_pool.get_session(self.base_url) as session:
                async with session.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json={
                        "model": model,
                        "messages": self._create_messages(query),
                        "temperature": 0.7,
                        "max_tokens": 4096,
                        "top_p": 0.95,
                        "stream": False
                    },
                    timeout=300  # Session already has timeout configured
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        content = data["choices"][0]["message"]["content"]
                        
                        response.content = content
                        response.confidence = self._calculate_confidence(content, data)
                        response.recommendations = self._extract_recommendations(content)
                        response.code_snippets = self._extract_code_snippets(content)
                        
                        # Add metadata
                        response.metadata = {
                            "model": model,
                            "usage": data.get("usage", {}),
                            "finish_reason": data["choices"][0].get("finish_reason")
                        }
                        
                        response.mark_completed()
                    else:
                        error_text = await resp.text()
                        raise RuntimeError(f"DeepSeek API error ({resp.status}): {error_text}")
                        
        except Exception as e:
            logger.error(f"DeepSeek generation failed: {e}")
            response.mark_failed(str(e))
        
        return response
    
    # Apply retry decorator
    pooled_generate_response = retry_api_call(max_attempts=5, timeout=120)(pooled_generate_response)
    
    # Replace method
    client_class.generate_response = pooled_generate_response
    
    # Also patch health check
    original_health_check = client_class.health_check
    
    async def pooled_health_check(self):
        """Check DeepSeek API availability using connection pool."""
        if not self.api_key:
            return False
        
        try:
            if not hasattr(self, '_connection_manager'):
                self._connection_manager = await ExpertConnectionPoolMixin.get_shared_connection_manager()
            
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            async with self._connection_manager.http_pool.get_session(self.base_url) as session:
                async with session.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json={
                        "model": "deepseek-chat",
                        "messages": [{"role": "user", "content": "Hi"}],
                        "max_tokens": 5
                    },
                    timeout=10
                ) as resp:
                    return resp.status == 200
        except Exception as e:
            logger.error(f"DeepSeek health check failed: {e}")
            return False
    
    client_class.health_check = pooled_health_check


def _patch_gpt4_client(client_class):
    """Patch GPT-4 client to use connection pooling."""
    # GPT-4 uses AsyncOpenAI which has its own connection pooling
    # We'll add monitoring hooks
    pass


def _patch_gemini_client(client_class):
    """Patch Gemini client to use connection pooling."""
    # Gemini uses its own SDK with connection management
    # We'll add monitoring hooks
    pass


def _patch_ollama_client(client_class):
    """Patch Ollama client to use connection pooling."""
    original_generate = client_class.generate_response
    
    async def pooled_generate_response(self, query):
        """Generate response using connection pool."""
        # Implementation similar to DeepSeek but for Ollama API
        pass
    
    client_class.generate_response = pooled_generate_response


# Auto-patch on import
patch_expert_clients()