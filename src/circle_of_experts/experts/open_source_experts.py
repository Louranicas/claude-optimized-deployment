"""
Open source expert clients for local and free AI models.

Provides alternatives that don't require API keys or payment.
"""

from __future__ import annotations
import os
import asyncio
import aiohttp
from typing import Optional, Dict, Any, List
import json
import logging
from datetime import datetime

from src.circle_of_experts.models.response import ExpertResponse, ExpertType, ResponseStatus
from src.circle_of_experts.models.query import ExpertQuery
from src.core.retry import retry_network, RetryConfig, RetryStrategy
from src.circle_of_experts.experts.claude_expert import BaseExpertClient
from src.core.connections import get_connection_manager
from src.core.circuit_breaker import circuit_breaker, CircuitBreakerConfig, get_circuit_breaker_manager

logger = logging.getLogger(__name__)


class OllamaExpertClient(BaseExpertClient):
    """
    Ollama client for local LLM inference.
    
    Supports multiple open source models running locally.
    No API key required, completely free and private.
    """
    
    def __init__(
        self,
        host: str = None,
        model: str = "mixtral",
        timeout: int = 300
    ):
        """
        Initialize Ollama client.
        
        Args:
            host: Ollama server URL (default: http://localhost:11434)
            model: Model name (e.g., mixtral, mistral, codellama, llama2)
            timeout: Request timeout in seconds
        """
        super().__init__(api_key=None)  # No API key needed
        self.host = host or os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self.model = model
        self.timeout = timeout
        
        # Model selection based on task
        self.model_selection = {
            "code": "codellama:13b",
            "general": "mixtral:8x7b",
            "fast": "mistral:7b",
            "detailed": "llama2:70b"
        }
    
    async def ensure_model_pulled(self) -> bool:
        """Ensure the model is downloaded."""
        try:
            # Use connection pool
            connection_manager = await get_connection_manager()
            async with connection_manager.http_pool.get_session(self.host) as session:
                # Check if model exists
                async with session.get(
                    f"{self.host}/api/tags"
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        models = [m['name'] for m in data.get('models', [])]
                        
                        if not any(self.model in m for m in models):
                            logger.warning(f"Model {self.model} not found. Pulling...")
                            # Pull model
                            async with session.post(
                                f"{self.host}/api/pull",
                                json={"name": self.model}
                            ) as pull_resp:
                                return pull_resp.status == 200
            return True
        except Exception as e:
            logger.error(f"Failed to ensure Ollama model: {e}")
            return False
    
    def _select_model_for_query(self, query: ExpertQuery) -> str:
        """Select appropriate model based on query type."""
        if query.query_type == "review" and "code" in query.tags:
            return self.model_selection.get("code", self.model)
        elif query.query_type in ["architectural", "research"]:
            return self.model_selection.get("detailed", self.model)
        elif query.priority == "high":
            return self.model_selection.get("general", self.model)
        else:
            return self.model_selection.get("fast", self.model)
    
    def _create_prompt(self, query: ExpertQuery) -> str:
        """Create optimized prompt for Ollama models."""
        prompt = f"""You are an expert consultant providing analysis for the following query:

Query Type: {query.query_type}
Priority: {query.priority}

{query.content}

Please provide:
1. A thorough analysis of the problem
2. Specific recommendations with examples
3. Any potential limitations or considerations

Format your response with clear sections and include code examples where relevant.
"""
        
        if query.context:
            prompt += f"\n\nAdditional Context: {json.dumps(query.context)}"
        
        if query.constraints:
            prompt += f"\n\nConstraints: {', '.join(query.constraints)}"
        
        return prompt
    
    async def generate_response(self, query: ExpertQuery) -> ExpertResponse:
        """Generate response using Ollama."""
        start_time = datetime.utcnow()
        response = ExpertResponse(
            query_id=query.id,
            expert_type=ExpertType.CLAUDE,  # We'll masquerade as Claude for compatibility
            status=ResponseStatus.IN_PROGRESS,
            metadata={"actual_expert": "ollama", "model": self.model}
        )
        
        try:
            # Ensure model is available
            if not await self.ensure_model_pulled():
                raise RuntimeError(f"Failed to pull Ollama model: {self.model}")
            
            # Select model
            model = self._select_model_for_query(query)
            logger.info(f"Using Ollama model: {model}")
            
            # Get circuit breaker for this expert
            manager = get_circuit_breaker_manager()
            breaker = await manager.get_or_create(
                f"ollama_expert_{model}",
                CircuitBreakerConfig(
                    failure_threshold=5,
                    timeout=120,
                    failure_rate_threshold=0.6,
                    minimum_calls=3,
                    fallback=lambda: self._create_fallback_response(query)
                )
            )
            
            # Generate response with circuit breaker protection
            result = await breaker.call(
                self._ollama_api_call,
                model,
                query
            )
            
            response.content = result['content']
            response.confidence = result['confidence']
            response.recommendations = result['recommendations']
            response.code_snippets = result['code_snippets']
            response.metadata = result['metadata']
            response.mark_completed()
                        
        except Exception as e:
            logger.error(f"Ollama generation failed: {e}")
            response.mark_failed(str(e))
        
        return response
    
    async def health_check(self) -> bool:
        """Check if Ollama is running."""
        try:
            # Use connection pool
            connection_manager = await get_connection_manager()
            async with connection_manager.http_pool.get_session(self.host) as session:
                async with session.get(
                    f"{self.host}/api/version"
                ) as resp:
                    return resp.status == 200
        except Exception:
            return False
    
    def _calculate_confidence(self, content: str) -> float:
        """Calculate confidence based on response quality."""
        # Base confidence for local models
        confidence = 0.7
        
        # Adjust based on content
        if len(content) > 500:
            confidence += 0.1
        if "```" in content:  # Has code
            confidence += 0.1
        if any(word in content.lower() for word in ["recommend", "suggest", "should"]):
            confidence += 0.05
        
        return min(0.95, confidence)  # Cap at 0.95 for local models
    
    def _extract_recommendations(self, content: str) -> List[str]:
        """Extract recommendations from content."""
        recommendations = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            line = line.strip()
            # Look for numbered or bulleted recommendations
            if any(line.startswith(prefix) for prefix in ['- ', '* ', '• ', '1.', '2.', '3.']):
                if any(word in lines[max(0, i-2):i+1] for word in ["recommend", "suggest", "should"]):
                    rec = line.lstrip('- *•1234567890.')
                    if rec:
                        recommendations.append(rec)
        
        return recommendations[:8]
    
    def _extract_code_snippets(self, content: str) -> List[Dict[str, str]]:
        """Extract code blocks from content."""
        snippets = []
        parts = content.split('```')
        
        for i in range(1, len(parts), 2):
            if i < len(parts):
                lines = parts[i].split('\n')
                language = lines[0].strip() if lines else ""
                code = '\n'.join(lines[1:]) if len(lines) > 1 else ""
                
                if code.strip():
                    snippets.append({
                        "language": language or "text",
                        "code": code,
                        "title": f"Example {len(snippets) + 1}"
                    })
        
        return snippets
    
    @retry_network(max_attempts=3, timeout=60)
    async def _ollama_api_call(self, model: str, query: ExpertQuery) -> Dict[str, Any]:
        """Make Ollama API call with retry logic."""
        # Use connection pool
        connection_manager = await get_connection_manager()
        async with connection_manager.http_pool.get_session(self.host) as session:
            # Generate response
            async with session.post(
                f"{self.host}/api/generate",
                json={
                    "model": model,
                    "prompt": self._create_prompt(query),
                    "stream": False,
                    "options": {
                        "temperature": 0.7,
                        "top_p": 0.9,
                        "num_predict": 4096
                    }
                }
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    content = data.get("response", "")
                    
                    return {
                        'content': content,
                        'confidence': self._calculate_confidence(content),
                        'recommendations': self._extract_recommendations(content),
                        'code_snippets': self._extract_code_snippets(content),
                        'metadata': {
                            "model": model,
                            "eval_count": data.get("eval_count"),
                            "eval_duration": data.get("eval_duration"),
                            "total_duration": data.get("total_duration")
                        }
                    }
                else:
                    raise RuntimeError(f"Ollama API error: {resp.status}")
    
    def _create_fallback_response(self, query: ExpertQuery) -> Dict[str, Any]:
        """Create fallback response when circuit is open."""
        return {
            'content': "Ollama service is currently unavailable. The circuit breaker has been triggered due to repeated failures. Please check if Ollama is running locally.",
            'confidence': 0.0,
            'recommendations': [],
            'code_snippets': [],
            'metadata': {
                "fallback": True,
                "reason": "circuit_breaker_open"
            }
        }


class LocalAIExpertClient(BaseExpertClient):
    """
    LocalAI client - OpenAI-compatible local inference.
    
    Drop-in replacement for OpenAI API but runs locally.
    """
    
    def __init__(
        self,
        host: str = None,
        model: str = "gpt-3.5-turbo",  # Model name mapping
        timeout: int = 300
    ):
        """Initialize LocalAI client."""
        super().__init__(api_key=None)
        self.host = host or os.getenv("LOCALAI_HOST", "http://localhost:8080")
        self.model = model
        self.timeout = timeout
    
    async def generate_response(self, query: ExpertQuery) -> ExpertResponse:
        """Generate response using LocalAI."""
        start_time = datetime.utcnow()
        response = ExpertResponse(
            query_id=query.id,
            expert_type=ExpertType.GPT4,  # Masquerade as GPT-4
            status=ResponseStatus.IN_PROGRESS,
            metadata={"actual_expert": "localai", "model": self.model}
        )
        
        try:
            async with aiohttp.ClientSession() as session:
                # OpenAI-compatible endpoint
                async with session.post(
                    f"{self.host}/v1/chat/completions",
                    json={
                        "model": self.model,
                        "messages": [
                            {
                                "role": "system",
                                "content": "You are an expert consultant providing detailed technical analysis."
                            },
                            {
                                "role": "user",
                                "content": query.content
                            }
                        ],
                        "temperature": 0.7,
                        "max_tokens": 4096
                    },
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        content = data["choices"][0]["message"]["content"]
                        
                        response.content = content
                        response.confidence = 0.8  # Default for local models
                        response.mark_completed()
                    else:
                        raise RuntimeError(f"LocalAI error: {resp.status}")
                        
        except Exception as e:
            logger.error(f"LocalAI generation failed: {e}")
            response.mark_failed(str(e))
        
        return response
    
    async def health_check(self) -> bool:
        """Check LocalAI availability."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.host}/readyz",
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    return resp.status == 200
        except Exception:
            return False


class HuggingFaceExpertClient(BaseExpertClient):
    """
    Hugging Face Inference API client.
    
    Free tier available with rate limits.
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "mistralai/Mixtral-8x7B-Instruct-v0.1"
    ):
        """Initialize HuggingFace client."""
        super().__init__(api_key or os.getenv("HUGGINGFACE_API_TOKEN"))
        self.model = model
        self.api_url = f"https://api-inference.huggingface.co/models/{model}"
    
    async def generate_response(self, query: ExpertQuery) -> ExpertResponse:
        """Generate response using HuggingFace."""
        response = ExpertResponse(
            query_id=query.id,
            expert_type=ExpertType.CLAUDE,  # Generic expert type
            status=ResponseStatus.IN_PROGRESS,
            metadata={"actual_expert": "huggingface", "model": self.model}
        )
        
        try:
            # Get circuit breaker for this expert
            manager = get_circuit_breaker_manager()
            breaker = await manager.get_or_create(
                f"huggingface_expert_{self.model.replace('/', '_')}",
                CircuitBreakerConfig(
                    failure_threshold=5,
                    timeout=90,
                    failure_rate_threshold=0.6,
                    minimum_calls=3,
                    fallback=lambda: self._create_fallback_response(query)
                )
            )
            
            # Generate response with circuit breaker protection
            result = await breaker.call(
                self._huggingface_api_call,
                query
            )
            
            response.content = result['content']
            response.confidence = result['confidence']
            response.metadata = result['metadata']
            response.mark_completed()
                        
        except Exception as e:
            logger.error(f"HuggingFace generation failed: {e}")
            response.mark_failed(str(e))
        
        return response
    
    async def health_check(self) -> bool:
        """Check HuggingFace API availability."""
        try:
            headers = {}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.api_url,
                    headers=headers,
                    json={"inputs": "Hello"},
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    return resp.status in [200, 503]  # 503 = model loading
        except Exception:
            return False
    
    @retry_network(max_attempts=3, timeout=60)
    async def _huggingface_api_call(self, query: ExpertQuery) -> Dict[str, Any]:
        """Make HuggingFace API call with retry logic."""
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        
        prompt = f"""<|system|>You are an expert technical consultant.</s>
<|user|>{query.content}</s>
<|assistant|>"""
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                self.api_url,
                headers=headers,
                json={
                    "inputs": prompt,
                    "parameters": {
                        "max_new_tokens": 2048,
                        "temperature": 0.7,
                        "top_p": 0.95,
                        "do_sample": True
                    }
                },
                timeout=aiohttp.ClientTimeout(total=60)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    
                    # Extract generated text
                    if isinstance(data, list) and data:
                        content = data[0].get("generated_text", "")
                        # Remove the prompt from response
                        content = content.replace(prompt, "").strip()
                    else:
                        content = str(data)
                    
                    return {
                        'content': content,
                        'confidence': 0.75,
                        'metadata': {
                            "model": self.model,
                            "api_url": self.api_url
                        }
                    }
                else:
                    error_data = await resp.text()
                    raise RuntimeError(f"HuggingFace error {resp.status}: {error_data}")
    
    def _create_fallback_response(self, query: ExpertQuery) -> Dict[str, Any]:
        """Create fallback response when circuit is open."""
        return {
            'content': "HuggingFace Inference API is currently unavailable. The circuit breaker has been triggered due to repeated failures. Please try again later or check API status.",
            'confidence': 0.0,
            'metadata': {
                "fallback": True,
                "reason": "circuit_breaker_open",
                "model": self.model
            }
        }
