"""
Open source expert clients for local and free AI models.

Provides alternatives that don't require API keys or payment.
"""

from __future__ import annotations
import os
import asyncio
import httpx
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

__all__ = [
    "OllamaExpertClient",
    "LocalAIExpertClient",
    "HuggingFaceExpertClient"
]


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
            prompt += f"\n\nAdditional Context: {json.dumps(query.context)}"\n\n        if query.constraints:\n            prompt += f"\n\nConstraints: {', '.join(query.constraints)}"\n\n        return prompt\n\n    async def generate_response(self, query: ExpertQuery) -> ExpertResponse:\n        """Generate response using Ollama."""\n        start_time = datetime.utcnow()\n        response = ExpertResponse(\n            query_id=query.id,\n            expert_type=ExpertType.CLAUDE,  # We'll masquerade as Claude for compatibility\n            status=ResponseStatus.IN_PROGRESS,\n            metadata={"actual_expert": "ollama", "model": self.model}\n        )\n\n        try:\n            # Ensure model is available\n            if not await self.ensure_model_pulled():\n                raise RuntimeError(f"Failed to pull Ollama model: {self.model}")\n\n            # Select model\n            model = self._select_model_for_query(query)\n            logger.info(f"Using Ollama model: {model}")\n\n            # Get circuit breaker for this expert\n            manager = get_circuit_breaker_manager()\n            breaker = await manager.get_or_create(\n                f"ollama_expert_{model}",\n                CircuitBreakerConfig(\n                    failure_threshold=5,\n                    timeout=120,\n                    failure_rate_threshold=0.6,\n                    minimum_calls=3,\n                    fallback=lambda: self._create_fallback_response(query)\n                )\n            )\n\n            # Generate response with circuit breaker protection\n            result = await breaker.call(\n                self._ollama_api_call,\n                model,\n                query\n            )\n\n            response.content = result['content']\n            response.confidence = result['confidence']\n            response.recommendations = result['recommendations']\n            response.code_snippets = result['code_snippets']\n            response.metadata = result['metadata']\n            response.mark_completed()\n\n        except Exception as e:\n            logger.error(f"Ollama generation failed: {e}")\n            response.mark_failed(str(e))\n\n        return response\n\n    async def health_check(self) -> bool:\n        """Check if Ollama is running."""\n        try:\n            # Use connection pool\n            connection_manager = await get_connection_manager()\n            async with connection_manager.http_pool.get_session(self.host) as session:\n                async with session.get(\n                    f"{self.host}/api/version"\n                ) as resp:\n                    return resp.status == 200\n        except Exception:\n            return False\n\n    def _calculate_confidence(self, content: str) -> float:\n        """Calculate confidence based on response quality."""\n        # Base confidence for local models\n        confidence = 0.7\n\n        # Adjust based on content\n        if len(content) > 500:\n            confidence += 0.1\n        if "```" in content:  # Has code\n            confidence += 0.1\n        if any(word in content.lower() for word in ["recommend", "suggest", "should"]):\n            confidence += 0.05\n\n        return min(0.95, confidence)  # Cap at 0.95 for local models\n\n    def _extract_recommendations(self, content: str) -> List[str]:\n        """Extract recommendations from content."""\n        recommendations = []\n        lines = content.split('\n')\n\n        for i, line in enumerate(lines):\n            line = line.strip()\n            # Look for numbered or bulleted recommendations\n            if any(line.startswith(prefix) for prefix in ['- ', '* ', '• ', '1.', '2.', '3.']):\n                if any(word in lines[max(0, i-2):i+1] for word in ["recommend", "suggest", "should"]):\n                    rec = line.lstrip('- *•1234567890.')\n                    if rec:\n                        recommendations.append(rec)\n\n        return recommendations[:8]\n\n    def _extract_code_snippets(self, content: str) -> List[Dict[str, str]]:\n        """Extract code blocks from content."""\n        snippets = []\n        parts = content.split('```')\n\n        for i in range(1, len(parts), 2):\n            if i < len(parts):\n                lines = parts[i].split('\n')\n                language = lines[0].strip() if lines else ""\n                code = '\n'.join(lines[1:]) if len(lines) > 1 else ""\n\n                if code.strip():\n                    snippets.append({\n                        "language": language or "text",\n                        "code": code,\n                        "title": f"Example {len(snippets) + 1}"\n                    })\n\n        return snippets\n\n    @retry_network(max_attempts=3, timeout=60)\n    async def _ollama_api_call(self, model: str, query: ExpertQuery) -> Dict[str, Any]:\n        """Make Ollama API call with retry logic."""\n        # Use connection pool\n        connection_manager = await get_connection_manager()\n        async with connection_manager.http_pool.get_session(self.host) as session:\n            # Generate response\n            async with session.post(\n                f"{self.host}/api/generate",\n                json={\n                    "model": model,\n                    "prompt": self._create_prompt(query),\n                    "stream": False,\n                    "options": {\n                        "temperature": 0.7,\n                        "top_p": 0.9,\n                        "num_predict": 4096\n                    }\n                }\n            ) as resp:\n                if resp.status == 200:\n                    data = await resp.json()\n                    content = data.get("response", "")\n\n                    return {\n                        'content': content,\n                        'confidence': self._calculate_confidence(content),\n                        'recommendations': self._extract_recommendations(content),\n                        'code_snippets': self._extract_code_snippets(content),\n                        'metadata': {\n                            "model": model,\n                            "eval_count": data.get("eval_count"),\n                            "eval_duration": data.get("eval_duration"),\n                            "total_duration": data.get("total_duration")\n                        }\n                    }\n                else:\n                    raise RuntimeError(f"Ollama API error: {resp.status}")\n\n    def _create_fallback_response(self, query: ExpertQuery) -> Dict[str, Any]:\n        """Create fallback response when circuit is open."""\n        return {\n            'content': "Ollama service is currently unavailable. The circuit breaker has been triggered due to repeated failures. Please check if Ollama is running locally.",\n            'confidence': 0.0,\n            'recommendations': [],\n            'code_snippets': [],\n            'metadata': {\n                "fallback": True,\n                "reason": "circuit_breaker_open"\n            }\n        }\n\n\nclass LocalAIExpertClient(BaseExpertClient):\n    """\n    LocalAI client - OpenAI-compatible local inference.\n\n    Drop-in replacement for OpenAI API but runs locally.\n    """\n\n    def __init__(\n        self,\n        host: str = None,\n        model: str = "gpt-3.5-turbo",  # Model name mapping\n        timeout: int = 300\n    ):\n        """Initialize LocalAI client."""\n        super().__init__(api_key=None)\n        self.host = host or os.getenv("LOCALAI_HOST", "http://localhost:8080")\n        self.model = model\n        self.timeout = timeout\n\n    async def generate_response(self, query: ExpertQuery) -> ExpertResponse:\n        """Generate response using LocalAI."""\n        start_time = datetime.utcnow()\n        response = ExpertResponse(\n            query_id=query.id,\n            expert_type=ExpertType.GPT4,  # Masquerade as GPT-4\n            status=ResponseStatus.IN_PROGRESS,\n            metadata={"actual_expert": "localai", "model": self.model}\n        )\n\n        try:\n            async with httpx.AsyncClient(timeout=self.timeout) as client:\n                # OpenAI-compatible endpoint\n                response_data = await client.post(\n                    f"{self.host}/v1/chat/completions",\n                    json={\n                        "model": self.model,\n                        "messages": [\n                            {\n                                "role": "system",\n                                "content": "You are an expert consultant providing detailed technical analysis."\n                            },\n                            {\n                                "role": "user",\n                                "content": query.content\n                            }\n                        ],\n                        "temperature": 0.7,\n                        "max_tokens": 4096\n                    }\n                )\n                if response_data.status_code == 200:\n                    data = response_data.json()\n                    content = data["choices"][0]["message"]["content"]\n\n                    response.content = content\n                    response.confidence = 0.8  # Default for local models\n                    response.mark_completed()\n                else:\n                    raise RuntimeError(f"LocalAI error: {response_data.status_code}")\n\n        except Exception as e:\n            logger.error(f"LocalAI generation failed: {e}")\n            response.mark_failed(str(e))\n\n        return response\n\n    async def health_check(self) -> bool:\n        """Check LocalAI availability."""\n        try:\n            async with httpx.AsyncClient(timeout=5) as client:\n                response = await client.get(f"{self.host}/readyz")\n                return response.status_code == 200\n        except Exception:\n            return False\n\n\nclass HuggingFaceExpertClient(BaseExpertClient):\n    """\n    Hugging Face Inference API client.\n\n    Free tier available with rate limits.\n    """\n\n    def __init__(\n        self,\n        api_key: Optional[str] = None,\n        model: str = "mistralai/Mixtral-8x7B-Instruct-v0.1"\n    ):\n        """Initialize HuggingFace client."""\n        super().__init__(api_key or os.getenv("HUGGINGFACE_API_TOKEN"))\n        self.model = model\n        self.api_url = f"https://api-inference.huggingface.co/models/{model}"\n\n    async def generate_response(self, query: ExpertQuery) -> ExpertResponse:\n        """Generate response using HuggingFace."""\n        response = ExpertResponse(\n            query_id=query.id,\n            expert_type=ExpertType.CLAUDE,  # Generic expert type\n            status=ResponseStatus.IN_PROGRESS,\n            metadata={"actual_expert": "huggingface", "model": self.model}\n        )\n\n        try:\n            # Get circuit breaker for this expert\n            manager = get_circuit_breaker_manager()\n            breaker = await manager.get_or_create(\n                f"huggingface_expert_{self.model.replace('/', '_')}",\n                CircuitBreakerConfig(\n                    failure_threshold=5,\n                    timeout=90,\n                    failure_rate_threshold=0.6,\n                    minimum_calls=3,\n                    fallback=lambda: self._create_fallback_response(query)\n                )\n            )\n\n            # Generate response with circuit breaker protection\n            result = await breaker.call(\n                self._huggingface_api_call,\n                query\n            )\n\n            response.content = result['content']\n            response.confidence = result['confidence']\n            response.metadata = result['metadata']\n            response.mark_completed()\n\n        except Exception as e:\n            logger.error(f"HuggingFace generation failed: {e}")\n            response.mark_failed(str(e))\n\n        return response\n\n    async def health_check(self) -> bool:\n        """Check HuggingFace API availability."""\n        try:\n            headers = {}\n            if self.api_key:\n                headers["Authorization"] = f"Bearer {self.api_key}"\n\n            async with httpx.AsyncClient(timeout=10) as client:\n                response = await client.post(\n                    self.api_url,\n                    headers=headers,\n                    json={"inputs": "Hello"}\n                )\n                return response.status_code in [200, 503]  # 503 = model loading\n        except Exception:\n            return False\n\n    @retry_network(max_attempts=3, timeout=60)\n    async def _huggingface_api_call(self, query: ExpertQuery) -> Dict[str, Any]:\n        """Make HuggingFace API call with retry logic."""\n        headers = {}\n        if self.api_key:\n            headers["Authorization"] = f"Bearer {self.api_key}"\n\n        prompt = f"""<|system|>You are an expert technical consultant.</s>\n<|user|>{query.content}</s>\n<|assistant|>"""\n\n        async with httpx.AsyncClient(timeout=60) as client:\n            response = await client.post(\n                self.api_url,\n                headers=headers,\n                json={\n                    "inputs": prompt,\n                    "parameters": {\n                        "max_new_tokens": 2048,\n                        "temperature": 0.7,\n                        "top_p": 0.95,\n                        "do_sample": True\n                    }\n                }\n            )\n            if response.status_code == 200:\n                data = response.json()\n\n                # Extract generated text\n                if isinstance(data, list) and data:\n                    content = data[0].get("generated_text", "")\n                    # Remove the prompt from response\n                    content = content.replace(prompt, "").strip()\n                else:\n                    content = str(data)\n\n                return {\n                    'content': content,\n                    'confidence': 0.75,\n                    'metadata': {\n                        "model": self.model,\n                        "api_url": self.api_url\n                    }\n                }\n            else:\n                error_data = response.text\n                raise RuntimeError(f"HuggingFace error {response.status_code}: {error_data}")\n\n    def _create_fallback_response(self, query: ExpertQuery) -> Dict[str, Any]:\n        """Create fallback response when circuit is open."""\n        return {\n            'content': "HuggingFace Inference API is currently unavailable. The circuit breaker has been triggered due to repeated failures. Please try again later or check API status.",\n            'confidence': 0.0,\n            'metadata': {\n                "fallback": True,\n                "reason": "circuit_breaker_open",\n                "model": self.model\n            }\n        }\n