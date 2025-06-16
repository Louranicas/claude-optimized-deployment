"""
OpenRouter expert client for accessing multiple AI models through a unified API.
"""

from __future__ import annotations
import os
import asyncio
from typing import Optional, Dict, Any, List
import json
import logging
from datetime import datetime

from openai import AsyncOpenAI

from src.circle_of_experts.models.response import ExpertResponse, ExpertType, ResponseStatus
from src.circle_of_experts.models.query import ExpertQuery
from src.core.retry import retry_api_call, RetryConfig, RetryStrategy
from src.circle_of_experts.experts.claude_expert import BaseExpertClient

__all__ = [
    "OpenRouterExpertClient"
]


logger = logging.getLogger(__name__)


class OpenRouterExpertClient(BaseExpertClient):
    """
    OpenRouter expert client providing access to multiple AI models.
    
    Supports Claude, GPT-4, Llama, Mixtral, and many other models through OpenRouter.
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "anthropic/claude-3.5-sonnet"
    ):
        """Initialize OpenRouter client."""
        super().__init__(api_key or os.getenv("OPENROUTER_API_KEY"))
        self.model = model
        self.base_url = "https://openrouter.ai/api/v1"
        
        # OpenRouter model options with capabilities
        self.model_options = {
            # Claude models (highest quality)
            "claude_sonnet": "anthropic/claude-3.5-sonnet",
            "claude_haiku": "anthropic/claude-3-haiku",
            "claude_opus": "anthropic/claude-3-opus",
            
            # GPT models
            "gpt4o": "openai/gpt-4o",
            "gpt4_turbo": "openai/gpt-4-turbo",
            "gpt4": "openai/gpt-4",
            
            # Open source powerhouses
            "llama_405b": "meta-llama/llama-3.1-405b-instruct",
            "llama_70b": "meta-llama/llama-3.1-70b-instruct",
            "mixtral_8x22b": "mistralai/mixtral-8x22b-instruct",
            "qwen_72b": "qwen/qwen-2.5-72b-instruct",
            
            # Specialized models  
            "deepseek_coder": "deepseek/deepseek-v3",
            "codestral": "mistralai/mistral-large-2411",
            "reasoning": "deepseek/deepseek-r1",
            
            # Cost-effective options
            "llama_8b": "meta-llama/llama-3.1-8b-instruct",
            "gemma_9b": "google/gemma-2-9b-it",
            "phi_mini": "microsoft/phi-3-mini-128k-instruct"
        }
        
        # Model capabilities for intelligent selection
        self.model_capabilities = {
            "anthropic/claude-3.5-sonnet": {"reasoning": 10, "speed": 8, "cost": 6, "coding": 9},
            "anthropic/claude-3-opus": {"reasoning": 10, "speed": 6, "cost": 4, "coding": 9},
            "openai/gpt-4o": {"reasoning": 9, "speed": 8, "cost": 6, "coding": 8},
            "meta-llama/llama-3.1-405b-instruct": {"reasoning": 9, "speed": 6, "cost": 5, "coding": 8},
            "meta-llama/llama-3.1-70b-instruct": {"reasoning": 8, "speed": 8, "cost": 8, "coding": 7},
            "mistralai/mixtral-8x22b-instruct": {"reasoning": 8, "speed": 7, "cost": 7, "coding": 8},
            "deepseek/deepseek-coder": {"reasoning": 7, "speed": 9, "cost": 9, "coding": 10},
            "deepseek/deepseek-r1": {"reasoning": 10, "speed": 6, "cost": 7, "coding": 8},
            "meta-llama/llama-3.1-8b-instruct": {"reasoning": 6, "speed": 10, "cost": 10, "coding": 6}
        }
        
        if self.api_key:
            self.client = AsyncOpenAI(
                api_key=self.api_key,
                base_url=self.base_url
            )
        else:
            self.client = None
    
    def _select_optimal_model(self, query: ExpertQuery) -> str:
        """Select optimal OpenRouter model based on query characteristics."""
        content_length = len(query.content)
        
        # Priority-based selection
        if query.priority == "critical":
            return self.model_options["claude_opus"]  # Best reasoning
        
        # Query type-based selection
        if query.query_type == "review" or "code" in query.content.lower():
            return self.model_options["deepseek_coder"]  # Best for coding
        elif query.query_type == "architectural":
            return self.model_options["claude_sonnet"]  # Best for architecture
        elif query.query_type == "optimization":
            return self.model_options["llama_405b"]  # Powerful reasoning
        elif query.query_type == "research":
            return self.model_options["reasoning"]  # DeepSeek R1 for reasoning
        
        # Content length considerations
        if content_length > 50000:
            return self.model_options["claude_sonnet"]  # Large context handling
        
        # Cost optimization for low priority
        if query.priority == "low":
            return self.model_options["llama_8b"]  # Most cost-effective
        
        # Default balanced choice
        return self.model_options["llama_70b"]  # Good balance
    
    def _get_fallback_models(self, primary_model: str) -> List[str]:
        """Get fallback model chain for reliability."""
        fallback_chains = {
            "anthropic/claude-3-opus": [self.model_options["claude_sonnet"], self.model_options["gpt4o"]],
            "anthropic/claude-3.5-sonnet": [self.model_options["gpt4o"], self.model_options["llama_70b"]],
            "openai/gpt-4o": [self.model_options["claude_sonnet"], self.model_options["llama_70b"]],
            "meta-llama/llama-3.1-405b-instruct": [self.model_options["llama_70b"], self.model_options["mixtral_8x22b"]],
            "deepseek/deepseek-coder": [self.model_options["codestral"], self.model_options["claude_sonnet"]],
            "deepseek/deepseek-r1": [self.model_options["claude_sonnet"], self.model_options["llama_405b"]]
        }
        return fallback_chains.get(primary_model, [self.model_options["llama_70b"], self.model_options["llama_8b"]])
    
    @retry_api_call(max_attempts=5, timeout=120)
    async def generate_response(self, query: ExpertQuery) -> ExpertResponse:
        """Generate response using OpenRouter model selection."""
        if not self.client:
            raise ValueError("OpenRouter API key not configured")
        
        response = ExpertResponse(
            query_id=query.id,
            expert_type=ExpertType.SUPERGROK,  # Using existing enum value
            status=ResponseStatus.IN_PROGRESS
        )
        
        # Select optimal model
        selected_model = self._select_optimal_model(query)
        fallback_models = self._get_fallback_models(selected_model)
        
        models_to_try = [selected_model] + fallback_models
        
        for model_name in models_to_try:
            try:
                logger.info(f"Attempting OpenRouter model: {model_name}")
                
                # Create optimized messages
                messages = self._create_messages(query, model_name)
                
                # Generate response
                completion = await self.client.chat.completions.create(
                    model=model_name,
                    messages=messages,
                    temperature=self._get_temperature(model_name, query),
                    max_tokens=self._get_max_tokens(model_name, query),
                    top_p=0.95,
                    extra_headers={
                        "HTTP-Referer": "https://circle-of-experts.ai",
                        "X-Title": "Circle of Experts"
                    }
                )
                
                # Extract content
                content = completion.choices[0].message.content
                
                response.content = content
                response.confidence = self._calculate_confidence(content, model_name, query)
                response.recommendations = self._extract_recommendations(content)
                response.code_snippets = self._extract_code_snippets(content)
                
                # Add metadata
                response.metadata = {
                    "selected_model": model_name,
                    "was_fallback": model_name != selected_model,
                    "model_capabilities": self.model_capabilities.get(model_name, {}),
                    "usage": {
                        "prompt_tokens": completion.usage.prompt_tokens if completion.usage else 0,
                        "completion_tokens": completion.usage.completion_tokens if completion.usage else 0,
                        "total_tokens": completion.usage.total_tokens if completion.usage else 0
                    },
                    "finish_reason": completion.choices[0].finish_reason,
                    "provider": "openrouter"
                }
                
                response.mark_completed()
                logger.info(f"✅ OpenRouter success with {model_name}")
                return response
                
            except Exception as e:
                logger.warning(f"OpenRouter model {model_name} failed: {e}")
                if model_name == models_to_try[-1]:  # Last model in chain
                    response.mark_failed(f"All OpenRouter models failed. Last error: {str(e)}")
                    return response
                continue
        
        return response
    
    def _create_messages(self, query: ExpertQuery, model_name: str) -> List[Dict[str, str]]:
        """Create optimized messages for specific model."""
        # Base system message
        system_message = """You are an expert consultant in the Circle of Experts system.
Provide detailed, actionable analysis with:
- Clear reasoning and step-by-step explanations
- Specific code examples when relevant
- Best practices and industry standards
- Honest assessment of trade-offs and limitations

Format your response with clear sections and use markdown for structure."""
        
        # Model-specific optimizations
        if "claude" in model_name:
            system_message += "

Use your analytical capabilities for thorough, nuanced responses."
        elif "deepseek" in model_name and "coder" in model_name:
            system_message += "

Focus on code quality, optimization, and technical implementation details."
        elif "deepseek-r1" in model_name:
            system_message += "

Show your reasoning process step-by-step before providing conclusions."
        elif "llama" in model_name:
            system_message += "

Provide comprehensive analysis with practical recommendations."
        
        # Query-specific instructions
        if query.query_type == "review":
            system_message += "

Focus on: Code quality, potential bugs, performance, and maintainability."
        elif query.query_type == "optimization":
            system_message += "

Focus on: Performance improvements, resource efficiency, and scalability."
        elif query.query_type == "architectural":
            system_message += "

Focus on: System design principles, patterns, trade-offs, and maintainability."
        
        user_message = query.content
        if query.context:
            user_message += f"\n\nContext: {json.dumps(query.context)}"\n        if query.constraints:\n            user_message += f"\n\nConstraints: {', '.join(query.constraints)}"\n\n        return [\n            {"role": "system", "content": system_message},\n            {"role": "user", "content": user_message}\n        ]\n\n    def _get_temperature(self, model_name: str, query: ExpertQuery) -> float:\n        """Get optimal temperature for model and query."""\n        base_temp = 0.7\n\n        # Lower temperature for reasoning models\n        if "deepseek-r1" in model_name or query.query_type == "review":\n            return 0.3\n        elif "coder" in model_name or query.query_type == "optimization":\n            return 0.5\n        elif query.priority == "critical":\n            return 0.6\n\n        return base_temp\n\n    def _get_max_tokens(self, model_name: str, query: ExpertQuery) -> int:\n        """Get optimal max tokens for model and query."""\n        base_tokens = 4096\n\n        # Higher token limits for complex queries\n        if query.priority == "critical":\n            base_tokens = 8192\n        elif query.query_type == "architectural":\n            base_tokens = 6144\n\n        # Model-specific adjustments\n        if "405b" in model_name or "claude-3-opus" in model_name:\n            return min(base_tokens * 2, 16384)  # These models can handle more\n        elif "8b" in model_name:\n            return min(base_tokens // 2, 2048)  # Smaller models\n\n        return base_tokens\n\n    def _calculate_confidence(self, content: str, model_name: str, query: ExpertQuery) -> float:\n        """Calculate confidence based on model capabilities and response quality."""\n        # Base confidence from model capabilities\n        model_caps = self.model_capabilities.get(model_name, {})\n        base_confidence = model_caps.get("reasoning", 7) / 10.0\n\n        # Adjust based on response quality\n        quality_indicators = 0\n        if len(content) > 500:\n            quality_indicators += 0.05\n        if "```" in content:\n            quality_indicators += 0.05\n        if any(word in content.lower() for word in ["analysis", "recommendation", "solution"]):\n            quality_indicators += 0.03\n\n        # Model-specific bonuses\n        if "claude" in model_name and len(content) > 1000:\n            quality_indicators += 0.05  # Claude excels at detailed responses\n        elif "deepseek-coder" in model_name and "```" in content:\n            quality_indicators += 0.07  # Coding specialist bonus\n        elif "deepseek-r1" in model_name and any(word in content.lower() for word in ["step", "reasoning", "because"]):\n            quality_indicators += 0.08  # Reasoning model bonus\n\n        return min(0.98, base_confidence + quality_indicators)\n\n    def _extract_recommendations(self, content: str) -> List[str]:\n        """Extract recommendations from OpenRouter response."""\n        recommendations = []\n        lines = content.split('\n')\n\n        in_recommendations = False\n        for line in lines:\n            line = line.strip()\n\n            if any(marker in line.lower() for marker in ["recommend", "suggestion", "advice", "should consider"]):\n                in_recommendations = True\n                continue\n\n            if in_recommendations and line:\n                if line.startswith(('-', '*', '•', '1.', '2.', '3.', '4.', '5.')):\n                    rec = line.lstrip('-*•1234567890. ')\n                    if rec and len(rec) > 10:\n                        recommendations.append(rec)\n                elif line.startswith('#') or line == "":\n                    in_recommendations = False\n\n        return recommendations[:10]\n\n    def _extract_code_snippets(self, content: str) -> List[Dict[str, str]]:\n        """Extract code snippets from response."""\n        snippets = []\n        parts = content.split('```')\n\n        for i in range(1, len(parts), 2):\n            if i < len(parts):\n                lines = parts[i].split('\n', 1)\n                language = lines[0].strip() if lines else ""\n                code = lines[1] if len(lines) > 1 else ""\n\n                if code.strip():\n                    snippets.append({\n                        "language": language or "text",\n                        "code": code.strip(),\n                        "title": f"OpenRouter Code Example {len(snippets) + 1}",\n                        "description": f"Generated via OpenRouter"\n                    })\n\n        return snippets\n\n    async def health_check(self) -> bool:\n        """Check OpenRouter API availability."""\n        if not self.client:\n            return False\n\n        try:\n            # Test with a fast, reliable model\n            completion = await self.client.chat.completions.create(\n                model=self.model_options["llama_8b"],\n                messages=[{"role": "user", "content": "Hi"}],\n                max_tokens=5,\n                extra_headers={\n                    "HTTP-Referer": "https://circle-of-experts.ai",\n                    "X-Title": "Circle of Experts Health Check"\n                }\n            )\n            return True\n        except Exception as e:\n            logger.error(f"OpenRouter health check failed: {e}")\n            return False