"""
Commercial expert clients for GPT-4, Gemini, and other paid APIs.
"""

from __future__ import annotations
import os
import asyncio
from typing import Optional, Dict, Any, List
import json
import logging
from datetime import datetime

from openai import AsyncOpenAI
import google.generativeai as genai
import aiohttp

from ..models.response import ExpertResponse, ExpertType, ResponseStatus
from ..models.query import ExpertQuery
from ..utils.retry import with_retry, RetryPolicy
from .claude_expert import BaseExpertClient

logger = logging.getLogger(__name__)


class GPT4ExpertClient(BaseExpertClient):
    """
    OpenAI GPT-4 expert client.
    
    Supports GPT-4, GPT-4-Turbo, and GPT-3.5-Turbo models.
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gpt-4-turbo-preview",
        organization: Optional[str] = None
    ):
        """
        Initialize GPT-4 client.
        
        Args:
            api_key: OpenAI API key
            model: Model to use (gpt-4, gpt-4-turbo-preview, gpt-3.5-turbo)
            organization: Optional organization ID
        """
        super().__init__(api_key or os.getenv("OPENAI_API_KEY"))
        self.model = model
        self.organization = organization or os.getenv("OPENAI_ORGANIZATION")
        self.client = AsyncOpenAI(
            api_key=self.api_key,
            organization=self.organization
        ) if self.api_key else None
        
        # Model selection based on requirements
        self.model_selection = {
            "high_quality": "gpt-4-turbo-preview",
            "balanced": "gpt-4",
            "fast": "gpt-3.5-turbo-16k"
        }
    
    def _select_model_for_query(self, query: ExpertQuery) -> str:
        """Select appropriate GPT model based on query."""
        if query.priority == "critical" or query.query_type == "architectural":
            return self.model_selection["high_quality"]
        elif query.priority == "low" or len(query.content) < 500:
            return self.model_selection["fast"]
        else:
            return self.model_selection["balanced"]
    
    def _create_messages(self, query: ExpertQuery) -> List[Dict[str, str]]:
        """Create optimized messages for GPT-4."""
        system_message = """You are an expert consultant in the Circle of Experts system.
Provide detailed, actionable analysis with:
- Clear reasoning and explanations
- Specific code examples when relevant
- Best practices and industry standards
- Honest assessment of trade-offs and limitations

Format your response with clear sections and use markdown for structure."""
        
        # Add query-specific instructions
        if query.query_type == "review":
            system_message += "\n\nFocus on: Code quality, potential bugs, performance, and maintainability."
        elif query.query_type == "optimization":
            system_message += "\n\nFocus on: Performance improvements, resource efficiency, and scalability."
        
        user_message = query.content
        if query.context:
            user_message += f"\n\nContext: {json.dumps(query.context)}"
        if query.constraints:
            user_message += f"\n\nConstraints: {', '.join(query.constraints)}"
        
        return [
            {"role": "system", "content": system_message},
            {"role": "user", "content": user_message}
        ]
    
    @with_retry(RetryPolicy(max_attempts=3, backoff_factor=2.0))
    async def generate_response(self, query: ExpertQuery) -> ExpertResponse:
        """Generate response using GPT-4."""
        if not self.client:
            raise ValueError("OpenAI API key not configured")
        
        response = ExpertResponse(
            query_id=query.id,
            expert_type=ExpertType.GPT4,
            status=ResponseStatus.IN_PROGRESS
        )
        
        try:
            # Select model
            model = self._select_model_for_query(query)
            logger.info(f"Using GPT model: {model}")
            
            # Generate response
            completion = await self.client.chat.completions.create(
                model=model,
                messages=self._create_messages(query),
                temperature=0.7,
                max_tokens=4096,
                top_p=0.95,
                presence_penalty=0.1,
                frequency_penalty=0.1
            )
            
            # Extract content
            content = completion.choices[0].message.content
            
            response.content = content
            response.confidence = self._calculate_confidence(content, completion)
            response.recommendations = self._extract_recommendations(content)
            response.code_snippets = self._extract_code_snippets(content)
            
            # Add metadata
            response.metadata = {
                "model": model,
                "usage": {
                    "prompt_tokens": completion.usage.prompt_tokens,
                    "completion_tokens": completion.usage.completion_tokens,
                    "total_tokens": completion.usage.total_tokens
                },
                "finish_reason": completion.choices[0].finish_reason
            }
            
            response.mark_completed()
            
        except Exception as e:
            logger.error(f"GPT-4 generation failed: {e}")
            response.mark_failed(str(e))
        
        return response
    
    async def health_check(self) -> bool:
        """Check OpenAI API availability."""
        if not self.client:
            return False
        
        try:
            # Simple test
            await self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": "Hi"}],
                max_tokens=5
            )
            return True
        except Exception as e:
            logger.error(f"GPT-4 health check failed: {e}")
            return False
    
    def _calculate_confidence(self, content: str, completion) -> float:
        """Calculate confidence based on response quality."""
        confidence = 0.8  # Base confidence for GPT-4
        
        # Adjust based on finish reason
        if completion.choices[0].finish_reason == "stop":
            confidence += 0.05
        
        # Adjust based on content quality
        if len(content) > 1000:
            confidence += 0.05
        if "```" in content:
            confidence += 0.05
        
        return min(1.0, confidence)
    
    def _extract_recommendations(self, content: str) -> List[str]:
        """Extract recommendations from GPT-4 response."""
        recommendations = []
        lines = content.split('\n')
        
        in_recommendations = False
        for line in lines:
            line = line.strip()
            
            if any(marker in line.lower() for marker in ["recommend", "suggestion", "advice"]):
                in_recommendations = True
            
            if in_recommendations and line.startswith(('-', '*', '•', '1.', '2.')):
                rec = line.lstrip('-*•1234567890. ')
                if rec and len(rec) > 10:
                    recommendations.append(rec)
            
            if in_recommendations and line == "":
                in_recommendations = False
        
        return recommendations[:10]
    
    def _extract_code_snippets(self, content: str) -> List[Dict[str, str]]:
        """Extract code snippets from response."""
        snippets = []
        parts = content.split('```')
        
        for i in range(1, len(parts), 2):
            if i < len(parts):
                lines = parts[i].split('\n', 1)
                language = lines[0].strip() if lines else ""
                code = lines[1] if len(lines) > 1 else ""
                
                if code.strip():
                    snippets.append({
                        "language": language or "text",
                        "code": code.strip(),
                        "title": f"Code Example {len(snippets) + 1}"
                    })
        
        return snippets


class GeminiExpertClient(BaseExpertClient):
    """
    Advanced Google Gemini expert client with intelligent model selection.
    
    Supports multiple Gemini models with smart routing based on query characteristics.
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gemini-1.5-flash"
    ):
        """Initialize advanced Gemini client."""
        super().__init__(api_key or os.getenv("GOOGLE_GEMINI_API_KEY"))
        self.default_model = model
        
        # Advanced model selection matrix
        self.model_options = {
            "experimental": "gemini-2.0-flash-exp",
            "thinking": "gemini-2.0-flash-thinking-exp", 
            "high_quality": "gemini-2.0-flash",
            "balanced": "gemini-1.5-flash",
            "large_context": "gemini-1.5-pro",
            "cost_optimized": "gemini-1.5-flash-8b",
            "default": "gemini-1.5-flash"
        }
        
        # Model capabilities for intelligent selection
        self.model_capabilities = {
            "gemini-2.0-flash-exp": {"reasoning": 10, "speed": 9, "cost": 7, "reliability": 7},
            "gemini-2.0-flash-thinking-exp": {"reasoning": 10, "speed": 8, "cost": 7, "reliability": 7},
            "gemini-2.0-flash": {"reasoning": 9, "speed": 9, "cost": 8, "reliability": 9},
            "gemini-1.5-pro": {"reasoning": 9, "speed": 7, "cost": 6, "reliability": 10},
            "gemini-1.5-flash": {"reasoning": 8, "speed": 10, "cost": 10, "reliability": 9},
            "gemini-1.5-flash-8b": {"reasoning": 7, "speed": 10, "cost": 10, "reliability": 9}
        }
        
        if self.api_key:
            genai.configure(api_key=self.api_key)
            # Initialize with default model, will be selected dynamically per query
            self.client = None
        else:
            self.client = None
    
    def _select_optimal_model(self, query: ExpertQuery) -> str:
        """Select optimal Gemini model based on query characteristics."""
        content_length = len(query.content)
        
        # Priority-based selection
        if query.priority == "critical":
            return self.model_options["experimental"]
        
        # Query type-based selection
        if query.query_type == "architectural":
            return self.model_options["thinking"]  # Reasoning transparency
        elif query.query_type == "review" and content_length > 10000:
            return self.model_options["large_context"]  # Large context for code review
        elif query.query_type == "optimization":
            return self.model_options["high_quality"]  # Latest capabilities
        
        # Content length considerations
        if content_length > 50000:
            return self.model_options["large_context"]  # 2M context window
        
        # Cost optimization for low priority
        if query.priority == "low":
            return self.model_options["cost_optimized"]
        
        # Default balanced choice
        return self.model_options["balanced"]
    
    def _get_fallback_models(self, primary_model: str) -> List[str]:
        """Get fallback model chain for reliability."""
        fallback_chains = {
            "gemini-2.0-flash-exp": ["gemini-2.0-flash", "gemini-1.5-flash"],
            "gemini-2.0-flash-thinking-exp": ["gemini-1.5-pro", "gemini-1.5-flash"],
            "gemini-2.0-flash": ["gemini-1.5-flash", "gemini-1.5-flash-8b"],
            "gemini-1.5-pro": ["gemini-2.0-flash", "gemini-1.5-flash"],
            "gemini-1.5-flash": ["gemini-1.5-flash-8b"],
            "gemini-1.5-flash-8b": ["gemini-1.5-flash"]
        }
        return fallback_chains.get(primary_model, ["gemini-1.5-flash"])
    
    @with_retry(RetryPolicy(max_attempts=3, backoff_factor=2.0))
    async def generate_response(self, query: ExpertQuery) -> ExpertResponse:
        """Generate response using advanced Gemini model selection."""
        if not self.api_key:
            raise ValueError("Gemini API key not configured")
        
        response = ExpertResponse(
            query_id=query.id,
            expert_type=ExpertType.GEMINI,
            status=ResponseStatus.IN_PROGRESS
        )
        
        # Select optimal model
        selected_model = self._select_optimal_model(query)
        fallback_models = self._get_fallback_models(selected_model)
        
        models_to_try = [selected_model] + fallback_models
        
        for model_name in models_to_try:
            try:
                logger.info(f"Attempting Gemini model: {model_name}")
                
                # Create model instance
                model = genai.GenerativeModel(model_name)
                
                # Create prompt
                prompt = self._create_prompt(query)
                
                # Configure generation parameters based on model
                generation_config = self._get_generation_config(model_name, query)
                
                # Generate response
                result = await asyncio.to_thread(
                    model.generate_content,
                    prompt,
                    generation_config=generation_config
                )
                
                # Extract content
                content = result.text
                
                response.content = content
                response.confidence = self._calculate_confidence(content, model_name, query)
                response.recommendations = self._extract_recommendations(content)
                response.code_snippets = self._extract_code_snippets(content)
                
                # Add metadata with model selection info
                response.metadata = {
                    "selected_model": model_name,
                    "was_fallback": model_name != selected_model,
                    "model_capabilities": self.model_capabilities.get(model_name, {}),
                    "prompt_token_count": getattr(result.usage_metadata, 'prompt_token_count', 0),
                    "candidates_token_count": getattr(result.usage_metadata, 'candidates_token_count', 0),
                    "total_token_count": getattr(result.usage_metadata, 'total_token_count', 0)
                }
                
                response.mark_completed()
                logger.info(f"✅ Gemini success with {model_name}")
                return response
                
            except Exception as e:
                logger.warning(f"Gemini model {model_name} failed: {e}")
                if model_name == models_to_try[-1]:  # Last model in chain
                    response.mark_failed(f"All Gemini models failed. Last error: {str(e)}")
                    return response
                continue
        
        return response
    
    def _get_generation_config(self, model_name: str, query: ExpertQuery) -> Dict[str, Any]:
        """Get optimized generation config based on model and query."""
        base_config = {
            "temperature": 0.7,
            "top_p": 0.95,
            "max_output_tokens": 4096,
        }
        
        # Adjust for thinking models (more structured output)
        if "thinking" in model_name:
            base_config["temperature"] = 0.5  # More focused
        
        # Adjust for experimental models (allow creativity)
        elif "exp" in model_name:
            base_config["temperature"] = 0.8
            
        # Adjust for critical queries (more output)
        if query.priority == "critical":
            base_config["max_output_tokens"] = 8192
            
        return base_config
    
    def _calculate_confidence(self, content: str, model_name: str, query: ExpertQuery) -> float:
        """Calculate confidence based on model capabilities and response quality."""
        # Base confidence from model capabilities
        model_caps = self.model_capabilities.get(model_name, {})
        base_confidence = model_caps.get("reasoning", 8) / 10.0
        
        # Adjust based on response quality indicators
        quality_indicators = 0
        if len(content) > 500:
            quality_indicators += 0.05
        if "```" in content:  # Contains code examples
            quality_indicators += 0.05
        if any(word in content.lower() for word in ["analysis", "recommendation", "solution"]):
            quality_indicators += 0.03
        if "thinking" in model_name and any(word in content.lower() for word in ["reasoning", "step", "therefore"]):
            quality_indicators += 0.07  # Bonus for thinking models showing reasoning
            
        return min(0.98, base_confidence + quality_indicators)
    
    async def health_check(self) -> bool:
        """Check Gemini API availability with advanced model support."""
        if not self.api_key:
            return False
        
        try:
            # Test with default reliable model
            test_model = genai.GenerativeModel(self.model_options["balanced"])
            
            # Simple test
            await asyncio.to_thread(
                test_model.generate_content,
                "Hello",
                generation_config={"max_output_tokens": 10}
            )
            return True
        except Exception as e:
            logger.error(f"Gemini health check failed: {e}")
            return False
    
    def _create_prompt(self, query: ExpertQuery) -> str:
        """Create optimized prompt for Gemini."""
        prompt = f"""As an expert consultant, provide a detailed analysis for this query:

Query Type: {query.query_type}
Priority: {query.priority}

{query.content}

Provide:
1. Comprehensive analysis
2. Specific recommendations with examples
3. Code examples where applicable
4. Potential limitations or considerations

Use clear formatting with sections and markdown."""
        
        if query.context:
            prompt += f"\n\nContext: {json.dumps(query.context)}"
        
        return prompt
    
    def _extract_recommendations(self, content: str) -> List[str]:
        """Extract recommendations from Gemini response."""
        recommendations = []
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            if line.startswith(('-', '*', '•', '1.', '2.', '3.')):
                if any(word in content[max(0, content.find(line)-100):content.find(line)].lower() 
                       for word in ["recommend", "suggest", "advice"]):
                    rec = line.lstrip('-*•1234567890. ')
                    if rec:
                        recommendations.append(rec)
        
        return recommendations[:10]
    
    def _extract_code_snippets(self, content: str) -> List[Dict[str, str]]:
        """Extract code snippets from response."""
        snippets = []
        
        # Find code blocks
        import re
        code_blocks = re.findall(r'```(\w*)\n(.*?)\n```', content, re.DOTALL)
        
        for i, (language, code) in enumerate(code_blocks):
            if code.strip():
                snippets.append({
                    "language": language or "text",
                    "code": code.strip(),
                    "title": f"Example {i + 1}"
                })
        
        return snippets


class GroqExpertClient(BaseExpertClient):
    """
    Groq expert client for fast inference.
    
    Supports various open models with high-speed inference.
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "mixtral-8x7b-32768"
    ):
        """Initialize Groq client."""
        super().__init__(api_key or os.getenv("GROQ_API_KEY"))
        self.model = model
        self.base_url = "https://api.groq.com/openai/v1"
    
    @with_retry(RetryPolicy(max_attempts=3, backoff_factor=2.0))
    async def generate_response(self, query: ExpertQuery) -> ExpertResponse:
        """Generate response using Groq."""
        if not self.api_key:
            raise ValueError("Groq API key not configured")
        
        response = ExpertResponse(
            query_id=query.id,
            expert_type=ExpertType.SUPERGROK,
            status=ResponseStatus.IN_PROGRESS
        )
        
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            messages = [
                {
                    "role": "system",
                    "content": "You are an expert technical consultant providing detailed analysis."
                },
                {
                    "role": "user",
                    "content": query.content
                }
            ]
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json={
                        "model": self.model,
                        "messages": messages,
                        "temperature": 0.7,
                        "max_tokens": 4096
                    }
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        content = data["choices"][0]["message"]["content"]
                        
                        response.content = content
                        response.confidence = 0.88  # High confidence for Groq
                        response.metadata = {
                            "model": self.model,
                            "usage": data.get("usage", {})
                        }
                        
                        response.mark_completed()
                    else:
                        error = await resp.text()
                        raise RuntimeError(f"Groq API error: {error}")
                        
        except Exception as e:
            logger.error(f"Groq generation failed: {e}")
            response.mark_failed(str(e))
        
        return response
    
    async def health_check(self) -> bool:
        """Check Groq API availability."""
        if not self.api_key:
            return False
        
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}/models",
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    return resp.status == 200
        except Exception:
            return False


class DeepSeekExpertClient(BaseExpertClient):
    """
    DeepSeek expert client for high-quality reasoning tasks.
    
    Uses DeepSeek's reasoning models for complex analysis.
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "deepseek-chat"
    ):
        """Initialize DeepSeek client."""
        super().__init__(api_key or os.getenv("DEEPSEEK_API_KEY"))
        self.model = model
        self.base_url = "https://api.deepseek.com"
        
        # Available models
        self.model_selection = {
            "reasoning": "deepseek-reasoner",
            "chat": "deepseek-chat",
            "coder": "deepseek-coder"
        }
    
    def _select_model_for_query(self, query: ExpertQuery) -> str:
        """Select appropriate DeepSeek model based on query."""
        if query.query_type in ["architectural", "optimization"] or query.priority == "critical":
            return self.model_selection["reasoning"]
        elif "code" in query.content.lower() or query.query_type == "review":
            return self.model_selection["coder"]
        else:
            return self.model_selection["chat"]
    
    def _create_messages(self, query: ExpertQuery) -> List[Dict[str, str]]:
        """Create optimized messages for DeepSeek."""
        system_message = """You are an expert consultant in the Circle of Experts system with advanced reasoning capabilities.
Provide thorough, well-reasoned analysis with:
- Step-by-step logical reasoning
- Clear explanations of your thought process
- Specific, actionable recommendations
- Code examples with detailed explanations
- Consideration of edge cases and limitations

Use clear structure with headings and markdown formatting."""
        
        # Add query-specific instructions
        if query.query_type == "review":
            system_message += "\n\nFocus on: Code quality analysis, potential issues, performance implications, and improvement suggestions."
        elif query.query_type == "optimization":
            system_message += "\n\nFocus on: Performance bottlenecks, efficiency improvements, scalability considerations, and optimization strategies."
        elif query.query_type == "architectural":
            system_message += "\n\nFocus on: System design principles, architecture patterns, trade-offs, and long-term maintainability."
        
        user_message = query.content
        if query.context:
            user_message += f"\n\nContext: {json.dumps(query.context)}"
        if query.constraints:
            user_message += f"\n\nConstraints: {', '.join(query.constraints)}"
        
        return [
            {"role": "system", "content": system_message},
            {"role": "user", "content": user_message}
        ]
    
    @with_retry(RetryPolicy(max_attempts=3, backoff_factor=2.0))
    async def generate_response(self, query: ExpertQuery) -> ExpertResponse:
        """Generate response using DeepSeek."""
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
            
            async with aiohttp.ClientSession() as session:
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
                    timeout=aiohttp.ClientTimeout(total=300)
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
    
    async def health_check(self) -> bool:
        """Check DeepSeek API availability."""
        if not self.api_key:
            return False
        
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json={
                        "model": "deepseek-chat",
                        "messages": [{"role": "user", "content": "Hi"}],
                        "max_tokens": 5
                    },
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    return resp.status == 200
        except Exception as e:
            logger.error(f"DeepSeek health check failed: {e}")
            return False
    
    def _calculate_confidence(self, content: str, completion_data) -> float:
        """Calculate confidence based on response quality."""
        confidence = 0.9  # High base confidence for DeepSeek reasoning models
        
        # Adjust based on finish reason
        finish_reason = completion_data["choices"][0].get("finish_reason")
        if finish_reason == "stop":
            confidence += 0.05
        
        # Adjust based on content quality indicators
        if len(content) > 1000:
            confidence += 0.02
        if "```" in content:  # Contains code examples
            confidence += 0.02
        if any(word in content.lower() for word in ["reasoning", "analysis", "step"]):
            confidence += 0.01
        
        return min(1.0, confidence)
    
    def _extract_recommendations(self, content: str) -> List[str]:
        """Extract recommendations from DeepSeek response."""
        recommendations = []
        lines = content.split('\n')
        
        # Look for common recommendation patterns
        in_recommendations = False
        for line in lines:
            line = line.strip()
            
            # Start of recommendations section
            if any(marker in line.lower() for marker in [
                "recommend", "suggestion", "advice", "should consider",
                "next steps", "action items"
            ]):
                in_recommendations = True
                continue
            
            # Extract bullet points and numbered items
            if in_recommendations and line:
                if line.startswith(('-', '*', '•', '1.', '2.', '3.', '4.', '5.')):
                    rec = line.lstrip('-*•1234567890. ')
                    if rec and len(rec) > 15:  # Filter out short items
                        recommendations.append(rec)
                elif line.startswith('#') or line == "":
                    in_recommendations = False
        
        return recommendations[:10]  # Limit to top 10
    
    def _extract_code_snippets(self, content: str) -> List[Dict[str, str]]:
        """Extract code snippets from DeepSeek response."""
        snippets = []
        parts = content.split('```')
        
        for i in range(1, len(parts), 2):
            if i < len(parts):
                lines = parts[i].split('\n', 1)
                language = lines[0].strip() if lines else ""
                code = lines[1] if len(lines) > 1 else ""
                
                if code.strip():
                    snippets.append({
                        "language": language or "text",
                        "code": code.strip(),
                        "title": f"DeepSeek Code Example {len(snippets) + 1}",
                        "description": f"Generated by DeepSeek {self.model}"
                    })
        
        return snippets
