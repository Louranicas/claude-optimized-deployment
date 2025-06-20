"""
Expert client implementations for various AI models.

Optimized for Claude Code tool calls with best practices from Anthropic docs.
"""

from __future__ import annotations
import os
import asyncio
import aiohttp
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
import json
import logging
from datetime import datetime

from anthropic import AsyncAnthropic
from openai import AsyncOpenAI
import google.generativeai as genai

from src.circle_of_experts.models.response import ExpertResponse, ExpertType, ResponseStatus
from src.circle_of_experts.models.query import ExpertQuery
from src.core.retry import retry_api_call, RetryConfig, RetryStrategy
from src.core.circuit_breaker import circuit_breaker, CircuitBreakerConfig, get_circuit_breaker_manager
from src.core.ssrf_protection import SSRFProtectedSession, get_ssrf_protector, STRICT_SSRF_CONFIG

logger = logging.getLogger(__name__)


class BaseExpertClient(ABC):
    """Base class for all expert AI clients with SSRF protection."""
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize the expert client."""
        self.api_key = api_key
        self._session: Optional[aiohttp.ClientSession] = None
        self._ssrf_session: Optional[SSRFProtectedSession] = None
        # Initialize SSRF protector with strict config for AI APIs
        from src.core.ssrf_protection import SSRFProtector
        self._ssrf_protector = SSRFProtector(**STRICT_SSRF_CONFIG)
    
    @abstractmethod
    async def generate_response(self, query: ExpertQuery) -> ExpertResponse:
        """Generate a response to the query."""
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the expert is available."""
        pass
    
    async def __aenter__(self):
        """Enter async context with SSRF-protected session."""
        self._ssrf_session = SSRFProtectedSession(self._ssrf_protector)
        await self._ssrf_session.__aenter__()
        # Keep regular session for backward compatibility
        self._session = self._ssrf_session.session
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit async context."""
        if self._ssrf_session:
            await self._ssrf_session.__aexit__(exc_type, exc_val, exc_tb)
            self._ssrf_session = None
            self._session = None
    
    async def _make_safe_request(self, method: str, url: str, **kwargs):
        """Make HTTP request with SSRF protection."""
        if not self._ssrf_session:
            raise RuntimeError("Session not initialized. Use async context manager.")
        
        # Validate URL before making request
        validation = self._ssrf_protector.validate_url(url)
        if not validation.is_safe:
            logger.error(f"SSRF protection blocked request to {url}: {validation.reason}")
            raise Exception(f"SSRF protection: {validation.reason}")
        
        # Log suspicious URLs
        if validation.threat_level.value == "suspicious":
            logger.warning(f"Suspicious URL detected: {url} - {validation.reason}")
        
        # Make the request
        return await self._ssrf_session._validate_and_request(method, url, **kwargs)


class ClaudeExpertClient(BaseExpertClient):
    """
    Anthropic Claude expert client.
    
    Optimized based on https://docs.anthropic.com/en/home best practices:
    - Uses Claude 3 models with appropriate selection
    - Implements proper prompting techniques
    - Handles tool use capabilities
    - Follows rate limiting best practices
    """
    
    def __init__(self, api_key: Optional[str] = None, model: str = "claude-3-opus-20240229"):
        """
        Initialize Claude client.
        
        Args:
            api_key: Anthropic API key (or from env ANTHROPIC_API_KEY)
            model: Model to use (opus, sonnet, or haiku)
        """
        super().__init__(api_key or os.getenv("ANTHROPIC_API_KEY"))
        self.model = model
        self.client = AsyncAnthropic(api_key=self.api_key) if self.api_key else None
        
        # Model selection based on query complexity
        self.model_selection = {
            "high_complexity": "claude-3-opus-20240229",
            "medium_complexity": "claude-3-sonnet-20240229",
            "low_complexity": "claude-3-haiku-20240307"
        }
    
    def _determine_model_for_query(self, query: ExpertQuery) -> str:
        """Select appropriate model based on query characteristics."""
        # High complexity: architectural, optimization queries
        if query.query_type in ["architectural", "optimization"]:
            return self.model_selection["high_complexity"]
        
        # Low complexity: simple reviews or general queries
        elif query.query_type in ["general", "review"] and len(query.content) < 500:
            return self.model_selection["low_complexity"]
        
        # Default to medium complexity
        return self.model_selection["medium_complexity"]
    
    def _create_system_prompt(self, query: ExpertQuery) -> str:
        """
        Create optimized system prompt following Anthropic best practices.
        
        Based on: https://docs.anthropic.com/en/docs/system-prompts
        """
        base_prompt = """You are an expert consultant in the Circle of Experts system. 
Your role is to provide thoughtful, detailed analysis and recommendations.

Key responsibilities:
1. Analyze queries thoroughly and provide actionable insights
2. Include specific code examples when relevant
3. Consider multiple perspectives and trade-offs
4. Cite best practices and industry standards
5. Be honest about limitations and uncertainties

Response format:
- Start with a brief summary
- Provide detailed analysis
- Include code examples in markdown blocks
- List specific recommendations
- Note any limitations or caveats
"""
        
        # Add query-specific context
        if query.query_type == "review":
            base_prompt += "\n\nFocus on code quality, best practices, and potential improvements."
        elif query.query_type == "architectural":
            base_prompt += "\n\nConsider scalability, maintainability, and system design principles."
        elif query.query_type == "optimization":
            base_prompt += "\n\nPrioritize performance metrics and efficiency improvements."
        
        return base_prompt
    
    async def generate_response(self, query: ExpertQuery) -> ExpertResponse:
        """Generate response using Claude."""
        if not self.client:
            raise ValueError("Claude API key not configured")
        
        start_time = datetime.utcnow()
        response = ExpertResponse(
            query_id=query.id,
            expert_type=ExpertType.CLAUDE,
            status=ResponseStatus.IN_PROGRESS
        )
        
        try:
            # Select appropriate model
            model = self._determine_model_for_query(query)
            logger.info(f"Using Claude model: {model} for query type: {query.query_type}")
            
            # Create messages following Anthropic format
            messages = [
                {
                    "role": "user",
                    "content": f"{query.content}\n\nContext: {json.dumps(query.context)}"
                }
            ]
            
            # Create circuit breaker for this expert if not exists
            manager = get_circuit_breaker_manager()
            breaker = await manager.get_or_create(
                f"claude_expert_{self.model}",
                CircuitBreakerConfig(
                    failure_threshold=3,
                    timeout=60,
                    failure_rate_threshold=0.5,
                    minimum_calls=5,
                    fallback=lambda: self._create_fallback_response(query)
                )
            )
            
            # Generate response with circuit breaker protection
            claude_response = await breaker.call(
                self._api_call_with_retry,
                model,
                messages,
                self._create_system_prompt(query)
            )
            
            # Extract content
            content = claude_response.content[0].text if claude_response.content else ""
            
            # Parse structured elements from response
            response.content = content
            response.confidence = self._calculate_confidence(content, query)
            response.recommendations = self._extract_recommendations(content)
            response.code_snippets = self._extract_code_snippets(content)
            response.limitations = self._extract_limitations(content)
            
            # Add Claude-specific metadata
            response.metadata = {
                "model": model,
                "usage": {
                    "input_tokens": claude_response.usage.input_tokens,
                    "output_tokens": claude_response.usage.output_tokens
                },
                "stop_reason": claude_response.stop_reason
            }
            
            response.mark_completed()
            
        except Exception as e:
            logger.error(f"Claude generation failed: {e}")
            response.mark_failed(str(e))
        
        return response
    
    async def health_check(self) -> bool:
        """Check Claude API availability."""
        if not self.client:
            return False
        
        try:
            # Simple test message
            await self.client.messages.create(
                model="claude-3-haiku-20240307",  # Use cheapest model
                messages=[{"role": "user", "content": "Hello"}],
                max_tokens=10
            )
            return True
        except Exception as e:
            logger.error(f"Claude health check failed: {e}")
            return False
    
    def _calculate_confidence(self, content: str, query: ExpertQuery) -> float:
        """Calculate confidence score based on response characteristics."""
        confidence = 0.5  # Base confidence
        
        # Increase for detailed responses
        if len(content) > 1000:
            confidence += 0.1
        
        # Increase for code examples
        if "```" in content:
            confidence += 0.15
        
        # Increase for structured recommendations
        if any(marker in content.lower() for marker in ["recommend", "suggestion", "best practice"]):
            confidence += 0.15
        
        # Decrease for uncertainty markers
        if any(marker in content.lower() for marker in ["might", "perhaps", "unclear", "depends"]):
            confidence -= 0.1
        
        return max(0.1, min(1.0, confidence))
    
    def _extract_recommendations(self, content: str) -> List[str]:
        """Extract recommendations from response."""
        recommendations = []
        lines = content.split('\n')
        
        in_recommendations = False
        for line in lines:
            line = line.strip()
            
            # Look for recommendation sections
            if any(marker in line.lower() for marker in ["recommend", "suggestion", "best practice"]):
                in_recommendations = True
                continue
            
            # Extract bullet points in recommendation sections
            if in_recommendations and line.startswith(('-', '*', '•', '1.', '2.', '3.')):
                rec = line.lstrip('-*•123456789. ')
                if rec:
                    recommendations.append(rec)
            
            # End of section
            elif in_recommendations and line and not line.startswith((' ', '\t', '-', '*', '•')):
                in_recommendations = False
        
        return recommendations[:10]  # Limit to top 10
    
    def _extract_code_snippets(self, content: str) -> List[Dict[str, str]]:
        """Extract code snippets from response."""
        snippets = []
        lines = content.split('\n')
        
        i = 0
        while i < len(lines):
            if lines[i].strip().startswith('```'):
                # Found code block
                language = lines[i].strip()[3:].strip()
                code_lines = []
                i += 1
                
                while i < len(lines) and not lines[i].strip().startswith('```'):
                    code_lines.append(lines[i])
                    i += 1
                
                if code_lines:
                    snippets.append({
                        "language": language or "text",
                        "code": '\n'.join(code_lines),
                        "title": f"Example {len(snippets) + 1}"
                    })
            i += 1
        
        return snippets
    
    def _extract_limitations(self, content: str) -> List[str]:
        """Extract limitations or caveats from response."""
        limitations = []
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Look for limitation markers
            if any(marker in line.lower() for marker in 
                   ["limitation", "caveat", "note that", "keep in mind", "however", "but"]):
                
                # Extract the limitation
                if ':' in line:
                    limitation = line.split(':', 1)[1].strip()
                else:
                    limitation = line
                
                if limitation and len(limitation) > 10:
                    limitations.append(limitation)
        
        return limitations[:5]  # Limit to top 5
    
    @retry_api_call(max_attempts=5, timeout=120)
    async def _api_call_with_retry(self, model: str, messages: List[Dict], system_prompt: str):
        """Make API call with retry logic."""
        return await self.client.messages.create(
            model=model,
            messages=messages,
            system=system_prompt,
            max_tokens=4096,
            temperature=0.7,
            top_p=0.95,
            stop_sequences=["<END_RESPONSE>"]
        )
    
    def _create_fallback_response(self, query: ExpertQuery) -> ExpertResponse:
        """Create fallback response when circuit is open."""
        response = ExpertResponse(
            query_id=query.id,
            expert_type=ExpertType.CLAUDE,
            status=ResponseStatus.FAILED
        )
        response.content = "Claude API is currently unavailable. The circuit breaker has been triggered due to repeated failures. Please try again later."
        response.confidence = 0.0
        response.metadata = {
            "fallback": True,
            "reason": "circuit_breaker_open"
        }
        return response
