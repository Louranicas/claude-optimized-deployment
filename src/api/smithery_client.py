"""Smithery API client for AI enhancement capabilities."""

import logging
from typing import Any, Dict, List, Optional

from .base import BaseAPIClient

logger = logging.getLogger(__name__)


class SmitheryClient(BaseAPIClient):
    """Smithery AI Enhancement API client."""
    
    def __init__(
        self,
        api_key: str,
        max_retries: int = 3,
        timeout: int = 60,  # Longer timeout for AI processing
        cache_ttl: int = 1800,  # 30 minutes cache for AI results
        **kwargs
    ):
        super().__init__(
            api_key=api_key,
            base_url="https://api.smithery.ai",
            max_retries=max_retries,
            timeout=timeout,
            cache_ttl=cache_ttl,
            rate_limit=(30, 60),  # 30 requests per minute
            **kwargs
        )
    
    def _build_headers(self) -> Dict[str, str]:
        """Build request headers for Smithery API."""
        return {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
            'User-Agent': 'Claude-Optimized-Deployment/1.0.0'
        }
    
    async def _process_response(self, response: Dict[str, Any]) -> Any:
        """Process Smithery API response."""
        if 'enhanced_content' in response:
            return {
                'content': response['enhanced_content'],
                'metadata': response.get('metadata', {}),
                'confidence': response.get('confidence', 0.0),
                'processing_time': response.get('processing_time', 0)
            }
        return response
    
    async def enhance_text(
        self,
        text: str,
        enhancement_type: str = "improve",
        context: Optional[str] = None,
        target_audience: Optional[str] = None,
        max_length: Optional[int] = None,
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """
        Enhance text using AI capabilities.
        
        Args:
            text: Text to enhance
            enhancement_type: Type of enhancement ("improve", "summarize", "expand", "clarify")
            context: Additional context for enhancement
            target_audience: Target audience description
            max_length: Maximum length of enhanced text
            use_cache: Use cached results if available
        
        Returns:
            Enhanced text with metadata
        """
        payload = {
            "text": text,
            "enhancement_type": enhancement_type
        }
        
        if context:
            payload["context"] = context
        
        if target_audience:
            payload["target_audience"] = target_audience
        
        if max_length:
            payload["max_length"] = max_length
        
        try:
            logger.info(f"Enhancing text with type: {enhancement_type}")
            response = await self._make_request(
                'POST',
                '/enhance/text',
                json=payload,
                use_cache=use_cache
            )
            
            processed = await self._process_response(response)
            logger.info(f"Text enhancement completed with confidence: {processed.get('confidence', 0):.2f}")
            
            return processed
            
        except Exception as e:
            logger.error(f"Text enhancement failed: {str(e)}")
            raise
    
    async def analyze_sentiment(
        self,
        text: str,
        detailed: bool = False,
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """
        Analyze sentiment of text.
        
        Args:
            text: Text to analyze
            detailed: Return detailed sentiment analysis
            use_cache: Use cached results if available
        
        Returns:
            Sentiment analysis results
        """
        payload = {
            "text": text,
            "detailed": detailed
        }
        
        try:
            logger.info("Analyzing sentiment")
            response = await self._make_request(
                'POST',
                '/analyze/sentiment',
                json=payload,
                use_cache=use_cache
            )
            
            logger.info("Sentiment analysis completed")
            return response
            
        except Exception as e:
            logger.error(f"Sentiment analysis failed: {str(e)}")
            raise
    
    async def extract_keywords(
        self,
        text: str,
        max_keywords: int = 10,
        include_phrases: bool = True,
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """
        Extract keywords from text.
        
        Args:
            text: Text to analyze
            max_keywords: Maximum number of keywords to extract
            include_phrases: Include key phrases
            use_cache: Use cached results if available
        
        Returns:
            Extracted keywords with scores
        """
        payload = {
            "text": text,
            "max_keywords": max_keywords,
            "include_phrases": include_phrases
        }
        
        try:
            logger.info(f"Extracting up to {max_keywords} keywords")
            response = await self._make_request(
                'POST',
                '/extract/keywords',
                json=payload,
                use_cache=use_cache
            )
            
            logger.info(f"Keyword extraction completed")
            return response
            
        except Exception as e:
            logger.error(f"Keyword extraction failed: {str(e)}")
            raise
    
    async def translate_text(
        self,
        text: str,
        target_language: str,
        source_language: Optional[str] = None,
        preserve_formatting: bool = True,
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """
        Translate text to target language.
        
        Args:
            text: Text to translate
            target_language: Target language code
            source_language: Source language code (auto-detect if None)
            preserve_formatting: Preserve text formatting
            use_cache: Use cached results if available
        
        Returns:
            Translated text with metadata
        """
        payload = {
            "text": text,
            "target_language": target_language,
            "preserve_formatting": preserve_formatting
        }
        
        if source_language:
            payload["source_language"] = source_language
        
        try:
            logger.info(f"Translating text to {target_language}")
            response = await self._make_request(
                'POST',
                '/translate',
                json=payload,
                use_cache=use_cache
            )
            
            logger.info("Translation completed")
            return response
            
        except Exception as e:
            logger.error(f"Translation failed: {str(e)}")
            raise
    
    async def generate_summary(
        self,
        text: str,
        summary_type: str = "extractive",
        max_sentences: int = 3,
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """
        Generate summary of text.
        
        Args:
            text: Text to summarize
            summary_type: "extractive" or "abstractive"
            max_sentences: Maximum sentences in summary
            use_cache: Use cached results if available
        
        Returns:
            Generated summary
        """
        payload = {
            "text": text,
            "summary_type": summary_type,
            "max_sentences": max_sentences
        }
        
        try:
            logger.info(f"Generating {summary_type} summary")
            response = await self._make_request(
                'POST',
                '/generate/summary',
                json=payload,
                use_cache=use_cache
            )
            
            logger.info("Summary generation completed")
            return response
            
        except Exception as e:
            logger.error(f"Summary generation failed: {str(e)}")
            raise
    
    async def validate_api_key(self) -> bool:
        """
        Validate the API key by making a test request.
        
        Returns:
            True if API key is valid
        """
        try:
            result = await self.enhance_text(
                text="test",
                enhancement_type="improve",
                use_cache=False
            )
            return 'content' in result
            
        except Exception as e:
            logger.error(f"API key validation failed: {str(e)}")
            return False