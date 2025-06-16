#!/usr/bin/env python3
"""
Development MCP Server
Provides intelligent development assistance with learning capabilities.
"""

import asyncio
import json
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime

from .learning import DevelopmentLearning
from .dependency_predictor import DependencyPredictor
from .style_classifier import StyleClassifier
from .embeddings import EmbeddingManager
from .integration import IntegrationManager

@dataclass
class DevelopmentRequest:
    """Development assistance request."""
    task_type: str
    code: Optional[str] = None
    language: Optional[str] = None
    framework: Optional[str] = None
    context: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None

@dataclass
class DevelopmentResponse:
    """Development assistance response."""
    success: bool
    result: Dict[str, Any]
    suggestions: List[str]
    confidence: float
    learning_data: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None

class DevelopmentMCPServer:
    """Main Development MCP Server with learning capabilities."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.learning = DevelopmentLearning()
        self.dependency_predictor = DependencyPredictor()
        self.style_classifier = StyleClassifier()
        self.embedding_manager = EmbeddingManager()
        self.integration_manager = IntegrationManager()
        self.active_sessions = {}
        self.performance_metrics = {
            'requests_processed': 0,
            'successful_optimizations': 0,
            'learning_events': 0,
            'avg_confidence': 0.0
        }
    
    async def initialize(self) -> bool:
        """Initialize the development server."""
        try:
            await self.learning.initialize()
            await self.dependency_predictor.initialize()
            await self.style_classifier.initialize()
            await self.embedding_manager.initialize()
            await self.integration_manager.initialize()
            
            self.logger.info("Development MCP Server initialized successfully")
            return True
        except Exception as e:
            self.logger.error(f"Failed to initialize development server: {e}")
            return False
    
    async def process_request(self, request: DevelopmentRequest) -> DevelopmentResponse:
        """Process a development assistance request."""
        try:
            self.performance_metrics['requests_processed'] += 1
            
            # Route request based on task type
            if request.task_type == "optimize_code":
                return await self._optimize_code(request)
            elif request.task_type == "suggest_dependencies":
                return await self._suggest_dependencies(request)
            elif request.task_type == "analyze_style":
                return await self._analyze_style(request)
            elif request.task_type == "generate_embeddings":
                return await self._generate_embeddings(request)
            elif request.task_type == "integration_advice":
                return await self._provide_integration_advice(request)
            else:
                return DevelopmentResponse(
                    success=False,
                    result={'error': f"Unknown task type: {request.task_type}"},
                    suggestions=[],
                    confidence=0.0
                )
        
        except Exception as e:
            self.logger.error(f"Error processing request: {e}")
            return DevelopmentResponse(
                success=False,
                result={'error': str(e)},
                suggestions=[],
                confidence=0.0
            )
    
    async def _optimize_code(self, request: DevelopmentRequest) -> DevelopmentResponse:
        """Optimize code using learning-based analysis."""
        try:
            if not request.code:
                return DevelopmentResponse(
                    success=False,
                    result={'error': 'No code provided'},
                    suggestions=[],
                    confidence=0.0
                )
            
            # Analyze code patterns
            patterns = await self.learning.analyze_code_patterns(
                request.code, 
                request.language or 'javascript'
            )
            
            # Generate optimization suggestions
            optimizations = await self.learning.suggest_optimizations(
                request.code,
                patterns,
                request.framework
            )
            
            # Calculate confidence based on pattern recognition
            confidence = self._calculate_optimization_confidence(patterns, optimizations)
            
            # Update performance metrics
            if confidence > 0.7:
                self.performance_metrics['successful_optimizations'] += 1
            
            # Prepare response
            result = {
                'original_code': request.code,
                'optimized_code': optimizations.get('optimized_code', request.code),
                'improvements': optimizations.get('improvements', []),
                'patterns_detected': patterns,
                'performance_gain': optimizations.get('performance_gain', 0.0)
            }
            
            suggestions = [
                "Consider using modern ES6+ features for better performance",
                "Apply functional programming patterns where appropriate",
                "Optimize component rendering with React.memo or useMemo",
                "Use TypeScript for better type safety and developer experience"
            ]
            
            # Create learning data for cross-instance sharing
            learning_data = {
                'pattern_type': 'code_optimization',
                'language': request.language,
                'framework': request.framework,
                'confidence': confidence,
                'improvements': optimizations.get('improvements', [])
            }
            
            return DevelopmentResponse(
                success=True,
                result=result,
                suggestions=suggestions,
                confidence=confidence,
                learning_data=learning_data
            )
            
        except Exception as e:
            self.logger.error(f"Code optimization error: {e}")
            return DevelopmentResponse(
                success=False,
                result={'error': str(e)},
                suggestions=[],
                confidence=0.0
            )
    
    async def _suggest_dependencies(self, request: DevelopmentRequest) -> DevelopmentResponse:
        """Suggest dependencies based on code analysis."""
        try:
            dependencies = await self.dependency_predictor.predict_dependencies(
                request.code or '',
                request.language or 'javascript',
                request.context or {}
            )
            
            confidence = dependencies.get('confidence', 0.5)
            
            result = {
                'recommended_dependencies': dependencies.get('dependencies', []),
                'dev_dependencies': dependencies.get('dev_dependencies', []),
                'reasoning': dependencies.get('reasoning', {}),
                'package_manager': dependencies.get('package_manager', 'npm')
            }
            
            suggestions = [
                "Always review dependency licenses before adding to your project",
                "Consider bundle size impact when adding new dependencies",
                "Use exact versions for critical dependencies",
                "Regularly audit dependencies for security vulnerabilities"
            ]
            
            return DevelopmentResponse(
                success=True,
                result=result,
                suggestions=suggestions,
                confidence=confidence
            )
            
        except Exception as e:
            self.logger.error(f"Dependency suggestion error: {e}")
            return DevelopmentResponse(
                success=False,
                result={'error': str(e)},
                suggestions=[],
                confidence=0.0
            )
    
    async def _analyze_style(self, request: DevelopmentRequest) -> DevelopmentResponse:
        """Analyze code style and provide recommendations."""
        try:
            style_analysis = await self.style_classifier.analyze_style(
                request.code or '',
                request.language or 'javascript'
            )
            
            confidence = style_analysis.get('confidence', 0.5)
            
            result = {
                'style_score': style_analysis.get('score', 0.0),
                'issues': style_analysis.get('issues', []),
                'recommendations': style_analysis.get('recommendations', []),
                'formatting_suggestions': style_analysis.get('formatting', [])
            }
            
            suggestions = [
                "Follow consistent naming conventions throughout your codebase",
                "Use automated formatters like Prettier or Black",
                "Set up ESLint or similar linting tools",
                "Document complex functions and classes"
            ]
            
            return DevelopmentResponse(
                success=True,
                result=result,
                suggestions=suggestions,
                confidence=confidence
            )
            
        except Exception as e:
            self.logger.error(f"Style analysis error: {e}")
            return DevelopmentResponse(
                success=False,
                result={'error': str(e)},
                suggestions=[],
                confidence=0.0
            )
    
    async def _generate_embeddings(self, request: DevelopmentRequest) -> DevelopmentResponse:
        """Generate embeddings for code analysis."""
        try:
            embeddings = await self.embedding_manager.generate_embeddings(
                request.code or '',
                request.language or 'javascript'
            )
            
            confidence = 0.9  # High confidence for embedding generation
            
            result = {
                'embeddings': embeddings.get('embeddings', []),
                'dimensions': embeddings.get('dimensions', 0),
                'similarity_score': embeddings.get('similarity_score', 0.0),
                'related_patterns': embeddings.get('related_patterns', [])
            }
            
            suggestions = [
                "Use embeddings for code similarity analysis",
                "Compare with existing patterns for optimization opportunities",
                "Leverage embeddings for automated code review"
            ]
            
            return DevelopmentResponse(
                success=True,
                result=result,
                suggestions=suggestions,
                confidence=confidence
            )
            
        except Exception as e:
            self.logger.error(f"Embedding generation error: {e}")
            return DevelopmentResponse(
                success=False,
                result={'error': str(e)},
                suggestions=[],
                confidence=0.0
            )
    
    async def _provide_integration_advice(self, request: DevelopmentRequest) -> DevelopmentResponse:
        """Provide integration advice for development workflows."""
        try:
            advice = await self.integration_manager.get_integration_advice(
                request.context or {},
                request.metadata or {}
            )
            
            confidence = advice.get('confidence', 0.7)
            
            result = {
                'integration_patterns': advice.get('patterns', []),
                'best_practices': advice.get('best_practices', []),
                'tools_recommended': advice.get('tools', []),
                'workflow_suggestions': advice.get('workflow', [])
            }
            
            suggestions = [
                "Set up continuous integration early in the project",
                "Use infrastructure as code for reproducible deployments",
                "Implement automated testing at multiple levels",
                "Monitor application performance and user experience"
            ]
            
            return DevelopmentResponse(
                success=True,
                result=result,
                suggestions=suggestions,
                confidence=confidence
            )
            
        except Exception as e:
            self.logger.error(f"Integration advice error: {e}")
            return DevelopmentResponse(
                success=False,
                result={'error': str(e)},
                suggestions=[],
                confidence=0.0
            )
    
    def _calculate_optimization_confidence(self, patterns: Dict, optimizations: Dict) -> float:
        """Calculate confidence score for optimizations."""
        base_confidence = 0.6
        
        # Increase confidence based on recognized patterns
        if patterns.get('recognized_patterns', 0) > 3:
            base_confidence += 0.2
        
        # Increase confidence based on optimization potential
        performance_gain = optimizations.get('performance_gain', 0.0)
        if performance_gain > 0.1:
            base_confidence += min(performance_gain, 0.2)
        
        return min(base_confidence, 1.0)
    
    async def learn_from_interaction(self, request: DevelopmentRequest, response: DevelopmentResponse):
        """Learn from user interaction for future improvements."""
        try:
            if response.success and response.confidence > 0.7:
                learning_event = {
                    'task_type': request.task_type,
                    'language': request.language,
                    'framework': request.framework,
                    'confidence': response.confidence,
                    'result_quality': 'high' if response.confidence > 0.8 else 'medium',
                    'timestamp': datetime.now().isoformat()
                }
                
                await self.learning.record_interaction(learning_event)
                self.performance_metrics['learning_events'] += 1
                
                # Update average confidence
                total_confidence = (self.performance_metrics['avg_confidence'] * 
                                  (self.performance_metrics['requests_processed'] - 1) + 
                                  response.confidence)
                self.performance_metrics['avg_confidence'] = (
                    total_confidence / self.performance_metrics['requests_processed']
                )
                
        except Exception as e:
            self.logger.error(f"Learning error: {e}")
    
    def extract_learning(self) -> Dict[str, Any]:
        """Extract learning data for cross-instance sharing."""
        return {
            'server_type': 'development',
            'patterns_learned': self.learning.get_learned_patterns(),
            'performance_metrics': self.performance_metrics,
            'optimization_strategies': self.learning.get_optimization_strategies(),
            'timestamp': datetime.now().isoformat()
        }
    
    async def shutdown(self):
        """Gracefully shutdown the server."""
        try:
            await self.learning.shutdown()
            await self.dependency_predictor.shutdown()
            await self.style_classifier.shutdown()
            await self.embedding_manager.shutdown()
            await self.integration_manager.shutdown()
            
            self.logger.info("Development MCP Server shutdown complete")
        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")

# Main entry point for testing
if __name__ == "__main__":
    import sys
    import os
    
    # Add project root to path for imports
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../../..'))
    
    async def test_server():
        """Test the development server."""
        server = DevelopmentMCPServer()
        
        # Initialize server
        initialized = await server.initialize()
        print(f"Server initialized: {initialized}")
        
        # Test code optimization
        request = DevelopmentRequest(
            task_type="optimize_code",
            code="function test() { var x = 1; return x + 1; }",
            language="javascript"
        )
        
        response = await server.process_request(request)
        print(f"Optimization response: {response.success}, confidence: {response.confidence}")
        
        # Learn from interaction
        await server.learn_from_interaction(request, response)
        
        # Extract learning data
        learning_data = server.extract_learning()
        print(f"Learning data extracted: {len(learning_data)} keys")
        
        # Shutdown
        await server.shutdown()
        print("Server test completed")
    
    # Run test
    asyncio.run(test_server())