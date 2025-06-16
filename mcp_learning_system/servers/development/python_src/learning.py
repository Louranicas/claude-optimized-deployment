"""Main learning system for Development MCP Server"""

import asyncio
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
import numpy as np
from datetime import datetime
import logging

from .embeddings import CodeEmbeddingModel
from .style_classifier import CodingStyleClassifier
from .dependency_predictor import DependencyPredictor

logger = logging.getLogger(__name__)

@dataclass
class CodeChange:
    file_path: str
    language: str
    before: str
    after: str
    change_type: str
    timestamp: datetime

@dataclass
class LearningUpdate:
    patterns: List[Dict[str, Any]]
    style: Dict[str, Any]
    dependencies: List[str]
    confidence: float
    metadata: Dict[str, Any]

class DevelopmentLearning:
    """Advanced learning system for code patterns and developer preferences"""
    
    def __init__(self, memory_limit_mb: int = 2048):
        self.code_embeddings = CodeEmbeddingModel(memory_limit_mb=memory_limit_mb // 2)
        self.style_classifier = CodingStyleClassifier()
        self.dependency_predictor = DependencyPredictor()
        self.learning_history = []
        self.pattern_frequency = {}
        self.style_preferences = {}
        
    async def learn_coding_patterns(self, code_changes: List[CodeChange]) -> LearningUpdate:
        """Learn from a batch of code changes"""
        logger.info(f"Learning from {len(code_changes)} code changes")
        
        # Extract patterns
        patterns = await self._extract_patterns(code_changes)
        
        # Update embeddings
        embedding_updates = await self.code_embeddings.update(patterns)
        
        # Classify style
        style = await self.style_classifier.classify(patterns)
        
        # Predict dependencies
        deps = await self.dependency_predictor.predict(patterns)
        
        # Update internal state
        self._update_learning_state(patterns, style, deps)
        
        # Calculate confidence based on consistency
        confidence = self._calculate_confidence(patterns, style)
        
        return LearningUpdate(
            patterns=patterns,
            style=style,
            dependencies=deps,
            confidence=confidence,
            metadata={
                'timestamp': datetime.now().isoformat(),
                'changes_processed': len(code_changes),
                'embedding_dimension': embedding_updates.get('dimension', 0),
                'patterns_extracted': len(patterns),
            }
        )
    
    async def _extract_patterns(self, code_changes: List[CodeChange]) -> List[Dict[str, Any]]:
        """Extract patterns from code changes"""
        patterns = []
        
        for change in code_changes:
            # Extract different types of patterns
            import_patterns = self._extract_import_patterns(change)
            function_patterns = self._extract_function_patterns(change)
            error_patterns = self._extract_error_patterns(change)
            naming_patterns = self._extract_naming_patterns(change)
            
            patterns.extend(import_patterns)
            patterns.extend(function_patterns)
            patterns.extend(error_patterns)
            patterns.extend(naming_patterns)
        
        return patterns
    
    def _extract_import_patterns(self, change: CodeChange) -> List[Dict[str, Any]]:
        """Extract import statement patterns"""
        patterns = []
        
        # Python imports
        if change.language == 'python':
            import_lines = [line for line in change.after.split('\n') 
                          if line.strip().startswith(('import ', 'from '))]
            
            for line in import_lines:
                pattern = {
                    'type': 'import',
                    'language': 'python',
                    'content': line.strip(),
                    'style': 'absolute' if line.startswith('import ') else 'from',
                    'file': change.file_path,
                }
                patterns.append(pattern)
        
        # JavaScript/TypeScript imports
        elif change.language in ['javascript', 'typescript']:
            import_lines = [line for line in change.after.split('\n')
                          if line.strip().startswith('import ') or 'require(' in line]
            
            for line in import_lines:
                pattern = {
                    'type': 'import',
                    'language': change.language,
                    'content': line.strip(),
                    'style': 'es6' if line.startswith('import ') else 'commonjs',
                    'file': change.file_path,
                }
                patterns.append(pattern)
        
        return patterns
    
    def _extract_function_patterns(self, change: CodeChange) -> List[Dict[str, Any]]:
        """Extract function signature patterns"""
        patterns = []
        
        if change.language == 'python':
            # Simple function extraction
            lines = change.after.split('\n')
            for i, line in enumerate(lines):
                if line.strip().startswith('def ') or line.strip().startswith('async def '):
                    # Extract function signature
                    signature = line.strip()
                    # Try to get return type hint if available
                    if '->' in signature:
                        pattern = {
                            'type': 'function_signature',
                            'language': 'python',
                            'content': signature,
                            'has_type_hints': True,
                            'is_async': 'async def' in signature,
                            'file': change.file_path,
                        }
                    else:
                        pattern = {
                            'type': 'function_signature',
                            'language': 'python',
                            'content': signature,
                            'has_type_hints': False,
                            'is_async': 'async def' in signature,
                            'file': change.file_path,
                        }
                    patterns.append(pattern)
        
        return patterns
    
    def _extract_error_patterns(self, change: CodeChange) -> List[Dict[str, Any]]:
        """Extract error handling patterns"""
        patterns = []
        
        if change.language == 'python':
            if 'try:' in change.after and 'except' in change.after:
                pattern = {
                    'type': 'error_handling',
                    'language': 'python',
                    'style': 'try_except',
                    'file': change.file_path,
                }
                patterns.append(pattern)
        
        elif change.language in ['javascript', 'typescript']:
            if 'try {' in change.after and 'catch' in change.after:
                pattern = {
                    'type': 'error_handling',
                    'language': change.language,
                    'style': 'try_catch',
                    'file': change.file_path,
                }
                patterns.append(pattern)
        
        return patterns
    
    def _extract_naming_patterns(self, change: CodeChange) -> List[Dict[str, Any]]:
        """Extract naming convention patterns"""
        patterns = []
        
        # Extract variable names (simplified)
        import re
        
        if change.language == 'python':
            # Find variable assignments
            var_pattern = r'(\w+)\s*='
            matches = re.findall(var_pattern, change.after)
            
            for var_name in matches:
                if '_' in var_name:
                    convention = 'snake_case'
                elif var_name[0].isupper():
                    convention = 'PascalCase'
                else:
                    convention = 'camelCase'
                
                pattern = {
                    'type': 'naming_convention',
                    'language': 'python',
                    'convention': convention,
                    'example': var_name,
                    'file': change.file_path,
                }
                patterns.append(pattern)
        
        return patterns
    
    def _update_learning_state(self, patterns: List[Dict[str, Any]], 
                               style: Dict[str, Any], deps: List[str]):
        """Update internal learning state"""
        # Update pattern frequency
        for pattern in patterns:
            key = f"{pattern['type']}:{pattern.get('style', 'default')}"
            self.pattern_frequency[key] = self.pattern_frequency.get(key, 0) + 1
        
        # Update style preferences
        for key, value in style.items():
            if key not in self.style_preferences:
                self.style_preferences[key] = {}
            
            if isinstance(value, str):
                self.style_preferences[key][value] = self.style_preferences[key].get(value, 0) + 1
        
        # Add to history
        self.learning_history.append({
            'timestamp': datetime.now(),
            'patterns_count': len(patterns),
            'style': style,
            'dependencies': deps,
        })
    
    def _calculate_confidence(self, patterns: List[Dict[str, Any]], 
                            style: Dict[str, Any]) -> float:
        """Calculate confidence based on pattern consistency"""
        if not patterns:
            return 0.0
        
        # Calculate pattern consistency
        pattern_types = [p['type'] for p in patterns]
        unique_types = len(set(pattern_types))
        pattern_consistency = 1.0 - (unique_types / len(pattern_types))
        
        # Calculate style consistency
        style_consistency = 0.8  # Default high consistency
        
        # Combine scores
        confidence = (pattern_consistency + style_consistency) / 2.0
        
        return min(max(confidence, 0.0), 1.0)
    
    async def predict_next_code(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Predict next code based on learned patterns"""
        # Get embeddings for context
        context_embedding = await self.code_embeddings.encode(context.get('code', ''))
        
        # Find similar patterns
        similar_patterns = await self.code_embeddings.find_similar(context_embedding, k=5)
        
        # Generate prediction
        prediction = {
            'suggestion': self._generate_suggestion(similar_patterns, context),
            'confidence': self._calculate_prediction_confidence(similar_patterns),
            'patterns_used': [p['type'] for p in similar_patterns],
        }
        
        return prediction
    
    def _generate_suggestion(self, patterns: List[Dict[str, Any]], 
                           context: Dict[str, Any]) -> str:
        """Generate code suggestion based on patterns"""
        if not patterns:
            return "# No suggestion available"
        
        # Simple suggestion based on most common pattern
        most_common = patterns[0]
        
        if most_common['type'] == 'import':
            return f"# Consider importing: {most_common.get('content', '')}"
        elif most_common['type'] == 'function_signature':
            return f"# Function pattern: {most_common.get('content', '')}"
        else:
            return "# Pattern-based suggestion"
    
    def _calculate_prediction_confidence(self, patterns: List[Dict[str, Any]]) -> float:
        """Calculate prediction confidence"""
        if not patterns:
            return 0.0
        
        # Simple confidence based on pattern count
        return min(len(patterns) / 10.0, 1.0)
    
    def get_learning_stats(self) -> Dict[str, Any]:
        """Get learning statistics"""
        return {
            'total_patterns_learned': sum(self.pattern_frequency.values()),
            'unique_patterns': len(self.pattern_frequency),
            'style_preferences': self.style_preferences,
            'learning_sessions': len(self.learning_history),
            'most_common_patterns': sorted(
                self.pattern_frequency.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10],
        }
    
    async def export_model(self, path: str):
        """Export learned model to disk"""
        model_data = {
            'embeddings': await self.code_embeddings.export(),
            'style_classifier': await self.style_classifier.export(),
            'dependency_predictor': await self.dependency_predictor.export(),
            'pattern_frequency': self.pattern_frequency,
            'style_preferences': self.style_preferences,
        }
        
        import pickle
        with open(path, 'wb') as f:
            pickle.dump(model_data, f)
        
        logger.info(f"Exported model to {path}")
    
    async def import_model(self, path: str):
        """Import learned model from disk"""
        import pickle
        with open(path, 'rb') as f:
            model_data = pickle.load(f)
        
        await self.code_embeddings.import_model(model_data['embeddings'])
        await self.style_classifier.import_model(model_data['style_classifier'])
        await self.dependency_predictor.import_model(model_data['dependency_predictor'])
        self.pattern_frequency = model_data['pattern_frequency']
        self.style_preferences = model_data['style_preferences']
        
        logger.info(f"Imported model from {path}")