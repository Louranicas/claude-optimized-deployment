"""Code embedding model for semantic understanding"""

import numpy as np
from typing import List, Dict, Any, Optional, Tuple
import hashlib
from collections import defaultdict
import asyncio
import logging

logger = logging.getLogger(__name__)

class CodeEmbeddingModel:
    """Lightweight code embedding model using feature hashing"""
    
    def __init__(self, embedding_dim: int = 512, memory_limit_mb: int = 1024):
        self.embedding_dim = embedding_dim
        self.memory_limit_mb = memory_limit_mb
        self.vocabulary = {}
        self.embeddings = {}
        self.code_cache = {}
        self.feature_weights = np.random.randn(embedding_dim, 100)  # 100 feature types
        self.idf_weights = defaultdict(float)
        self.total_documents = 0
        
    async def encode(self, code: str) -> np.ndarray:
        """Encode code snippet into embedding vector"""
        # Check cache
        code_hash = hashlib.md5(code.encode()).hexdigest()
        if code_hash in self.code_cache:
            return self.code_cache[code_hash]
        
        # Extract features
        features = self._extract_features(code)
        
        # Convert to embedding
        embedding = self._features_to_embedding(features)
        
        # Normalize
        norm = np.linalg.norm(embedding)
        if norm > 0:
            embedding = embedding / norm
        
        # Cache result
        self.code_cache[code_hash] = embedding
        
        return embedding
    
    def _extract_features(self, code: str) -> Dict[str, float]:
        """Extract various code features"""
        features = defaultdict(float)
        
        # Token features
        tokens = self._tokenize(code)
        for token in tokens:
            features[f'token:{token}'] += 1.0
        
        # N-gram features
        for n in [2, 3]:
            ngrams = self._get_ngrams(tokens, n)
            for ngram in ngrams:
                features[f'ngram{n}:{ngram}'] += 1.0
        
        # Structural features
        features['lines'] = code.count('\n') + 1
        features['indentation'] = self._measure_indentation(code)
        features['complexity'] = self._estimate_complexity(code)
        
        # Language-specific features
        if 'def ' in code or 'class ' in code:
            features['language:python'] = 1.0
        elif 'function ' in code or 'const ' in code:
            features['language:javascript'] = 1.0
        elif 'fn ' in code or 'impl ' in code:
            features['language:rust'] = 1.0
        
        # Pattern features
        if 'import ' in code or 'from ' in code or 'require(' in code:
            features['pattern:import'] = 1.0
        if 'try' in code and ('except' in code or 'catch' in code):
            features['pattern:error_handling'] = 1.0
        if 'async' in code or 'await' in code:
            features['pattern:async'] = 1.0
        
        return features
    
    def _tokenize(self, code: str) -> List[str]:
        """Simple tokenization"""
        import re
        # Split on whitespace and common delimiters
        tokens = re.findall(r'\b\w+\b|[^\w\s]', code.lower())
        return tokens
    
    def _get_ngrams(self, tokens: List[str], n: int) -> List[str]:
        """Get n-grams from tokens"""
        ngrams = []
        for i in range(len(tokens) - n + 1):
            ngram = ' '.join(tokens[i:i+n])
            ngrams.append(ngram)
        return ngrams
    
    def _measure_indentation(self, code: str) -> float:
        """Measure average indentation level"""
        lines = code.split('\n')
        indentations = []
        
        for line in lines:
            if line.strip():
                indent = len(line) - len(line.lstrip())
                indentations.append(indent)
        
        return np.mean(indentations) if indentations else 0.0
    
    def _estimate_complexity(self, code: str) -> float:
        """Estimate code complexity"""
        complexity = 1.0
        
        # Count control flow statements
        control_flow = ['if', 'else', 'elif', 'for', 'while', 'try', 'except', 'catch']
        for keyword in control_flow:
            complexity += code.count(keyword)
        
        # Count logical operators
        complexity += code.count('and') + code.count('or')
        complexity += code.count('&&') + code.count('||')
        
        return complexity
    
    def _features_to_embedding(self, features: Dict[str, float]) -> np.ndarray:
        """Convert features to embedding vector using feature hashing"""
        embedding = np.zeros(self.embedding_dim)
        
        for feature, value in features.items():
            # Hash feature to multiple indices
            indices = self._hash_feature(feature, num_indices=3)
            
            for idx in indices:
                # Apply feature weight
                feature_type = feature.split(':')[0]
                feature_idx = hash(feature_type) % 100
                weight = self.feature_weights[idx % self.embedding_dim, feature_idx]
                
                # Apply TF-IDF weight if available
                idf = self.idf_weights.get(feature, 1.0)
                
                embedding[idx % self.embedding_dim] += value * weight * idf
        
        return embedding
    
    def _hash_feature(self, feature: str, num_indices: int = 3) -> List[int]:
        """Hash feature to multiple indices for robustness"""
        indices = []
        for i in range(num_indices):
            h = hashlib.md5(f"{feature}:{i}".encode()).digest()
            idx = int.from_bytes(h[:4], 'big')
            indices.append(idx)
        return indices
    
    async def update(self, patterns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Update embeddings based on new patterns"""
        logger.info(f"Updating embeddings with {len(patterns)} patterns")
        
        # Update IDF weights
        self.total_documents += len(patterns)
        
        for pattern in patterns:
            code = pattern.get('content', '')
            features = self._extract_features(code)
            
            for feature in features:
                self.idf_weights[feature] += 1.0
        
        # Recalculate IDF
        for feature in self.idf_weights:
            df = self.idf_weights[feature]
            self.idf_weights[feature] = np.log(self.total_documents / (1 + df))
        
        # Update feature weights using simple gradient
        for pattern in patterns:
            code = pattern.get('content', '')
            embedding = await self.encode(code)
            
            # Simple weight update based on pattern type
            pattern_type = pattern.get('type', 'unknown')
            if pattern_type in ['import', 'function_signature', 'error_handling']:
                # Boost weights for important patterns
                self.feature_weights *= 1.01
        
        return {
            'dimension': self.embedding_dim,
            'vocabulary_size': len(self.idf_weights),
            'cache_size': len(self.code_cache),
        }
    
    async def find_similar(self, embedding: np.ndarray, k: int = 5) -> List[Dict[str, Any]]:
        """Find k most similar patterns to given embedding"""
        similarities = []
        
        # Compare with cached embeddings
        for code_hash, cached_embedding in self.code_cache.items():
            similarity = np.dot(embedding, cached_embedding)
            similarities.append((code_hash, similarity))
        
        # Sort by similarity
        similarities.sort(key=lambda x: x[1], reverse=True)
        
        # Return top k
        results = []
        for code_hash, similarity in similarities[:k]:
            results.append({
                'code_hash': code_hash,
                'similarity': float(similarity),
                'type': 'cached_pattern',
            })
        
        return results
    
    async def export(self) -> Dict[str, Any]:
        """Export model state"""
        return {
            'embedding_dim': self.embedding_dim,
            'feature_weights': self.feature_weights.tolist(),
            'idf_weights': dict(self.idf_weights),
            'total_documents': self.total_documents,
            'vocabulary_size': len(self.idf_weights),
        }
    
    async def import_model(self, model_data: Dict[str, Any]):
        """Import model state"""
        self.embedding_dim = model_data['embedding_dim']
        self.feature_weights = np.array(model_data['feature_weights'])
        self.idf_weights = defaultdict(float, model_data['idf_weights'])
        self.total_documents = model_data['total_documents']
        
        logger.info(f"Imported model with {len(self.idf_weights)} vocabulary items")
    
    def get_memory_usage(self) -> Dict[str, float]:
        """Get current memory usage in MB"""
        # Estimate memory usage
        weights_mb = self.feature_weights.nbytes / (1024 * 1024)
        cache_mb = sum(embed.nbytes for embed in self.code_cache.values()) / (1024 * 1024)
        idf_mb = len(self.idf_weights) * 100 / (1024 * 1024)  # Rough estimate
        
        return {
            'weights_mb': weights_mb,
            'cache_mb': cache_mb,
            'idf_mb': idf_mb,
            'total_mb': weights_mb + cache_mb + idf_mb,
            'limit_mb': self.memory_limit_mb,
        }
    
    def clear_cache(self):
        """Clear embedding cache to free memory"""
        self.code_cache.clear()
        logger.info("Cleared embedding cache")