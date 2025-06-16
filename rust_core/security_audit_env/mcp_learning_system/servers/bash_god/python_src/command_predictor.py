"""Command Predictor - Predicts best command approaches using ML techniques"""

import numpy as np
from typing import Dict, Any, List, Tuple
from collections import Counter, defaultdict
import re
import hashlib
from dataclasses import dataclass
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import pickle
import os


@dataclass
class CommandApproach:
    """Represents a command approach strategy"""
    name: str
    confidence: float
    typical_commands: List[str]
    resource_requirements: Dict[str, float]
    best_for: List[str]


class CommandPredictor:
    """Predicts best command approach for tasks"""
    
    def __init__(self):
        self.task_vectorizer = TfidfVectorizer(max_features=1000, ngram_range=(1, 3))
        self.approach_history: Dict[str, List[str]] = defaultdict(list)
        self.approach_success: Dict[str, float] = defaultdict(float)
        self.command_patterns: Dict[str, List[str]] = defaultdict(list)
        self.trained = False
        
        # Pre-defined approaches
        self.approaches = {
            'pipeline': CommandApproach(
                name='pipeline',
                confidence=0.0,
                typical_commands=['find', 'grep', 'awk', 'sed', 'sort'],
                resource_requirements={'cpu': 0.3, 'memory': 0.2},
                best_for=['text processing', 'file searching', 'data extraction']
            ),
            'parallel': CommandApproach(
                name='parallel',
                confidence=0.0,
                typical_commands=['parallel', 'xargs -P', 'find -exec'],
                resource_requirements={'cpu': 0.8, 'memory': 0.5},
                best_for=['bulk operations', 'cpu intensive', 'independent tasks']
            ),
            'iterative': CommandApproach(
                name='iterative',
                confidence=0.0,
                typical_commands=['for', 'while', 'until', 'do'],
                resource_requirements={'cpu': 0.4, 'memory': 0.3},
                best_for=['sequential processing', 'dependent operations', 'conditional logic']
            ),
            'direct': CommandApproach(
                name='direct',
                confidence=0.0,
                typical_commands=['single command'],
                resource_requirements={'cpu': 0.2, 'memory': 0.1},
                best_for=['simple operations', 'quick tasks', 'atomic operations']
            ),
            'scripted': CommandApproach(
                name='scripted',
                confidence=0.0,
                typical_commands=['bash script', 'python', 'perl'],
                resource_requirements={'cpu': 0.5, 'memory': 0.4},
                best_for=['complex logic', 'error handling', 'reusable solutions']
            ),
        }
        
        # Task keywords to approach mapping
        self.task_keywords = {
            'pipeline': ['filter', 'extract', 'transform', 'search', 'grep', 'find', 'parse'],
            'parallel': ['bulk', 'many', 'all', 'batch', 'multiple', 'concurrent', 'simultaneous'],
            'iterative': ['each', 'every', 'sequence', 'order', 'step', 'one by one'],
            'direct': ['single', 'simple', 'quick', 'just', 'only'],
            'scripted': ['complex', 'automate', 'schedule', 'repeat', 'logic', 'condition'],
        }
        
    def predict_approach(self, task: str, context: Dict[str, Any]) -> str:
        """Predict best approach for a task"""
        # Analyze task description
        task_features = self._extract_task_features(task)
        
        # Consider context
        context_features = self._extract_context_features(context)
        
        # Calculate approach scores
        approach_scores = self._calculate_approach_scores(task_features, context_features)
        
        # Get best approach
        best_approach = max(approach_scores.items(), key=lambda x: x[1])[0]
        
        # Update confidence based on historical success
        if best_approach in self.approach_success:
            confidence = self.approach_success[best_approach]
            self.approaches[best_approach].confidence = confidence
        
        return best_approach
    
    def _extract_task_features(self, task: str) -> Dict[str, float]:
        """Extract features from task description"""
        features = defaultdict(float)
        task_lower = task.lower()
        
        # Check for keywords
        for approach, keywords in self.task_keywords.items():
            for keyword in keywords:
                if keyword in task_lower:
                    features[f'keyword_{approach}'] += 1.0
        
        # Task complexity indicators
        features['word_count'] = len(task.split())
        features['has_multiple_operations'] = 1.0 if any(word in task_lower for word in ['and', 'then', 'also']) else 0.0
        features['has_conditions'] = 1.0 if any(word in task_lower for word in ['if', 'when', 'unless']) else 0.0
        
        # File operation indicators
        features['file_operations'] = sum(1 for word in ['file', 'files', 'directory', 'folder'] if word in task_lower)
        features['bulk_indicator'] = 1.0 if any(word in task_lower for word in ['all', 'many', 'bulk', 'batch']) else 0.0
        
        return features
    
    def _extract_context_features(self, context: Dict[str, Any]) -> Dict[str, float]:
        """Extract features from context"""
        features = defaultdict(float)
        
        # System resources
        features['cpu_cores'] = context.get('cpu_cores', 1)
        features['memory_gb'] = context.get('memory_gb', 1)
        features['load_average'] = context.get('load_average', 0.5)
        
        # Task specifics
        features['file_count'] = context.get('file_count', 1)
        features['data_size_mb'] = context.get('data_size_mb', 0)
        features['time_constraint'] = 1.0 if context.get('urgent', False) else 0.0
        
        # Environment
        features['has_parallel_tools'] = 1.0 if context.get('has_parallel', True) else 0.0
        features['in_container'] = 1.0 if context.get('in_docker', False) else 0.0
        
        return features
    
    def _calculate_approach_scores(self, task_features: Dict[str, float], 
                                 context_features: Dict[str, float]) -> Dict[str, float]:
        """Calculate scores for each approach"""
        scores = {}
        
        for approach_name, approach in self.approaches.items():
            score = 0.0
            
            # Keyword matching score
            keyword_score = task_features.get(f'keyword_{approach_name}', 0.0)
            score += keyword_score * 2.0
            
            # Resource availability score
            cpu_available = context_features['cpu_cores'] * (1 - context_features['load_average'])
            memory_available = context_features['memory_gb']
            
            cpu_fit = 1.0 - abs(cpu_available - approach.resource_requirements['cpu'] * context_features['cpu_cores'])
            memory_fit = 1.0 - abs(memory_available - approach.resource_requirements['memory'] * context_features['memory_gb'])
            
            resource_score = (cpu_fit + memory_fit) / 2
            score += resource_score
            
            # Specific approach scoring
            if approach_name == 'pipeline':
                if task_features['file_operations'] > 0:
                    score += 1.0
                if 'filter' in task_features or 'search' in task_features:
                    score += 1.5
                    
            elif approach_name == 'parallel':
                if context_features['cpu_cores'] > 2 and task_features['bulk_indicator']:
                    score += 2.0
                if context_features['file_count'] > 100:
                    score += 1.5
                if not context_features['has_parallel_tools']:
                    score -= 3.0
                    
            elif approach_name == 'iterative':
                if task_features['has_conditions']:
                    score += 1.5
                if task_features['has_multiple_operations']:
                    score += 1.0
                    
            elif approach_name == 'direct':
                if task_features['word_count'] < 5:
                    score += 2.0
                if not task_features['has_multiple_operations']:
                    score += 1.0
                    
            elif approach_name == 'scripted':
                if task_features['has_conditions'] and task_features['has_multiple_operations']:
                    score += 2.0
                if task_features['word_count'] > 20:
                    score += 1.0
            
            # Historical success adjustment
            if approach_name in self.approach_success:
                score *= (1 + self.approach_success[approach_name])
            
            scores[approach_name] = max(0, score)
        
        # Normalize scores
        total_score = sum(scores.values())
        if total_score > 0:
            scores = {k: v / total_score for k, v in scores.items()}
        
        return scores
    
    def learn_from_execution(self, task: str, approach: str, success: bool, duration_ms: float):
        """Learn from command execution results"""
        # Update approach history
        self.approach_history[approach].append(task)
        
        # Update success rate
        current_success = self.approach_success.get(approach, 0.5)
        # Exponential moving average
        alpha = 0.1
        new_success = alpha * (1.0 if success else 0.0) + (1 - alpha) * current_success
        self.approach_success[approach] = new_success
        
        # Learn command patterns
        if success and duration_ms < 5000:  # Fast and successful
            task_hash = hashlib.md5(task.encode()).hexdigest()[:8]
            self.command_patterns[task_hash].append(approach)
    
    def get_similar_tasks(self, task: str, top_k: int = 5) -> List[Tuple[str, float]]:
        """Find similar tasks from history"""
        if not self.approach_history:
            return []
        
        all_tasks = []
        for approach_tasks in self.approach_history.values():
            all_tasks.extend(approach_tasks)
        
        if len(all_tasks) < 2:
            return []
        
        # Vectorize tasks
        try:
            if not self.trained:
                self.task_vectorizer.fit(all_tasks)
                self.trained = True
            
            task_vector = self.task_vectorizer.transform([task])
            all_vectors = self.task_vectorizer.transform(all_tasks)
            
            # Calculate similarities
            similarities = cosine_similarity(task_vector, all_vectors)[0]
            
            # Get top k similar tasks
            top_indices = similarities.argsort()[-top_k-1:-1][::-1]
            similar_tasks = [(all_tasks[i], similarities[i]) for i in top_indices]
            
            return similar_tasks
            
        except Exception:
            # Fallback to simple string matching
            similar = []
            task_words = set(task.lower().split())
            
            for hist_task in all_tasks:
                hist_words = set(hist_task.lower().split())
                similarity = len(task_words & hist_words) / max(len(task_words), len(hist_words))
                if similarity > 0.3:
                    similar.append((hist_task, similarity))
            
            return sorted(similar, key=lambda x: x[1], reverse=True)[:top_k]
    
    def suggest_approach_combination(self, task: str, context: Dict[str, Any]) -> List[str]:
        """Suggest combination of approaches for complex tasks"""
        task_features = self._extract_task_features(task)
        
        suggestions = []
        
        # Check if task might benefit from multiple approaches
        if task_features['has_multiple_operations'] and task_features['word_count'] > 10:
            # Could use pipeline + parallel
            if task_features['bulk_indicator'] and context.get('cpu_cores', 1) > 2:
                suggestions.append("Consider combining pipeline and parallel approaches")
                suggestions.append("Example: find | parallel -j+0 'grep {} | awk {}'")
            
            # Could use scripted with embedded approaches
            if task_features['has_conditions']:
                suggestions.append("Consider a bash script with conditional logic")
                suggestions.append("This allows better error handling and flow control")
        
        return suggestions
    
    def export_model(self, filepath: str):
        """Export the predictor model"""
        model_data = {
            'approach_history': dict(self.approach_history),
            'approach_success': dict(self.approach_success),
            'command_patterns': dict(self.command_patterns),
            'vectorizer': self.task_vectorizer if self.trained else None,
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
    
    def import_model(self, filepath: str):
        """Import a previously trained model"""
        if os.path.exists(filepath):
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            
            self.approach_history = defaultdict(list, model_data['approach_history'])
            self.approach_success = defaultdict(float, model_data['approach_success'])
            self.command_patterns = defaultdict(list, model_data['command_patterns'])
            
            if model_data['vectorizer'] is not None:
                self.task_vectorizer = model_data['vectorizer']
                self.trained = True