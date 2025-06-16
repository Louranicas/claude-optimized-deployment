"""Dependency prediction for smart import suggestions"""

from typing import List, Dict, Any, Set, Tuple, Optional
from collections import defaultdict, Counter
import re
import logging

logger = logging.getLogger(__name__)

class DependencyPredictor:
    """Predict likely dependencies based on code patterns"""
    
    def __init__(self):
        # Common patterns and their typical dependencies
        self.pattern_dependencies = {
            'python': {
                'patterns': {
                    r'\basync\s+def': ['asyncio', 'aiohttp'],
                    r'DataFrame': ['pandas'],
                    r'np\.': ['numpy'],
                    r'plt\.': ['matplotlib.pyplot'],
                    r'requests\.': ['requests'],
                    r'torch\.': ['torch'],
                    r'tf\.': ['tensorflow'],
                    r'@app\.route': ['flask'],
                    r'models\.Model': ['django.db'],
                    r'datetime\.': ['datetime'],
                    r'json\.': ['json'],
                    r're\.': ['re'],
                    r'os\.': ['os'],
                    r'Path\(': ['pathlib'],
                    r'typing\.': ['typing'],
                    r'dataclass': ['dataclasses'],
                    r'logging\.': ['logging'],
                    r'unittest\.': ['unittest'],
                    r'pytest': ['pytest'],
                },
                'frameworks': {
                    'flask': ['flask', 'flask_cors', 'flask_sqlalchemy'],
                    'django': ['django', 'django.db', 'django.contrib.auth'],
                    'fastapi': ['fastapi', 'pydantic', 'uvicorn'],
                    'pytorch': ['torch', 'torchvision', 'numpy'],
                    'tensorflow': ['tensorflow', 'keras', 'numpy'],
                }
            },
            'javascript': {
                'patterns': {
                    r'React\.': ['react'],
                    r'useState': ['react'],
                    r'useEffect': ['react'],
                    r'express\(\)': ['express'],
                    r'app\.get': ['express'],
                    r'axios\.': ['axios'],
                    r'fetch\(': [],  # Built-in
                    r'document\.': [],  # Built-in
                    r'console\.': [],  # Built-in
                    r'Promise': [],  # Built-in
                    r'async/await': [],  # Built-in
                    r'\.map\(': [],  # Built-in
                    r'\.filter\(': [],  # Built-in
                    r'fs\.': ['fs'],
                    r'path\.': ['path'],
                    r'http\.': ['http'],
                    r'crypto\.': ['crypto'],
                },
                'frameworks': {
                    'react': ['react', 'react-dom', 'react-router-dom'],
                    'vue': ['vue', 'vuex', 'vue-router'],
                    'angular': ['@angular/core', '@angular/common', '@angular/router'],
                    'express': ['express', 'body-parser', 'cors'],
                    'nextjs': ['next', 'react', 'react-dom'],
                }
            },
            'typescript': {
                'patterns': {
                    r': Observable': ['rxjs'],
                    r'@Component': ['@angular/core'],
                    r'@Injectable': ['@angular/core'],
                    r'interface\s+\w+': [],  # Built-in
                    r'type\s+\w+': [],  # Built-in
                    r'enum\s+\w+': [],  # Built-in
                },
                'frameworks': {}  # Inherits from javascript
            },
            'rust': {
                'patterns': {
                    r'tokio::': ['tokio'],
                    r'async fn': ['tokio', 'async-std'],
                    r'serde::': ['serde'],
                    r'#\[derive.*Serialize': ['serde'],
                    r'reqwest::': ['reqwest'],
                    r'Vec<': [],  # std
                    r'HashMap<': ['std::collections'],
                    r'Result<': [],  # std
                    r'Option<': [],  # std
                    r'println!': [],  # std
                    r'format!': [],  # std
                },
                'frameworks': {
                    'actix': ['actix-web', 'actix-rt'],
                    'rocket': ['rocket'],
                    'warp': ['warp', 'tokio'],
                }
            }
        }
        
        # Track learned associations
        self.learned_associations = defaultdict(lambda: defaultdict(set))
        self.import_co_occurrence = defaultdict(Counter)
        
    async def predict(self, patterns: List[Dict[str, Any]]) -> List[str]:
        """Predict dependencies based on code patterns"""
        predicted_deps = set()
        language_counts = defaultdict(int)
        
        # Count languages
        for pattern in patterns:
            language = pattern.get('language', 'unknown')
            language_counts[language] += 1
        
        # Get dominant language
        if language_counts:
            dominant_language = max(language_counts.items(), key=lambda x: x[1])[0]
        else:
            return []
        
        # Analyze patterns for each language
        for pattern in patterns:
            language = pattern.get('language', dominant_language)
            content = pattern.get('content', '')
            
            deps = self._predict_for_content(content, language)
            predicted_deps.update(deps)
        
        # Add commonly co-occurring dependencies
        co_occurring = self._get_co_occurring_deps(list(predicted_deps))
        predicted_deps.update(co_occurring)
        
        # Filter out built-in modules based on language
        filtered_deps = self._filter_builtin_modules(list(predicted_deps), dominant_language)
        
        return sorted(filtered_deps)
    
    def _predict_for_content(self, content: str, language: str) -> Set[str]:
        """Predict dependencies for specific content"""
        deps = set()
        
        if language not in self.pattern_dependencies:
            return deps
        
        lang_patterns = self.pattern_dependencies[language]['patterns']
        
        # Check each pattern
        for pattern, dependencies in lang_patterns.items():
            if re.search(pattern, content):
                deps.update(dependencies)
        
        # Check for framework indicators
        frameworks = self.pattern_dependencies[language].get('frameworks', {})
        for framework, framework_deps in frameworks.items():
            if framework.lower() in content.lower():
                deps.update(framework_deps)
        
        # Add learned associations
        for token in self._tokenize(content):
            if token in self.learned_associations[language]:
                deps.update(self.learned_associations[language][token])
        
        return deps
    
    def _tokenize(self, content: str) -> List[str]:
        """Simple tokenization for dependency detection"""
        # Extract potential module/library names
        tokens = re.findall(r'\b[a-zA-Z_][\w\.]*\b', content)
        return [t for t in tokens if len(t) > 2]  # Filter short tokens
    
    def _get_co_occurring_deps(self, current_deps: List[str]) -> List[str]:
        """Get dependencies that commonly occur together"""
        co_occurring = set()
        
        for dep in current_deps:
            if dep in self.import_co_occurrence:
                # Get top co-occurring dependencies
                for co_dep, count in self.import_co_occurrence[dep].most_common(3):
                    if count > 2 and co_dep not in current_deps:
                        co_occurring.add(co_dep)
        
        return list(co_occurring)
    
    def _filter_builtin_modules(self, deps: List[str], language: str) -> List[str]:
        """Filter out built-in modules that don't need to be imported"""
        builtin_modules = {
            'python': {'os', 'sys', 're', 'json', 'datetime', 'collections', 
                      'itertools', 'functools', 'pathlib', 'typing', 'logging'},
            'javascript': {'console', 'document', 'window', 'Promise', 'Array', 'Object'},
            'typescript': {'console', 'document', 'window', 'Promise', 'Array', 'Object'},
            'rust': {'std', 'core', 'alloc'},
        }
        
        if language in builtin_modules:
            # Keep some Python built-ins as they're commonly explicitly imported
            if language == 'python':
                return deps  # Don't filter Python imports
            else:
                return [d for d in deps if d not in builtin_modules[language]]
        
        return deps
    
    def learn_from_imports(self, imports: List[Tuple[str, str]], language: str):
        """Learn from actual import statements"""
        # Track co-occurrence
        import_names = [imp[1] for imp in imports]
        
        for i, imp1 in enumerate(import_names):
            for imp2 in import_names[i+1:]:
                if imp1 != imp2:
                    self.import_co_occurrence[imp1][imp2] += 1
                    self.import_co_occurrence[imp2][imp1] += 1
        
        # Learn associations from import context
        for context, import_name in imports:
            tokens = self._tokenize(context)
            for token in tokens:
                self.learned_associations[language][token].add(import_name)
    
    async def export(self) -> Dict[str, Any]:
        """Export predictor state"""
        return {
            'learned_associations': {
                lang: {token: list(deps) for token, deps in lang_data.items()}
                for lang, lang_data in self.learned_associations.items()
            },
            'import_co_occurrence': {
                imp: dict(counter)
                for imp, counter in self.import_co_occurrence.items()
            }
        }
    
    async def import_model(self, model_data: Dict[str, Any]):
        """Import predictor state"""
        # Import learned associations
        self.learned_associations = defaultdict(lambda: defaultdict(set))
        for lang, lang_data in model_data.get('learned_associations', {}).items():
            for token, deps in lang_data.items():
                self.learned_associations[lang][token] = set(deps)
        
        # Import co-occurrence data
        self.import_co_occurrence = defaultdict(Counter)
        for imp, counter_data in model_data.get('import_co_occurrence', {}).items():
            self.import_co_occurrence[imp] = Counter(counter_data)
        
        logger.info(f"Imported dependency predictor with {len(self.learned_associations)} languages")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get predictor statistics"""
        return {
            'languages': list(self.learned_associations.keys()),
            'total_associations': sum(
                len(tokens) for tokens in self.learned_associations.values()
            ),
            'co_occurrence_pairs': len(self.import_co_occurrence),
            'most_common_dependencies': Counter(
                dep 
                for deps_set in self.learned_associations.values()
                for dep_set in deps_set.values()
                for dep in dep_set
            ).most_common(10)
        }