"""Coding style classifier for consistent code generation"""

from typing import List, Dict, Any, Optional
from collections import defaultdict, Counter
import re
import logging

logger = logging.getLogger(__name__)

class CodingStyleClassifier:
    """Classify and learn coding style preferences"""
    
    def __init__(self):
        self.style_stats = defaultdict(Counter)
        self.language_styles = {
            'python': PythonStyleAnalyzer(),
            'javascript': JavaScriptStyleAnalyzer(),
            'typescript': JavaScriptStyleAnalyzer(),  # Similar to JS
            'rust': RustStyleAnalyzer(),
        }
        self.learned_preferences = {}
        
    async def classify(self, patterns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Classify coding style from patterns"""
        style_features = defaultdict(Counter)
        
        for pattern in patterns:
            language = pattern.get('language', 'unknown')
            content = pattern.get('content', '')
            
            if language in self.language_styles:
                analyzer = self.language_styles[language]
                features = analyzer.analyze(content)
                
                for feature, value in features.items():
                    style_features[feature][value] += 1
        
        # Convert to most common style
        style = {}
        for feature, counter in style_features.items():
            if counter:
                style[feature] = counter.most_common(1)[0][0]
                # Update stats
                self.style_stats[feature].update(counter)
        
        # Add learned preferences
        style.update(self.learned_preferences)
        
        return style
    
    def learn_preference(self, feature: str, value: Any):
        """Learn a specific style preference"""
        self.learned_preferences[feature] = value
        logger.info(f"Learned preference: {feature} = {value}")
    
    async def export(self) -> Dict[str, Any]:
        """Export classifier state"""
        return {
            'style_stats': {k: dict(v) for k, v in self.style_stats.items()},
            'learned_preferences': self.learned_preferences,
        }
    
    async def import_model(self, model_data: Dict[str, Any]):
        """Import classifier state"""
        self.style_stats = defaultdict(Counter)
        for feature, counts in model_data.get('style_stats', {}).items():
            self.style_stats[feature] = Counter(counts)
        
        self.learned_preferences = model_data.get('learned_preferences', {})
        logger.info(f"Imported style classifier with {len(self.style_stats)} features")
    
    def get_style_summary(self) -> Dict[str, Any]:
        """Get summary of learned styles"""
        summary = {}
        
        for feature, counter in self.style_stats.items():
            total = sum(counter.values())
            if total > 0:
                # Get top 3 most common values
                top_values = counter.most_common(3)
                summary[feature] = {
                    'most_common': top_values[0][0] if top_values else None,
                    'distribution': {
                        value: count / total 
                        for value, count in top_values
                    }
                }
        
        return summary


class PythonStyleAnalyzer:
    """Analyze Python-specific style features"""
    
    def analyze(self, code: str) -> Dict[str, Any]:
        features = {}
        
        # Indentation style
        if '\t' in code:
            features['indentation'] = 'tabs'
        else:
            # Check space count
            indents = re.findall(r'^( +)', code, re.MULTILINE)
            if indents:
                space_counts = [len(indent) for indent in indents]
                most_common = Counter(space_counts).most_common(1)
                if most_common:
                    features['indentation'] = f"{most_common[0][0]}_spaces"
                else:
                    features['indentation'] = '4_spaces'
            else:
                features['indentation'] = '4_spaces'
        
        # Quote style
        single_quotes = code.count("'")
        double_quotes = code.count('"')
        features['quote_style'] = 'single' if single_quotes > double_quotes else 'double'
        
        # Type hints
        if '->' in code or ': ' in re.sub(r':\s*$', '', code, flags=re.MULTILINE):
            features['type_hints'] = 'yes'
        else:
            features['type_hints'] = 'no'
        
        # Docstring style
        if '"""' in code:
            features['docstring_style'] = 'triple_double'
        elif "'''" in code:
            features['docstring_style'] = 'triple_single'
        else:
            features['docstring_style'] = 'none'
        
        # Import style
        if 'from ' in code and 'import ' in code:
            features['import_style'] = 'from_import'
        elif 'import ' in code:
            features['import_style'] = 'direct_import'
        
        # Naming convention
        if re.search(r'def [a-z_]+\(', code):
            features['function_naming'] = 'snake_case'
        elif re.search(r'def [a-z][a-zA-Z]*\(', code):
            features['function_naming'] = 'camelCase'
        
        if re.search(r'class [A-Z][a-zA-Z]*', code):
            features['class_naming'] = 'PascalCase'
        
        return features


class JavaScriptStyleAnalyzer:
    """Analyze JavaScript/TypeScript-specific style features"""
    
    def analyze(self, code: str) -> Dict[str, Any]:
        features = {}
        
        # Semicolons
        features['semicolons'] = 'yes' if ';' in code else 'no'
        
        # Quote style
        single_quotes = code.count("'")
        double_quotes = code.count('"')
        backticks = code.count('`')
        
        if backticks > single_quotes and backticks > double_quotes:
            features['quote_style'] = 'backticks'
        elif single_quotes > double_quotes:
            features['quote_style'] = 'single'
        else:
            features['quote_style'] = 'double'
        
        # Arrow functions vs function keyword
        if '=>' in code:
            features['function_style'] = 'arrow'
        elif 'function' in code:
            features['function_style'] = 'function_keyword'
        
        # Const/let/var
        if 'const ' in code:
            features['variable_declaration'] = 'const'
        elif 'let ' in code:
            features['variable_declaration'] = 'let'
        elif 'var ' in code:
            features['variable_declaration'] = 'var'
        
        # Import style
        if 'import ' in code and ' from ' in code:
            features['import_style'] = 'es6'
        elif 'require(' in code:
            features['import_style'] = 'commonjs'
        
        # Trailing commas
        if re.search(r',\s*[}\]]', code):
            features['trailing_commas'] = 'yes'
        else:
            features['trailing_commas'] = 'no'
        
        # Bracket spacing
        if '{ ' in code or ' }' in code:
            features['bracket_spacing'] = 'yes'
        else:
            features['bracket_spacing'] = 'no'
        
        return features


class RustStyleAnalyzer:
    """Analyze Rust-specific style features"""
    
    def analyze(self, code: str) -> Dict[str, Any]:
        features = {}
        
        # Use statements
        if 'use ' in code:
            if '::*' in code:
                features['import_style'] = 'glob'
            elif '{' in code and '}' in code:
                features['import_style'] = 'grouped'
            else:
                features['import_style'] = 'single'
        
        # Error handling style
        if '.unwrap()' in code:
            features['error_handling'] = 'unwrap'
        elif '?' in code:
            features['error_handling'] = 'question_mark'
        elif 'match ' in code and 'Ok(' in code:
            features['error_handling'] = 'match'
        
        # Lifetime usage
        if re.search(r"'[a-z]", code):
            features['lifetimes'] = 'explicit'
        else:
            features['lifetimes'] = 'elided'
        
        # Trait bounds style
        if 'where' in code:
            features['trait_bounds'] = 'where_clause'
        elif '<' in code and '>' in code and ':' in code:
            features['trait_bounds'] = 'inline'
        
        # Documentation style
        if '///' in code:
            features['doc_style'] = 'triple_slash'
        elif '//!' in code:
            features['doc_style'] = 'inner_doc'
        
        return features