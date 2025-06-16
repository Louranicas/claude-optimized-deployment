#!/usr/bin/env python3
"""
ULTRA THINK MODE: Comprehensive Code Quality Assessment Tool

This script performs deep analysis of code quality across multiple languages:
1. Code complexity metrics
2. Duplicate code detection
3. Dead code identification
4. Circular dependencies
5. Module coupling issues
6. Naming convention violations
7. Documentation coverage
8. Type safety issues
9. Error handling patterns
10. Best practices violations
"""

import os
import re
import ast
import json
import hashlib
import subprocess
from pathlib import Path
from collections import defaultdict, Counter
from dataclasses import dataclass, asdict
from typing import Dict, List, Set, Tuple, Optional, Any
import sys
import importlib.util
from datetime import datetime

@dataclass
class QualityMetrics:
    """Data class to hold code quality metrics"""
    file_path: str
    language: str
    lines_of_code: int
    cyclomatic_complexity: int
    cognitive_complexity: int
    maintainability_index: float
    code_duplicates: List[Dict]
    dead_code_percentage: float
    documentation_coverage: float
    type_safety_score: float
    error_handling_score: float
    naming_violations: List[str]
    circular_dependencies: List[str]
    coupling_score: float
    best_practice_violations: List[str]

class CodeQualityAnalyzer:
    """Comprehensive code quality analyzer for multiple languages"""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.results = {}
        self.global_metrics = {}
        self.code_hashes = defaultdict(list)
        self.import_graph = defaultdict(set)
        
    def analyze_project(self):
        """Main analysis entry point"""
        print("🚀 Starting ULTRA THINK MODE Code Quality Assessment...")
        
        # Analyze different file types
        python_files = list(self.project_root.glob("**/*.py"))
        rust_files = list(self.project_root.glob("**/*.rs"))
        js_files = list(self.project_root.glob("**/*.js"))
        ts_files = list(self.project_root.glob("**/*.ts"))
        
        # Filter out virtual environments and node_modules
        python_files = [f for f in python_files if not any(part in str(f) for part in ['venv', 'node_modules', '__pycache__', '.git'])]
        rust_files = [f for f in rust_files if not any(part in str(f) for part in ['target', 'node_modules', '.git'])]
        js_files = [f for f in js_files if not any(part in str(f) for part in ['node_modules', 'venv', '.git'])]
        ts_files = [f for f in ts_files if not any(part in str(f) for part in ['node_modules', 'venv', '.git'])]
        
        print(f"📊 Found {len(python_files)} Python files")
        print(f"📊 Found {len(rust_files)} Rust files")
        print(f"📊 Found {len(js_files)} JavaScript files")
        print(f"📊 Found {len(ts_files)} TypeScript files")
        
        # Analyze each language
        for py_file in python_files[:50]:  # Limit for performance
            try:
                self.analyze_python_file(py_file)
            except Exception as e:
                print(f"❌ Error analyzing {py_file}: {e}")
                
        for rust_file in rust_files[:20]:  # Limit for performance
            try:
                self.analyze_rust_file(rust_file)
            except Exception as e:
                print(f"❌ Error analyzing {rust_file}: {e}")
                
        for js_file in js_files[:10]:  # Limit for performance
            try:
                self.analyze_javascript_file(js_file)
            except Exception as e:
                print(f"❌ Error analyzing {js_file}: {e}")
        
        # Detect circular dependencies
        self.detect_circular_dependencies()
        
        # Calculate global metrics
        self.calculate_global_metrics()
        
        return self.generate_report()
    
    def analyze_python_file(self, file_path: Path):
        """Analyze a Python file for quality metrics"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            return
            
        # Parse AST
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return
            
        # Calculate metrics
        lines_of_code = len([line for line in content.split('\n') if line.strip() and not line.strip().startswith('#')])
        cyclomatic_complexity = self.calculate_cyclomatic_complexity_python(tree)
        cognitive_complexity = self.calculate_cognitive_complexity_python(tree)
        maintainability_index = self.calculate_maintainability_index(lines_of_code, cyclomatic_complexity)
        
        # Detect code duplicates
        code_blocks = self.extract_code_blocks_python(tree)
        duplicates = self.detect_duplicates(code_blocks, str(file_path))
        
        # Analyze documentation
        doc_coverage = self.calculate_documentation_coverage_python(tree)
        
        # Type safety analysis
        type_safety = self.analyze_type_safety_python(tree, content)
        
        # Error handling analysis
        error_handling = self.analyze_error_handling_python(tree)
        
        # Naming convention analysis
        naming_violations = self.check_naming_conventions_python(tree)
        
        # Best practices violations
        best_practices = self.check_best_practices_python(tree, content)
        
        # Extract imports for dependency analysis
        self.extract_imports_python(tree, str(file_path))
        
        # Dead code analysis
        dead_code_percentage = self.analyze_dead_code_python(tree)
        
        # Module coupling
        coupling_score = self.calculate_coupling_score_python(tree)
        
        metrics = QualityMetrics(
            file_path=str(file_path),
            language="Python",
            lines_of_code=lines_of_code,
            cyclomatic_complexity=cyclomatic_complexity,
            cognitive_complexity=cognitive_complexity,
            maintainability_index=maintainability_index,
            code_duplicates=duplicates,
            dead_code_percentage=dead_code_percentage,
            documentation_coverage=doc_coverage,
            type_safety_score=type_safety,
            error_handling_score=error_handling,
            naming_violations=naming_violations,
            circular_dependencies=[],  # Will be filled later
            coupling_score=coupling_score,
            best_practice_violations=best_practices
        )
        
        self.results[str(file_path)] = metrics
    
    def analyze_rust_file(self, file_path: Path):
        """Analyze a Rust file for quality metrics"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception:
            return
            
        lines_of_code = len([line for line in content.split('\n') if line.strip() and not line.strip().startswith('//')])
        
        # Basic Rust analysis
        cyclomatic_complexity = self.calculate_cyclomatic_complexity_rust(content)
        naming_violations = self.check_naming_conventions_rust(content)
        error_handling = self.analyze_error_handling_rust(content)
        doc_coverage = self.calculate_documentation_coverage_rust(content)
        best_practices = self.check_best_practices_rust(content)
        
        metrics = QualityMetrics(
            file_path=str(file_path),
            language="Rust",
            lines_of_code=lines_of_code,
            cyclomatic_complexity=cyclomatic_complexity,
            cognitive_complexity=cyclomatic_complexity,  # Simplified
            maintainability_index=self.calculate_maintainability_index(lines_of_code, cyclomatic_complexity),
            code_duplicates=[],
            dead_code_percentage=0.0,  # Hard to detect in Rust without compiler
            documentation_coverage=doc_coverage,
            type_safety_score=95.0,  # Rust has excellent type safety
            error_handling_score=error_handling,
            naming_violations=naming_violations,
            circular_dependencies=[],
            coupling_score=50.0,  # Default
            best_practice_violations=best_practices
        )
        
        self.results[str(file_path)] = metrics
    
    def analyze_javascript_file(self, file_path: Path):
        """Analyze a JavaScript file for quality metrics"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception:
            return
            
        lines_of_code = len([line for line in content.split('\n') if line.strip() and not line.strip().startswith('//')])
        
        # Basic JavaScript analysis
        cyclomatic_complexity = self.calculate_cyclomatic_complexity_js(content)
        naming_violations = self.check_naming_conventions_js(content)
        error_handling = self.analyze_error_handling_js(content)
        best_practices = self.check_best_practices_js(content)
        
        metrics = QualityMetrics(
            file_path=str(file_path),
            language="JavaScript",
            lines_of_code=lines_of_code,
            cyclomatic_complexity=cyclomatic_complexity,
            cognitive_complexity=cyclomatic_complexity,
            maintainability_index=self.calculate_maintainability_index(lines_of_code, cyclomatic_complexity),
            code_duplicates=[],
            dead_code_percentage=0.0,
            documentation_coverage=20.0,  # Generally low in JS
            type_safety_score=30.0,  # JavaScript has weak typing
            error_handling_score=error_handling,
            naming_violations=naming_violations,
            circular_dependencies=[],
            coupling_score=60.0,
            best_practice_violations=best_practices
        )
        
        self.results[str(file_path)] = metrics
    
    def calculate_cyclomatic_complexity_python(self, tree: ast.AST) -> int:
        """Calculate cyclomatic complexity for Python"""
        complexity = 1  # Base complexity
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            elif isinstance(node, ast.ExceptHandler):
                complexity += 1
            elif isinstance(node, (ast.And, ast.Or)):
                complexity += 1
            elif isinstance(node, ast.ListComp):
                complexity += 1
                
        return complexity
    
    def calculate_cognitive_complexity_python(self, tree: ast.AST) -> int:
        """Calculate cognitive complexity for Python"""
        complexity = 0
        nesting_level = 0
        
        def analyze_node(node, nesting=0):
            nonlocal complexity
            
            if isinstance(node, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1 + nesting
                nesting += 1
            elif isinstance(node, ast.ExceptHandler):
                complexity += 1 + nesting
            elif isinstance(node, (ast.And, ast.Or)):
                complexity += 1
                
            for child in ast.iter_child_nodes(node):
                analyze_node(child, nesting)
                
        analyze_node(tree)
        return complexity
    
    def calculate_maintainability_index(self, loc: int, complexity: int) -> float:
        """Calculate maintainability index"""
        if loc == 0:
            return 100.0
            
        # Simplified MI calculation
        mi = max(0, (171 - 5.2 * (complexity / loc) * 100 - 0.23 * complexity - 16.2 * (loc / 1000)) * 100 / 171)
        return min(100.0, mi)
    
    def extract_code_blocks_python(self, tree: ast.AST) -> List[str]:
        """Extract code blocks for duplicate detection"""
        blocks = []
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                # Get the source code for this node (simplified)
                block_hash = hashlib.md5(ast.dump(node).encode()).hexdigest()
                blocks.append(block_hash)
                
        return blocks
    
    def detect_duplicates(self, code_blocks: List[str], file_path: str) -> List[Dict]:
        """Detect duplicate code blocks"""
        duplicates = []
        
        for block in code_blocks:
            self.code_hashes[block].append(file_path)
            
        # Find duplicates
        for block_hash, files in self.code_hashes.items():
            if len(files) > 1:
                duplicates.append({
                    "hash": block_hash,
                    "files": files,
                    "count": len(files)
                })
                
        return duplicates
    
    def calculate_documentation_coverage_python(self, tree: ast.AST) -> float:
        """Calculate documentation coverage for Python"""
        total_functions = 0
        documented_functions = 0
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                total_functions += 1
                if ast.get_docstring(node):
                    documented_functions += 1
                    
        if total_functions == 0:
            return 100.0
            
        return (documented_functions / total_functions) * 100
    
    def analyze_type_safety_python(self, tree: ast.AST, content: str) -> float:
        """Analyze type safety in Python code"""
        total_functions = 0
        typed_functions = 0
        
        # Check for type annotations
        has_typing_import = 'typing' in content or 'from typing' in content
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                total_functions += 1
                
                # Check if function has type annotations
                if node.returns or any(arg.annotation for arg in node.args.args):
                    typed_functions += 1
                    
        type_coverage = (typed_functions / total_functions * 100) if total_functions > 0 else 0
        
        # Bonus for using typing module
        bonus = 10 if has_typing_import else 0
        
        return min(100.0, type_coverage + bonus)
    
    def analyze_error_handling_python(self, tree: ast.AST) -> float:
        """Analyze error handling patterns"""
        total_functions = 0
        functions_with_error_handling = 0
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                total_functions += 1
                
                # Check if function contains try-except blocks
                for child in ast.walk(node):
                    if isinstance(child, ast.Try):
                        functions_with_error_handling += 1
                        break
                        
        if total_functions == 0:
            return 100.0
            
        return (functions_with_error_handling / total_functions) * 100
    
    def check_naming_conventions_python(self, tree: ast.AST) -> List[str]:
        """Check Python naming conventions"""
        violations = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                if not re.match(r'^[a-z_][a-z0-9_]*$', node.name):
                    violations.append(f"Function '{node.name}' violates snake_case convention")
                    
            elif isinstance(node, ast.ClassDef):
                if not re.match(r'^[A-Z][a-zA-Z0-9]*$', node.name):
                    violations.append(f"Class '{node.name}' violates PascalCase convention")
                    
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                if node.name.isupper() and len(node.name) > 1:
                    # Constants should be UPPER_CASE
                    if not re.match(r'^[A-Z_][A-Z0-9_]*$', node.name):
                        violations.append(f"Constant '{node.name}' violates UPPER_CASE convention")
                        
        return violations
    
    def check_best_practices_python(self, tree: ast.AST, content: str) -> List[str]:
        """Check Python best practices"""
        violations = []
        
        # Check for bare except clauses
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                violations.append("Bare except clause found - should specify exception type")
                
        # Check for global variables
        for node in ast.walk(tree):
            if isinstance(node, ast.Global):
                violations.append(f"Global variable usage found: {', '.join(node.names)}")
                
        # Check line length (simplified)
        long_lines = [i+1 for i, line in enumerate(content.split('\n')) if len(line) > 100]
        if long_lines:
            violations.append(f"Lines too long (>100 chars): {long_lines[:5]}")
            
        return violations
    
    def extract_imports_python(self, tree: ast.AST, file_path: str):
        """Extract imports for dependency analysis"""
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.import_graph[file_path].add(alias.name)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    self.import_graph[file_path].add(node.module)
    
    def analyze_dead_code_python(self, tree: ast.AST) -> float:
        """Analyze dead code percentage (simplified)"""
        # This is a simplified analysis - real dead code detection is complex
        defined_functions = set()
        called_functions = set()
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                defined_functions.add(node.name)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                called_functions.add(node.func.id)
                
        if not defined_functions:
            return 0.0
            
        dead_functions = defined_functions - called_functions
        return (len(dead_functions) / len(defined_functions)) * 100
    
    def calculate_coupling_score_python(self, tree: ast.AST) -> float:
        """Calculate module coupling score"""
        import_count = 0
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                import_count += 1
                
        # Higher import count = higher coupling
        # Normalize to 0-100 scale
        return min(100.0, import_count * 5)
    
    def calculate_cyclomatic_complexity_rust(self, content: str) -> int:
        """Calculate cyclomatic complexity for Rust (simplified)"""
        complexity = 1
        
        # Count control flow keywords
        keywords = ['if', 'while', 'for', 'match', 'loop']
        for keyword in keywords:
            complexity += content.count(f' {keyword} ')
            complexity += content.count(f'\n{keyword} ')
            
        return complexity
    
    def check_naming_conventions_rust(self, content: str) -> List[str]:
        """Check Rust naming conventions"""
        violations = []
        
        # Find function definitions
        fn_pattern = r'fn\s+([a-zA-Z_][a-zA-Z0-9_]*)'
        for match in re.finditer(fn_pattern, content):
            fn_name = match.group(1)
            if not re.match(r'^[a-z_][a-z0-9_]*$', fn_name):
                violations.append(f"Rust function '{fn_name}' violates snake_case convention")
                
        # Find struct definitions
        struct_pattern = r'struct\s+([a-zA-Z_][a-zA-Z0-9_]*)'
        for match in re.finditer(struct_pattern, content):
            struct_name = match.group(1)
            if not re.match(r'^[A-Z][a-zA-Z0-9]*$', struct_name):
                violations.append(f"Rust struct '{struct_name}' violates PascalCase convention")
                
        return violations
    
    def analyze_error_handling_rust(self, content: str) -> float:
        """Analyze Rust error handling"""
        # Count Result/Option usage
        result_count = content.count('Result<')
        option_count = content.count('Option<')
        unwrap_count = content.count('.unwrap()')
        expect_count = content.count('.expect(')
        
        total_error_handling = result_count + option_count + expect_count
        bad_practices = unwrap_count
        
        if total_error_handling == 0:
            return 50.0  # Neutral score
            
        # Score based on good vs bad practices
        score = ((total_error_handling - bad_practices) / total_error_handling) * 100
        return max(0.0, score)
    
    def calculate_documentation_coverage_rust(self, content: str) -> float:
        """Calculate Rust documentation coverage"""
        # Count doc comments
        doc_comments = content.count('///')
        doc_blocks = content.count('/*!')
        
        # Count functions/structs/enums
        functions = len(re.findall(r'fn\s+\w+', content))
        structs = len(re.findall(r'struct\s+\w+', content))
        enums = len(re.findall(r'enum\s+\w+', content))
        
        total_items = functions + structs + enums
        total_docs = doc_comments + doc_blocks
        
        if total_items == 0:
            return 100.0
            
        return min(100.0, (total_docs / total_items) * 100)
    
    def check_best_practices_rust(self, content: str) -> List[str]:
        """Check Rust best practices"""
        violations = []
        
        # Check for unwrap usage
        if '.unwrap()' in content:
            violations.append("Usage of .unwrap() found - consider using .expect() or proper error handling")
            
        # Check for unsafe blocks
        if 'unsafe {' in content:
            violations.append("Unsafe block found - ensure safety invariants")
            
        # Check for clone usage
        clone_count = content.count('.clone()')
        if clone_count > 5:
            violations.append(f"Excessive .clone() usage ({clone_count}) - consider borrowing")
            
        return violations
    
    def calculate_cyclomatic_complexity_js(self, content: str) -> int:
        """Calculate cyclomatic complexity for JavaScript (simplified)"""
        complexity = 1
        
        keywords = ['if', 'while', 'for', 'switch', 'case', '&&', '||', '?']
        for keyword in keywords:
            complexity += content.count(keyword)
            
        return complexity
    
    def check_naming_conventions_js(self, content: str) -> List[str]:
        """Check JavaScript naming conventions"""
        violations = []
        
        # Find function declarations
        fn_pattern = r'function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)'
        for match in re.finditer(fn_pattern, content):
            fn_name = match.group(1)
            if not re.match(r'^[a-z$_][a-zA-Z0-9$_]*$', fn_name):
                violations.append(f"JavaScript function '{fn_name}' violates camelCase convention")
                
        # Find class declarations
        class_pattern = r'class\s+([a-zA-Z_$][a-zA-Z0-9_$]*)'
        for match in re.finditer(class_pattern, content):
            class_name = match.group(1)
            if not re.match(r'^[A-Z][a-zA-Z0-9$_]*$', class_name):
                violations.append(f"JavaScript class '{class_name}' violates PascalCase convention")
                
        return violations
    
    def analyze_error_handling_js(self, content: str) -> float:
        """Analyze JavaScript error handling"""
        try_count = content.count('try {')
        catch_count = content.count('catch')
        throw_count = content.count('throw ')
        
        total_error_handling = try_count + catch_count + throw_count
        
        # Basic scoring
        if total_error_handling == 0:
            return 30.0  # Low score for no error handling
            
        return min(100.0, total_error_handling * 20)
    
    def check_best_practices_js(self, content: str) -> List[str]:
        """Check JavaScript best practices"""
        violations = []
        
        # Check for var usage
        if ' var ' in content:
            violations.append("Usage of 'var' found - prefer 'let' or 'const'")
            
        # Check for == instead of ===
        if ' == ' in content or ' != ' in content:
            violations.append("Usage of == or != found - prefer === or !==")
            
        # Check for console.log in production code
        if 'console.log' in content:
            violations.append("console.log statements found - remove before production")
            
        return violations
    
    def detect_circular_dependencies(self):
        """Detect circular dependencies using DFS"""
        def has_cycle(node, visited, rec_stack, path):
            visited.add(node)
            rec_stack.add(node)
            path.append(node)
            
            for neighbor in self.import_graph.get(node, []):
                if neighbor not in visited:
                    if has_cycle(neighbor, visited, rec_stack, path):
                        return True
                elif neighbor in rec_stack:
                    # Found a cycle
                    cycle_start = path.index(neighbor)
                    cycle = path[cycle_start:] + [neighbor]
                    for file_path in cycle:
                        if file_path in self.results:
                            self.results[file_path].circular_dependencies.append(" -> ".join(cycle))
                    return True
                    
            rec_stack.remove(node)
            path.pop()
            return False
        
        visited = set()
        for node in self.import_graph:
            if node not in visited:
                has_cycle(node, visited, set(), [])
    
    def calculate_global_metrics(self):
        """Calculate project-wide quality metrics"""
        if not self.results:
            return
            
        total_files = len(self.results)
        total_loc = sum(m.lines_of_code for m in self.results.values())
        avg_complexity = sum(m.cyclomatic_complexity for m in self.results.values()) / total_files
        avg_maintainability = sum(m.maintainability_index for m in self.results.values()) / total_files
        avg_doc_coverage = sum(m.documentation_coverage for m in self.results.values()) / total_files
        avg_type_safety = sum(m.type_safety_score for m in self.results.values()) / total_files
        
        # Count violations
        total_naming_violations = sum(len(m.naming_violations) for m in self.results.values())
        total_best_practice_violations = sum(len(m.best_practice_violations) for m in self.results.values())
        
        # Language distribution
        language_dist = Counter(m.language for m in self.results.values())
        
        self.global_metrics = {
            "total_files_analyzed": total_files,
            "total_lines_of_code": total_loc,
            "average_cyclomatic_complexity": round(avg_complexity, 2),
            "average_maintainability_index": round(avg_maintainability, 2),
            "average_documentation_coverage": round(avg_doc_coverage, 2),
            "average_type_safety_score": round(avg_type_safety, 2),
            "total_naming_violations": total_naming_violations,
            "total_best_practice_violations": total_best_practice_violations,
            "language_distribution": dict(language_dist),
            "code_quality_grade": self.calculate_quality_grade(avg_maintainability, avg_doc_coverage, avg_type_safety)
        }
    
    def calculate_quality_grade(self, maintainability: float, doc_coverage: float, type_safety: float) -> str:
        """Calculate overall code quality grade"""
        overall_score = (maintainability + doc_coverage + type_safety) / 3
        
        if overall_score >= 90:
            return "A+"
        elif overall_score >= 80:
            return "A"
        elif overall_score >= 70:
            return "B"
        elif overall_score >= 60:
            return "C"
        elif overall_score >= 50:
            return "D"
        else:
            return "F"
    
    def generate_report(self) -> Dict:
        """Generate comprehensive quality report"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Find worst offenders
        worst_complexity = max(self.results.values(), key=lambda x: x.cyclomatic_complexity, default=None)
        worst_maintainability = min(self.results.values(), key=lambda x: x.maintainability_index, default=None)
        best_documented = max(self.results.values(), key=lambda x: x.documentation_coverage, default=None)
        
        # Duplicate code analysis
        all_duplicates = []
        for metrics in self.results.values():
            all_duplicates.extend(metrics.code_duplicates)
        
        # Priority recommendations
        recommendations = self.generate_recommendations()
        
        report = {
            "analysis_timestamp": timestamp,
            "project_root": str(self.project_root),
            "global_metrics": self.global_metrics,
            "detailed_file_metrics": {path: asdict(metrics) for path, metrics in self.results.items()},
            "worst_offenders": {
                "highest_complexity": asdict(worst_complexity) if worst_complexity else None,
                "lowest_maintainability": asdict(worst_maintainability) if worst_maintainability else None,
                "best_documented": asdict(best_documented) if best_documented else None
            },
            "duplicate_code_summary": {
                "total_duplicate_blocks": len(all_duplicates),
                "duplicate_details": all_duplicates[:10]  # Show top 10
            },
            "recommendations": recommendations,
            "refactoring_priorities": self.generate_refactoring_priorities()
        }
        
        return report
    
    def generate_recommendations(self) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if not self.results:
            return ["No files analyzed"]
        
        avg_complexity = sum(m.cyclomatic_complexity for m in self.results.values()) / len(self.results)
        avg_doc_coverage = sum(m.documentation_coverage for m in self.results.values()) / len(self.results)
        avg_type_safety = sum(m.type_safety_score for m in self.results.values()) / len(self.results)
        
        if avg_complexity > 10:
            recommendations.append("🔴 HIGH PRIORITY: Reduce cyclomatic complexity by breaking down large functions")
            
        if avg_doc_coverage < 50:
            recommendations.append("📚 MEDIUM PRIORITY: Improve documentation coverage by adding docstrings")
            
        if avg_type_safety < 70:
            recommendations.append("🏷️ MEDIUM PRIORITY: Add type annotations to improve type safety")
            
        total_violations = sum(len(m.naming_violations) + len(m.best_practice_violations) for m in self.results.values())
        if total_violations > 20:
            recommendations.append("⚠️ LOW PRIORITY: Fix naming convention and best practice violations")
            
        return recommendations
    
    def generate_refactoring_priorities(self) -> List[Dict]:
        """Generate refactoring priorities based on metrics"""
        priorities = []
        
        for path, metrics in self.results.items():
            priority_score = 0
            reasons = []
            
            if metrics.cyclomatic_complexity > 15:
                priority_score += 3
                reasons.append(f"High complexity ({metrics.cyclomatic_complexity})")
                
            if metrics.maintainability_index < 40:
                priority_score += 2
                reasons.append(f"Low maintainability ({metrics.maintainability_index:.1f})")
                
            if len(metrics.best_practice_violations) > 5:
                priority_score += 1
                reasons.append(f"Many violations ({len(metrics.best_practice_violations)})")
                
            if priority_score > 0:
                priorities.append({
                    "file": path,
                    "priority_score": priority_score,
                    "reasons": reasons,
                    "language": metrics.language
                })
        
        # Sort by priority score
        priorities.sort(key=lambda x: x["priority_score"], reverse=True)
        return priorities[:10]  # Top 10 priorities

def main():
    """Main execution function"""
    project_root = "/home/louranicas/projects/claude-optimized-deployment"
    
    analyzer = CodeQualityAnalyzer(project_root)
    report = analyzer.analyze_project()
    
    # Save report
    report_file = os.path.join(project_root, "comprehensive_code_quality_report.json")
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"\n✅ Analysis complete! Report saved to: {report_file}")
    
    # Print summary
    if "global_metrics" in report:
        metrics = report["global_metrics"]
        print(f"\n📊 QUALITY SUMMARY:")
        print(f"   Files Analyzed: {metrics.get('total_files_analyzed', 0)}")
        print(f"   Total Lines of Code: {metrics.get('total_lines_of_code', 0):,}")
        print(f"   Overall Quality Grade: {metrics.get('code_quality_grade', 'N/A')}")
        print(f"   Average Complexity: {metrics.get('average_cyclomatic_complexity', 0)}")
        print(f"   Documentation Coverage: {metrics.get('average_documentation_coverage', 0):.1f}%")
        print(f"   Type Safety Score: {metrics.get('average_type_safety_score', 0):.1f}%")
    
    return report

if __name__ == "__main__":
    main()