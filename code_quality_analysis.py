#!/usr/bin/env python3
"""
Comprehensive Code Quality Assessment Script
AGENT 5: Code Quality Assessment

Analyzes code quality across all modules using industry-standard metrics.
"""

import ast
import os
import sys
import json
import subprocess
import importlib.util
from pathlib import Path
from typing import Dict, List, Any, Set, Tuple
from collections import defaultdict
import re
from datetime import datetime

class CodeQualityAnalyzer:
    """Comprehensive code quality analyzer."""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.src_path = self.project_root / "src"
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "project_root": str(project_root),
            "metrics": {},
            "issues": {},
            "recommendations": [],
            "summary": {}
        }
        
    def analyze_all(self) -> Dict[str, Any]:
        """Run comprehensive code quality analysis."""
        print("🔍 Starting comprehensive code quality analysis...")
        
        # Get all Python files
        python_files = self._get_python_files()
        print(f"📁 Found {len(python_files)} Python files to analyze")
        
        # Run all analysis methods
        self.results["metrics"]["syntax_errors"] = self._check_syntax_errors(python_files)
        self.results["metrics"]["complexity"] = self._analyze_complexity(python_files)
        self.results["metrics"]["duplication"] = self._detect_duplication(python_files)
        self.results["metrics"]["naming_conventions"] = self._check_naming_conventions(python_files)
        self.results["metrics"]["type_hints"] = self._analyze_type_hints(python_files)
        self.results["metrics"]["docstrings"] = self._analyze_docstrings(python_files)
        self.results["metrics"]["imports"] = self._analyze_imports(python_files)
        self.results["metrics"]["function_metrics"] = self._analyze_function_metrics(python_files)
        self.results["metrics"]["code_style"] = self._check_code_style()
        
        # Generate summary and recommendations
        self._generate_summary()
        self._generate_recommendations()
        
        return self.results
    
    def _get_python_files(self) -> List[Path]:
        """Get all Python files in the project."""
        python_files = []
        
        # Main source files
        if self.src_path.exists():
            python_files.extend(self.src_path.rglob("*.py"))
        
        # Tests
        test_files = list(self.project_root.rglob("test_*.py"))
        python_files.extend(test_files)
        
        # Scripts
        scripts_path = self.project_root / "scripts"
        if scripts_path.exists():
            python_files.extend(scripts_path.rglob("*.py"))
        
        # Examples
        examples_path = self.project_root / "examples"
        if examples_path.exists():
            python_files.extend(examples_path.rglob("*.py"))
        
        return [f for f in python_files if f.is_file()]
    
    def _check_syntax_errors(self, files: List[Path]) -> Dict[str, Any]:
        """Check for syntax errors in Python files."""
        print("🔧 Checking syntax errors...")
        
        syntax_errors = []
        valid_files = []
        
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                ast.parse(content)
                valid_files.append(str(file_path))
            except SyntaxError as e:
                syntax_errors.append({
                    "file": str(file_path),
                    "line": e.lineno,
                    "error": str(e),
                    "text": e.text.strip() if e.text else ""
                })
            except Exception as e:
                syntax_errors.append({
                    "file": str(file_path),
                    "line": 0,
                    "error": f"Parse error: {str(e)}",
                    "text": ""
                })
        
        return {
            "total_files": len(files),
            "valid_files": len(valid_files),
            "files_with_errors": len(syntax_errors),
            "errors": syntax_errors,
            "error_rate": len(syntax_errors) / len(files) if files else 0
        }
    
    def _analyze_complexity(self, files: List[Path]) -> Dict[str, Any]:
        """Analyze cyclomatic complexity."""
        print("🧮 Analyzing cyclomatic complexity...")
        
        complexity_data = {
            "files": {},
            "high_complexity_functions": [],
            "average_complexity": 0,
            "max_complexity": 0
        }
        
        total_complexity = 0
        function_count = 0
        
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                tree = ast.parse(content)
                file_complexity = self._calculate_file_complexity(tree, str(file_path))
                complexity_data["files"][str(file_path)] = file_complexity
                
                for func_data in file_complexity["functions"]:
                    complexity = func_data["complexity"]
                    total_complexity += complexity
                    function_count += 1
                    
                    if complexity > 10:  # High complexity threshold
                        complexity_data["high_complexity_functions"].append({
                            "file": str(file_path),
                            "function": func_data["name"],
                            "complexity": complexity,
                            "line": func_data["line"]
                        })
                    
                    complexity_data["max_complexity"] = max(
                        complexity_data["max_complexity"], complexity
                    )
                        
            except Exception as e:
                print(f"Error analyzing {file_path}: {e}")
        
        if function_count > 0:
            complexity_data["average_complexity"] = total_complexity / function_count
        
        return complexity_data
    
    def _calculate_file_complexity(self, tree: ast.AST, file_path: str) -> Dict[str, Any]:
        """Calculate complexity metrics for a file."""
        functions = []
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                complexity = self._calculate_function_complexity(node)
                functions.append({
                    "name": node.name,
                    "line": node.lineno,
                    "complexity": complexity,
                    "type": "async" if isinstance(node, ast.AsyncFunctionDef) else "sync"
                })
        
        return {
            "functions": functions,
            "total_functions": len(functions),
            "average_complexity": sum(f["complexity"] for f in functions) / len(functions) if functions else 0
        }
    
    def _calculate_function_complexity(self, node: ast.FunctionDef) -> int:
        """Calculate cyclomatic complexity for a function."""
        complexity = 1  # Base complexity
        
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            elif isinstance(child, ast.ExceptHandler):
                complexity += 1
            elif isinstance(child, (ast.And, ast.Or)):
                complexity += 1
            elif isinstance(child, ast.comprehension):
                complexity += 1
        
        return complexity
    
    def _detect_duplication(self, files: List[Path]) -> Dict[str, Any]:
        """Detect code duplication."""
        print("🔍 Detecting code duplication...")
        
        # Simple duplicate detection based on function signatures and similar lines
        function_signatures = defaultdict(list)
        line_hashes = defaultdict(list)
        
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                
                # Parse AST for function signatures
                tree = ast.parse(''.join(lines))
                
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        # Create signature hash
                        sig = f"{node.name}({len(node.args.args)})"
                        function_signatures[sig].append({
                            "file": str(file_path),
                            "line": node.lineno,
                            "name": node.name
                        })
                
                # Hash non-empty lines for duplicate detection
                for i, line in enumerate(lines, 1):
                    clean_line = line.strip()
                    if clean_line and not clean_line.startswith('#'):
                        line_hashes[hash(clean_line)].append({
                            "file": str(file_path),
                            "line": i,
                            "content": clean_line[:50] + "..." if len(clean_line) > 50 else clean_line
                        })
                        
            except Exception as e:
                print(f"Error analyzing duplication in {file_path}: {e}")
        
        # Find duplicates
        duplicate_functions = {
            sig: locations for sig, locations in function_signatures.items()
            if len(locations) > 1
        }
        
        duplicate_lines = {
            hash_val: locations for hash_val, locations in line_hashes.items()
            if len(locations) > 1
        }
        
        return {
            "duplicate_functions": duplicate_functions,
            "duplicate_lines": len(duplicate_lines),
            "total_duplicate_line_instances": sum(len(locs) for locs in duplicate_lines.values()),
            "duplication_ratio": len(duplicate_lines) / len(line_hashes) if line_hashes else 0
        }
    
    def _check_naming_conventions(self, files: List[Path]) -> Dict[str, Any]:
        """Check naming convention adherence."""
        print("📝 Checking naming conventions...")
        
        naming_issues = []
        naming_stats = {
            "functions": {"total": 0, "compliant": 0},
            "classes": {"total": 0, "compliant": 0},
            "variables": {"total": 0, "compliant": 0},
            "constants": {"total": 0, "compliant": 0}
        }
        
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                tree = ast.parse(content)
                
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        naming_stats["functions"]["total"] += 1
                        if self._is_snake_case(node.name):
                            naming_stats["functions"]["compliant"] += 1
                        else:
                            naming_issues.append({
                                "file": str(file_path),
                                "line": node.lineno,
                                "type": "function",
                                "name": node.name,
                                "issue": "Should use snake_case"
                            })
                    
                    elif isinstance(node, ast.ClassDef):
                        naming_stats["classes"]["total"] += 1
                        if self._is_pascal_case(node.name):
                            naming_stats["classes"]["compliant"] += 1
                        else:
                            naming_issues.append({
                                "file": str(file_path),
                                "line": node.lineno,
                                "type": "class",
                                "name": node.name,
                                "issue": "Should use PascalCase"
                            })
                    
                    elif isinstance(node, ast.Assign):
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                if target.id.isupper():
                                    naming_stats["constants"]["total"] += 1
                                    if self._is_constant_case(target.id):
                                        naming_stats["constants"]["compliant"] += 1
                                    else:
                                        naming_issues.append({
                                            "file": str(file_path),
                                            "line": node.lineno,
                                            "type": "constant",
                                            "name": target.id,
                                            "issue": "Should use UPPER_SNAKE_CASE"
                                        })
                                else:
                                    naming_stats["variables"]["total"] += 1
                                    if self._is_snake_case(target.id):
                                        naming_stats["variables"]["compliant"] += 1
                                    else:
                                        naming_issues.append({
                                            "file": str(file_path),
                                            "line": node.lineno,
                                            "type": "variable",
                                            "name": target.id,
                                            "issue": "Should use snake_case"
                                        })
                        
            except Exception as e:
                print(f"Error checking naming in {file_path}: {e}")
        
        # Calculate compliance rates
        for category in naming_stats:
            total = naming_stats[category]["total"]
            compliant = naming_stats[category]["compliant"]
            naming_stats[category]["compliance_rate"] = compliant / total if total > 0 else 0
        
        return {
            "issues": naming_issues,
            "statistics": naming_stats,
            "total_issues": len(naming_issues)
        }
    
    def _is_snake_case(self, name: str) -> bool:
        """Check if name follows snake_case convention."""
        return re.match(r'^[a-z_][a-z0-9_]*$', name) is not None
    
    def _is_pascal_case(self, name: str) -> bool:
        """Check if name follows PascalCase convention."""
        return re.match(r'^[A-Z][a-zA-Z0-9]*$', name) is not None
    
    def _is_constant_case(self, name: str) -> bool:
        """Check if name follows CONSTANT_CASE convention."""
        return re.match(r'^[A-Z_][A-Z0-9_]*$', name) is not None
    
    def _analyze_type_hints(self, files: List[Path]) -> Dict[str, Any]:
        """Analyze type hint coverage."""
        print("🏷️ Analyzing type hint coverage...")
        
        type_hint_data = {
            "functions": {"total": 0, "with_hints": 0, "with_return_hints": 0},
            "function_parameters": {"total": 0, "with_hints": 0},
            "coverage_by_file": {}
        }
        
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                tree = ast.parse(content)
                file_functions = {"total": 0, "with_hints": 0}
                
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        type_hint_data["functions"]["total"] += 1
                        file_functions["total"] += 1
                        
                        has_return_hint = node.returns is not None
                        if has_return_hint:
                            type_hint_data["functions"]["with_return_hints"] += 1
                        
                        param_hints = 0
                        total_params = len(node.args.args)
                        
                        for arg in node.args.args:
                            type_hint_data["function_parameters"]["total"] += 1
                            if arg.annotation is not None:
                                param_hints += 1
                                type_hint_data["function_parameters"]["with_hints"] += 1
                        
                        # Function considered "with hints" if return and all params have hints
                        if has_return_hint and (total_params == 0 or param_hints == total_params):
                            type_hint_data["functions"]["with_hints"] += 1
                            file_functions["with_hints"] += 1
                
                # Calculate file coverage
                if file_functions["total"] > 0:
                    file_coverage = file_functions["with_hints"] / file_functions["total"]
                    type_hint_data["coverage_by_file"][str(file_path)] = {
                        "total_functions": file_functions["total"],
                        "functions_with_hints": file_functions["with_hints"],
                        "coverage": file_coverage
                    }
                        
            except Exception as e:
                print(f"Error analyzing type hints in {file_path}: {e}")
        
        # Calculate overall coverage
        functions_total = type_hint_data["functions"]["total"]
        functions_with_hints = type_hint_data["functions"]["with_hints"]
        params_total = type_hint_data["function_parameters"]["total"]
        params_with_hints = type_hint_data["function_parameters"]["with_hints"]
        
        type_hint_data["overall_function_coverage"] = (
            functions_with_hints / functions_total if functions_total > 0 else 0
        )
        type_hint_data["overall_parameter_coverage"] = (
            params_with_hints / params_total if params_total > 0 else 0
        )
        
        return type_hint_data
    
    def _analyze_docstrings(self, files: List[Path]) -> Dict[str, Any]:
        """Analyze docstring coverage and quality."""
        print("📚 Analyzing docstring coverage...")
        
        docstring_data = {
            "modules": {"total": 0, "with_docstrings": 0},
            "classes": {"total": 0, "with_docstrings": 0},
            "functions": {"total": 0, "with_docstrings": 0},
            "coverage_by_file": {},
            "quality_issues": []
        }
        
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                tree = ast.parse(content)
                file_stats = {
                    "classes": {"total": 0, "with_docstrings": 0},
                    "functions": {"total": 0, "with_docstrings": 0}
                }
                
                # Module docstring
                docstring_data["modules"]["total"] += 1
                if ast.get_docstring(tree):
                    docstring_data["modules"]["with_docstrings"] += 1
                
                for node in ast.walk(tree):
                    if isinstance(node, ast.ClassDef):
                        docstring_data["classes"]["total"] += 1
                        file_stats["classes"]["total"] += 1
                        
                        docstring = ast.get_docstring(node)
                        if docstring:
                            docstring_data["classes"]["with_docstrings"] += 1
                            file_stats["classes"]["with_docstrings"] += 1
                            
                            # Check docstring quality
                            if len(docstring.strip()) < 10:
                                docstring_data["quality_issues"].append({
                                    "file": str(file_path),
                                    "line": node.lineno,
                                    "type": "class",
                                    "name": node.name,
                                    "issue": "Docstring too short"
                                })
                    
                    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        # Skip private methods for docstring requirements
                        if not node.name.startswith('_'):
                            docstring_data["functions"]["total"] += 1
                            file_stats["functions"]["total"] += 1
                            
                            docstring = ast.get_docstring(node)
                            if docstring:
                                docstring_data["functions"]["with_docstrings"] += 1
                                file_stats["functions"]["with_docstrings"] += 1
                                
                                # Check docstring quality
                                if len(docstring.strip()) < 10:
                                    docstring_data["quality_issues"].append({
                                        "file": str(file_path),
                                        "line": node.lineno,
                                        "type": "function",
                                        "name": node.name,
                                        "issue": "Docstring too short"
                                    })
                
                # Calculate file coverage
                total_items = file_stats["classes"]["total"] + file_stats["functions"]["total"]
                documented_items = (file_stats["classes"]["with_docstrings"] + 
                                  file_stats["functions"]["with_docstrings"])
                
                if total_items > 0:
                    docstring_data["coverage_by_file"][str(file_path)] = {
                        "total_items": total_items,
                        "documented_items": documented_items,
                        "coverage": documented_items / total_items,
                        "details": file_stats
                    }
                        
            except Exception as e:
                print(f"Error analyzing docstrings in {file_path}: {e}")
        
        # Calculate overall coverage
        for category in ["modules", "classes", "functions"]:
            total = docstring_data[category]["total"]
            with_docs = docstring_data[category]["with_docstrings"]
            docstring_data[category]["coverage"] = with_docs / total if total > 0 else 0
        
        return docstring_data
    
    def _analyze_imports(self, files: List[Path]) -> Dict[str, Any]:
        """Analyze import organization and style."""
        print("📦 Analyzing import organization...")
        
        import_data = {
            "total_imports": 0,
            "import_issues": [],
            "unused_imports": [],
            "import_organization": {},
            "circular_imports": []
        }
        
        all_imports = defaultdict(list)
        
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    content = ''.join(lines)
                
                tree = ast.parse(content)
                file_imports = []
                
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            import_data["total_imports"] += 1
                            file_imports.append(alias.name)
                            all_imports[alias.name].append(str(file_path))
                    
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            import_data["total_imports"] += 1
                            file_imports.append(node.module)
                            all_imports[node.module].append(str(file_path))
                
                # Check import organization within file
                import_lines = []
                for i, line in enumerate(lines):
                    if line.strip().startswith(('import ', 'from ')):
                        import_lines.append((i + 1, line.strip()))
                
                # Check if imports are at the top
                non_import_found = False
                for i, line in enumerate(lines):
                    if line.strip() and not line.strip().startswith(('#', '"""', "'''", 'import ', 'from ')):
                        non_import_found = True
                    elif non_import_found and line.strip().startswith(('import ', 'from ')):
                        import_data["import_issues"].append({
                            "file": str(file_path),
                            "line": i + 1,
                            "issue": "Import not at top of file",
                            "content": line.strip()
                        })
                
                import_data["import_organization"][str(file_path)] = {
                    "total_imports": len(file_imports),
                    "import_lines": import_lines
                }
                        
            except Exception as e:
                print(f"Error analyzing imports in {file_path}: {e}")
        
        return import_data
    
    def _analyze_function_metrics(self, files: List[Path]) -> Dict[str, Any]:
        """Analyze function and class size metrics."""
        print("📏 Analyzing function and class metrics...")
        
        metrics_data = {
            "functions": [],
            "classes": [],
            "large_functions": [],
            "large_classes": [],
            "statistics": {
                "avg_function_length": 0,
                "avg_class_length": 0,
                "max_function_length": 0,
                "max_class_length": 0
            }
        }
        
        function_lengths = []
        class_lengths = []
        
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    content = ''.join(lines)
                
                tree = ast.parse(content)
                
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        # Calculate function length
                        start_line = node.lineno
                        end_line = node.end_lineno if hasattr(node, 'end_lineno') else start_line
                        length = end_line - start_line + 1
                        
                        function_data = {
                            "file": str(file_path),
                            "name": node.name,
                            "start_line": start_line,
                            "length": length,
                            "parameters": len(node.args.args),
                            "type": "async" if isinstance(node, ast.AsyncFunctionDef) else "sync"
                        }
                        
                        metrics_data["functions"].append(function_data)
                        function_lengths.append(length)
                        
                        # Flag large functions (>50 lines)
                        if length > 50:
                            metrics_data["large_functions"].append(function_data)
                    
                    elif isinstance(node, ast.ClassDef):
                        # Calculate class length
                        start_line = node.lineno
                        end_line = node.end_lineno if hasattr(node, 'end_lineno') else start_line
                        length = end_line - start_line + 1
                        
                        # Count methods
                        methods = [n for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
                        
                        class_data = {
                            "file": str(file_path),
                            "name": node.name,
                            "start_line": start_line,
                            "length": length,
                            "methods": len(methods),
                            "bases": len(node.bases)
                        }
                        
                        metrics_data["classes"].append(class_data)
                        class_lengths.append(length)
                        
                        # Flag large classes (>200 lines)
                        if length > 200:
                            metrics_data["large_classes"].append(class_data)
                        
            except Exception as e:
                print(f"Error analyzing metrics in {file_path}: {e}")
        
        # Calculate statistics
        if function_lengths:
            metrics_data["statistics"]["avg_function_length"] = sum(function_lengths) / len(function_lengths)
            metrics_data["statistics"]["max_function_length"] = max(function_lengths)
        
        if class_lengths:
            metrics_data["statistics"]["avg_class_length"] = sum(class_lengths) / len(class_lengths)
            metrics_data["statistics"]["max_class_length"] = max(class_lengths)
        
        return metrics_data
    
    def _check_code_style(self) -> Dict[str, Any]:
        """Check code style compliance using available tools."""
        print("🎨 Checking code style compliance...")
        
        style_data = {
            "tools_available": {},
            "style_issues": [],
            "compliance_score": 0
        }
        
        # Check which tools are available
        tools = ["black", "flake8", "isort"]
        venv_path = self.project_root / "venv_bulletproof" / "bin"
        
        for tool in tools:
            tool_path = venv_path / tool
            style_data["tools_available"][tool] = tool_path.exists()
        
        # Run available style checkers
        if style_data["tools_available"].get("black"):
            try:
                result = subprocess.run(
                    [str(venv_path / "black"), "--check", "--diff", str(self.src_path)],
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode != 0:
                    style_data["style_issues"].append({
                        "tool": "black",
                        "message": "Code formatting issues detected",
                        "details": result.stdout[:500] if result.stdout else result.stderr[:500]
                    })
            except Exception as e:
                style_data["style_issues"].append({
                    "tool": "black",
                    "message": f"Error running black: {e}",
                    "details": ""
                })
        
        # Calculate compliance score based on available checks
        total_checks = len([t for t in style_data["tools_available"].values() if t])
        failed_checks = len(style_data["style_issues"])
        style_data["compliance_score"] = (total_checks - failed_checks) / total_checks if total_checks > 0 else 0
        
        return style_data
    
    def _generate_summary(self):
        """Generate overall quality summary."""
        print("📊 Generating quality summary...")
        
        metrics = self.results["metrics"]
        
        # Calculate overall scores
        scores = {}
        
        # Syntax score
        syntax_errors = metrics.get("syntax_errors", {})
        scores["syntax"] = 1.0 - syntax_errors.get("error_rate", 0)
        
        # Complexity score (penalize high complexity)
        complexity = metrics.get("complexity", {})
        avg_complexity = complexity.get("average_complexity", 0)
        scores["complexity"] = max(0, 1.0 - (avg_complexity - 5) / 10) if avg_complexity > 5 else 1.0
        
        # Type hints score
        type_hints = metrics.get("type_hints", {})
        scores["type_hints"] = type_hints.get("overall_function_coverage", 0)
        
        # Docstring score
        docstrings = metrics.get("docstrings", {})
        scores["docstrings"] = (
            (docstrings.get("classes", {}).get("coverage", 0) + 
             docstrings.get("functions", {}).get("coverage", 0)) / 2
        )
        
        # Naming score
        naming = metrics.get("naming_conventions", {})
        naming_stats = naming.get("statistics", {})
        total_compliance = sum(
            category.get("compliance_rate", 0) 
            for category in naming_stats.values()
        )
        scores["naming"] = total_compliance / len(naming_stats) if naming_stats else 0
        
        # Style score
        style = metrics.get("code_style", {})
        scores["style"] = style.get("compliance_score", 0)
        
        # Overall quality score
        overall_score = sum(scores.values()) / len(scores)
        
        self.results["summary"] = {
            "overall_score": overall_score,
            "grade": self._get_quality_grade(overall_score),
            "individual_scores": scores,
            "key_statistics": {
                "total_files": len(self._get_python_files()),
                "total_functions": metrics.get("function_metrics", {}).get("statistics", {}).get("total_functions", 0),
                "total_classes": len(metrics.get("function_metrics", {}).get("classes", [])),
                "syntax_error_rate": syntax_errors.get("error_rate", 0),
                "high_complexity_functions": len(complexity.get("high_complexity_functions", [])),
                "type_hint_coverage": type_hints.get("overall_function_coverage", 0),
                "docstring_coverage": docstrings.get("functions", {}).get("coverage", 0)
            }
        }
    
    def _get_quality_grade(self, score: float) -> str:
        """Convert numeric score to letter grade."""
        if score >= 0.9:
            return "A"
        elif score >= 0.8:
            return "B"
        elif score >= 0.7:
            return "C"
        elif score >= 0.6:
            return "D"
        else:
            return "F"
    
    def _generate_recommendations(self):
        """Generate improvement recommendations."""
        print("💡 Generating improvement recommendations...")
        
        metrics = self.results["metrics"]
        recommendations = []
        
        # Syntax errors
        syntax_errors = metrics.get("syntax_errors", {})
        if syntax_errors.get("files_with_errors", 0) > 0:
            recommendations.append({
                "priority": "critical",
                "category": "syntax",
                "title": "Fix Syntax Errors",
                "description": f"There are {syntax_errors.get('files_with_errors', 0)} files with syntax errors that prevent proper code analysis.",
                "action": "Review and fix syntax errors in affected files."
            })
        
        # High complexity
        complexity = metrics.get("complexity", {})
        high_complexity_funcs = complexity.get("high_complexity_functions", [])
        if len(high_complexity_funcs) > 0:
            recommendations.append({
                "priority": "high",
                "category": "complexity",
                "title": "Reduce Function Complexity",
                "description": f"Found {len(high_complexity_funcs)} functions with high cyclomatic complexity (>10).",
                "action": "Refactor complex functions by breaking them into smaller, more focused functions."
            })
        
        # Type hints
        type_hints = metrics.get("type_hints", {})
        coverage = type_hints.get("overall_function_coverage", 0)
        if coverage < 0.8:
            recommendations.append({
                "priority": "medium",
                "category": "type_safety",
                "title": "Improve Type Hint Coverage",
                "description": f"Type hint coverage is {coverage:.1%}. Consider adding type hints to improve code clarity and catch errors early.",
                "action": "Add type hints to function parameters and return types."
            })
        
        # Docstrings
        docstrings = metrics.get("docstrings", {})
        doc_coverage = docstrings.get("functions", {}).get("coverage", 0)
        if doc_coverage < 0.7:
            recommendations.append({
                "priority": "medium",
                "category": "documentation",
                "title": "Improve Documentation Coverage",
                "description": f"Function docstring coverage is {doc_coverage:.1%}. Good documentation improves code maintainability.",
                "action": "Add comprehensive docstrings to public functions and classes."
            })
        
        # Large functions
        function_metrics = metrics.get("function_metrics", {})
        large_functions = function_metrics.get("large_functions", [])
        if len(large_functions) > 0:
            recommendations.append({
                "priority": "medium",
                "category": "maintainability",
                "title": "Refactor Large Functions",
                "description": f"Found {len(large_functions)} functions with >50 lines. Large functions can be harder to understand and test.",
                "action": "Consider breaking large functions into smaller, more focused functions."
            })
        
        # Code style
        style = metrics.get("code_style", {})
        style_issues = style.get("style_issues", [])
        if len(style_issues) > 0:
            recommendations.append({
                "priority": "low",
                "category": "style",
                "title": "Address Code Style Issues",
                "description": f"Found {len(style_issues)} code style issues.",
                "action": "Run code formatters like black and follow PEP 8 guidelines."
            })
        
        self.results["recommendations"] = recommendations


def main():
    """Main entry point for code quality analysis."""
    project_root = "/home/louranicas/projects/claude-optimized-deployment"
    
    analyzer = CodeQualityAnalyzer(project_root)
    results = analyzer.analyze_all()
    
    # Save results
    output_file = Path(project_root) / "code_quality_report.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    # Print summary
    print("\n" + "="*80)
    print("🎯 CODE QUALITY ASSESSMENT SUMMARY")
    print("="*80)
    
    summary = results["summary"]
    print(f"Overall Quality Score: {summary['overall_score']:.2f} (Grade: {summary['grade']})")
    print()
    
    print("Individual Scores:")
    for category, score in summary["individual_scores"].items():
        print(f"  {category.replace('_', ' ').title()}: {score:.2f}")
    print()
    
    print("Key Statistics:")
    stats = summary["key_statistics"]
    for key, value in stats.items():
        if isinstance(value, float):
            print(f"  {key.replace('_', ' ').title()}: {value:.2%}")
        else:
            print(f"  {key.replace('_', ' ').title()}: {value}")
    print()
    
    print("Priority Recommendations:")
    for rec in results["recommendations"][:5]:  # Top 5 recommendations
        priority_icon = {"critical": "🚨", "high": "⚠️", "medium": "📝", "low": "💡"}.get(rec["priority"], "📝")
        print(f"  {priority_icon} {rec['title']} ({rec['priority'].upper()})")
        print(f"    {rec['description']}")
        print()
    
    print(f"📄 Full report saved to: {output_file}")
    print("="*80)


if __name__ == "__main__":
    main()