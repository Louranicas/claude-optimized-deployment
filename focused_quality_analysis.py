#!/usr/bin/env python3
"""
Focused Code Quality Assessment for Core Modules
AGENT 5: Code Quality Assessment

Quick analysis focusing on main source code modules.
"""

import ast
import os
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Any
from collections import defaultdict
import re
from datetime import datetime

def analyze_syntax_errors(files: List[Path]) -> Dict[str, Any]:
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
                "file": str(file_path.relative_to(Path.cwd())),
                "line": e.lineno,
                "error": str(e),
                "text": e.text.strip() if e.text else ""
            })
        except Exception as e:
            syntax_errors.append({
                "file": str(file_path.relative_to(Path.cwd())),
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

def analyze_complexity(files: List[Path]) -> Dict[str, Any]:
    """Analyze cyclomatic complexity."""
    print("🧮 Analyzing cyclomatic complexity...")
    
    high_complexity_functions = []
    all_complexities = []
    
    for file_path in files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    complexity = calculate_function_complexity(node)
                    all_complexities.append(complexity)
                    
                    if complexity > 10:  # High complexity threshold
                        high_complexity_functions.append({
                            "file": str(file_path.relative_to(Path.cwd())),
                            "function": node.name,
                            "complexity": complexity,
                            "line": node.lineno
                        })
                        
        except Exception as e:
            print(f"Error analyzing complexity in {file_path}: {e}")
    
    return {
        "high_complexity_functions": high_complexity_functions,
        "average_complexity": sum(all_complexities) / len(all_complexities) if all_complexities else 0,
        "max_complexity": max(all_complexities) if all_complexities else 0,
        "total_functions": len(all_complexities)
    }

def calculate_function_complexity(node: ast.FunctionDef) -> int:
    """Calculate cyclomatic complexity for a function."""
    complexity = 1  # Base complexity
    
    for child in ast.walk(node):
        if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor)):
            complexity += 1
        elif isinstance(child, ast.ExceptHandler):
            complexity += 1
        elif isinstance(child, (ast.And, ast.Or)):
            complexity += 1
    
    return complexity

def analyze_type_hints(files: List[Path]) -> Dict[str, Any]:
    """Analyze type hint coverage."""
    print("🏷️ Analyzing type hint coverage...")
    
    total_functions = 0
    functions_with_hints = 0
    functions_with_return_hints = 0
    
    for file_path in files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    total_functions += 1
                    
                    has_return_hint = node.returns is not None
                    if has_return_hint:
                        functions_with_return_hints += 1
                    
                    # Check parameter hints
                    param_hints = sum(1 for arg in node.args.args if arg.annotation is not None)
                    total_params = len(node.args.args)
                    
                    # Function considered "with hints" if return and all params have hints
                    if has_return_hint and (total_params == 0 or param_hints == total_params):
                        functions_with_hints += 1
                        
        except Exception as e:
            print(f"Error analyzing type hints in {file_path}: {e}")
    
    return {
        "total_functions": total_functions,
        "functions_with_hints": functions_with_hints,
        "functions_with_return_hints": functions_with_return_hints,
        "coverage": functions_with_hints / total_functions if total_functions > 0 else 0
    }

def analyze_docstrings(files: List[Path]) -> Dict[str, Any]:
    """Analyze docstring coverage."""
    print("📚 Analyzing docstring coverage...")
    
    total_functions = 0
    functions_with_docs = 0
    total_classes = 0
    classes_with_docs = 0
    
    for file_path in files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    total_classes += 1
                    if ast.get_docstring(node):
                        classes_with_docs += 1
                
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    # Skip private methods for docstring requirements
                    if not node.name.startswith('_'):
                        total_functions += 1
                        if ast.get_docstring(node):
                            functions_with_docs += 1
                        
        except Exception as e:
            print(f"Error analyzing docstrings in {file_path}: {e}")
    
    return {
        "total_functions": total_functions,
        "functions_with_docs": functions_with_docs,
        "function_coverage": functions_with_docs / total_functions if total_functions > 0 else 0,
        "total_classes": total_classes,
        "classes_with_docs": classes_with_docs,
        "class_coverage": classes_with_docs / total_classes if total_classes > 0 else 0
    }

def analyze_function_sizes(files: List[Path]) -> Dict[str, Any]:
    """Analyze function and class sizes."""
    print("📏 Analyzing function sizes...")
    
    large_functions = []
    large_classes = []
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
                    start_line = node.lineno
                    end_line = node.end_lineno if hasattr(node, 'end_lineno') else start_line
                    length = end_line - start_line + 1
                    function_lengths.append(length)
                    
                    if length > 50:  # Large function threshold
                        large_functions.append({
                            "file": str(file_path.relative_to(Path.cwd())),
                            "function": node.name,
                            "length": length,
                            "line": start_line
                        })
                
                elif isinstance(node, ast.ClassDef):
                    start_line = node.lineno
                    end_line = node.end_lineno if hasattr(node, 'end_lineno') else start_line
                    length = end_line - start_line + 1
                    class_lengths.append(length)
                    
                    if length > 200:  # Large class threshold
                        large_classes.append({
                            "file": str(file_path.relative_to(Path.cwd())),
                            "class": node.name,
                            "length": length,
                            "line": start_line
                        })
                        
        except Exception as e:
            print(f"Error analyzing sizes in {file_path}: {e}")
    
    return {
        "large_functions": large_functions,
        "large_classes": large_classes,
        "avg_function_length": sum(function_lengths) / len(function_lengths) if function_lengths else 0,
        "avg_class_length": sum(class_lengths) / len(class_lengths) if class_lengths else 0,
        "max_function_length": max(function_lengths) if function_lengths else 0,
        "max_class_length": max(class_lengths) if class_lengths else 0
    }

def check_naming_conventions(files: List[Path]) -> Dict[str, Any]:
    """Check naming convention adherence."""
    print("📝 Checking naming conventions...")
    
    naming_issues = []
    stats = {
        "functions": {"total": 0, "compliant": 0},
        "classes": {"total": 0, "compliant": 0},
        "variables": {"total": 0, "compliant": 0}
    }
    
    def is_snake_case(name: str) -> bool:
        return re.match(r'^[a-z_][a-z0-9_]*$', name) is not None
    
    def is_pascal_case(name: str) -> bool:
        return re.match(r'^[A-Z][a-zA-Z0-9]*$', name) is not None
    
    for file_path in files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    stats["functions"]["total"] += 1
                    if is_snake_case(node.name):
                        stats["functions"]["compliant"] += 1
                    else:
                        naming_issues.append({
                            "file": str(file_path.relative_to(Path.cwd())),
                            "line": node.lineno,
                            "type": "function",
                            "name": node.name,
                            "issue": "Should use snake_case"
                        })
                
                elif isinstance(node, ast.ClassDef):
                    stats["classes"]["total"] += 1
                    if is_pascal_case(node.name):
                        stats["classes"]["compliant"] += 1
                    else:
                        naming_issues.append({
                            "file": str(file_path.relative_to(Path.cwd())),
                            "line": node.lineno,
                            "type": "class",
                            "name": node.name,
                            "issue": "Should use PascalCase"
                        })
                        
        except Exception as e:
            print(f"Error checking naming in {file_path}: {e}")
    
    # Calculate compliance rates
    for category in stats:
        total = stats[category]["total"]
        compliant = stats[category]["compliant"]
        stats[category]["compliance_rate"] = compliant / total if total > 0 else 0
    
    return {
        "issues": naming_issues,
        "statistics": stats,
        "total_issues": len(naming_issues)
    }

def main():
    """Main analysis function."""
    project_root = Path("/home/louranicas/projects/claude-optimized-deployment")
    src_path = project_root / "src"
    
    # Get core Python files only
    core_files = []
    if src_path.exists():
        for pattern in ["**/*.py"]:
            core_files.extend(src_path.glob(pattern))
    
    # Filter out __pycache__ and focus on main modules
    core_files = [f for f in core_files if "__pycache__" not in str(f) and f.is_file()]
    
    print(f"🔍 Analyzing {len(core_files)} core Python files...")
    
    # Run analyses
    results = {
        "timestamp": datetime.now().isoformat(),
        "total_files": len(core_files),
        "syntax_errors": analyze_syntax_errors(core_files),
        "complexity": analyze_complexity(core_files),
        "type_hints": analyze_type_hints(core_files),
        "docstrings": analyze_docstrings(core_files),
        "function_sizes": analyze_function_sizes(core_files),
        "naming_conventions": check_naming_conventions(core_files)
    }
    
    # Calculate overall quality score
    scores = {}
    scores["syntax"] = 1.0 - results["syntax_errors"]["error_rate"]
    scores["complexity"] = max(0, 1.0 - (results["complexity"]["average_complexity"] - 5) / 10)
    scores["type_hints"] = results["type_hints"]["coverage"]
    scores["docstrings"] = (results["docstrings"]["function_coverage"] + results["docstrings"]["class_coverage"]) / 2
    scores["naming"] = sum(cat["compliance_rate"] for cat in results["naming_conventions"]["statistics"].values()) / 3
    
    overall_score = sum(scores.values()) / len(scores)
    
    def get_grade(score):
        if score >= 0.9: return "A"
        elif score >= 0.8: return "B"
        elif score >= 0.7: return "C"
        elif score >= 0.6: return "D"
        else: return "F"
    
    results["summary"] = {
        "overall_score": overall_score,
        "grade": get_grade(overall_score),
        "individual_scores": scores
    }
    
    # Save results
    output_file = project_root / "focused_quality_report.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    # Print summary
    print("\n" + "="*80)
    print("🎯 FOCUSED CODE QUALITY ASSESSMENT SUMMARY")
    print("="*80)
    
    print(f"Overall Quality Score: {overall_score:.2f} (Grade: {get_grade(overall_score)})")
    print()
    
    print("Individual Scores:")
    for category, score in scores.items():
        print(f"  {category.replace('_', ' ').title()}: {score:.2f}")
    print()
    
    print("Key Issues Found:")
    if results["syntax_errors"]["files_with_errors"] > 0:
        print(f"  🚨 {results['syntax_errors']['files_with_errors']} files with syntax errors")
    
    if len(results["complexity"]["high_complexity_functions"]) > 0:
        print(f"  ⚠️  {len(results['complexity']['high_complexity_functions'])} high-complexity functions")
    
    if len(results["function_sizes"]["large_functions"]) > 0:
        print(f"  📏 {len(results['function_sizes']['large_functions'])} large functions (>50 lines)")
    
    if results["type_hints"]["coverage"] < 0.8:
        print(f"  🏷️  Low type hint coverage: {results['type_hints']['coverage']:.1%}")
    
    if results["docstrings"]["function_coverage"] < 0.7:
        print(f"  📚 Low docstring coverage: {results['docstrings']['function_coverage']:.1%}")
    
    print()
    print(f"📄 Full report saved to: {output_file}")
    print("="*80)

if __name__ == "__main__":
    main()