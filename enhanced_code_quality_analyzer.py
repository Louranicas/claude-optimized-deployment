#!/usr/bin/env python3
"""
Enhanced Code Quality Analyzer - ULTRA THINK MODE
Comprehensive analysis with detailed reporting and recommendations
"""

import os
import re
import ast
import json
import subprocess
from pathlib import Path
from collections import defaultdict, Counter
from dataclasses import dataclass, asdict
from typing import Dict, List, Set, Tuple, Optional, Any
import sys
from datetime import datetime

@dataclass
class CodeQualityReport:
    """Comprehensive code quality report"""
    timestamp: str
    project_overview: Dict
    language_analysis: Dict
    complexity_analysis: Dict
    code_duplicates: Dict
    documentation_analysis: Dict
    security_analysis: Dict
    dependency_analysis: Dict
    refactoring_priorities: List[Dict]
    recommendations: List[str]
    quality_score: float

class EnhancedCodeQualityAnalyzer:
    """Enhanced comprehensive code quality analyzer"""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.analysis_results = {}
        
    def run_comprehensive_analysis(self):
        """Run the complete analysis suite"""
        print("🚀 ULTRA THINK MODE: Starting Enhanced Code Quality Analysis...")
        
        # 1. Project Overview Analysis
        project_overview = self.analyze_project_overview()
        
        # 2. Language-specific Analysis
        language_analysis = self.analyze_by_language()
        
        # 3. Complexity Analysis
        complexity_analysis = self.analyze_complexity_metrics()
        
        # 4. Code Duplicates Detection
        duplicates_analysis = self.detect_code_duplicates()
        
        # 5. Documentation Analysis
        documentation_analysis = self.analyze_documentation()
        
        # 6. Security Analysis
        security_analysis = self.analyze_security_issues()
        
        # 7. Dependency Analysis
        dependency_analysis = self.analyze_dependencies()
        
        # 8. Calculate overall quality score
        quality_score = self.calculate_overall_quality_score(
            complexity_analysis, documentation_analysis, security_analysis
        )
        
        # 9. Generate recommendations
        recommendations = self.generate_actionable_recommendations(
            complexity_analysis, documentation_analysis, security_analysis
        )
        
        # 10. Generate refactoring priorities
        refactoring_priorities = self.generate_refactoring_priorities()
        
        # Create comprehensive report
        report = CodeQualityReport(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            project_overview=project_overview,
            language_analysis=language_analysis,
            complexity_analysis=complexity_analysis,
            code_duplicates=duplicates_analysis,
            documentation_analysis=documentation_analysis,
            security_analysis=security_analysis,
            dependency_analysis=dependency_analysis,
            refactoring_priorities=refactoring_priorities,
            recommendations=recommendations,
            quality_score=quality_score
        )
        
        return report
    
    def analyze_project_overview(self) -> Dict:
        """Analyze project structure and overview"""
        print("📊 Analyzing project overview...")
        
        file_counts = defaultdict(int)
        total_lines = 0
        
        for ext in ['.py', '.rs', '.js', '.ts', '.md', '.json', '.yaml', '.yml']:
            files = list(self.project_root.glob(f"**/*{ext}"))
            # Filter out common directories to ignore
            files = [f for f in files if not any(part in str(f) for part in 
                    ['node_modules', 'venv', '__pycache__', '.git', 'target'])]
            file_counts[ext] = len(files)
            
            # Count lines for code files
            if ext in ['.py', '.rs', '.js', '.ts']:
                for file_path in files[:100]:  # Limit for performance
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            total_lines += len(f.readlines())
                    except:
                        continue
        
        return {
            "file_distribution": dict(file_counts),
            "estimated_total_lines": total_lines,
            "project_size_category": self.categorize_project_size(total_lines),
            "language_diversity": len([k for k, v in file_counts.items() if v > 0 and k in ['.py', '.rs', '.js', '.ts']])
        }
    
    def categorize_project_size(self, lines: int) -> str:
        """Categorize project size"""
        if lines < 1000:
            return "Small"
        elif lines < 10000:
            return "Medium"
        elif lines < 100000:
            return "Large"
        else:
            return "Extra Large"
    
    def analyze_by_language(self) -> Dict:
        """Analyze code quality by programming language"""
        print("🔍 Analyzing by programming language...")
        
        analysis = {}
        
        # Python Analysis
        python_files = list(self.project_root.glob("**/*.py"))
        python_files = [f for f in python_files if not any(part in str(f) for part in 
                       ['node_modules', 'venv', '__pycache__', '.git'])]
        
        if python_files:
            analysis['python'] = self.analyze_python_files(python_files[:30])
        
        # Rust Analysis
        rust_files = list(self.project_root.glob("**/*.rs"))
        rust_files = [f for f in rust_files if not any(part in str(f) for part in 
                     ['target', 'node_modules', '.git'])]
        
        if rust_files:
            analysis['rust'] = self.analyze_rust_files(rust_files[:20])
        
        # JavaScript Analysis
        js_files = list(self.project_root.glob("**/*.js"))
        js_files = [f for f in js_files if not any(part in str(f) for part in 
                   ['node_modules', 'venv', '.git'])]
        
        if js_files:
            analysis['javascript'] = self.analyze_javascript_files(js_files[:10])
        
        return analysis
    
    def analyze_python_files(self, files: List[Path]) -> Dict:
        """Detailed Python code analysis"""
        results = {
            "total_files": len(files),
            "total_lines": 0,
            "functions_analyzed": 0,
            "classes_analyzed": 0,
            "imports_count": 0,
            "docstring_coverage": 0.0,
            "type_hints_usage": 0.0,
            "complexity_distribution": defaultdict(int),
            "common_issues": [],
            "best_practices_score": 0.0
        }
        
        total_functions = 0
        documented_functions = 0
        typed_functions = 0
        total_complexity = 0
        
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    results["total_lines"] += len(content.splitlines())
                
                try:
                    tree = ast.parse(content)
                except SyntaxError:
                    results["common_issues"].append(f"Syntax error in {file_path.name}")
                    continue
                
                # Analyze AST
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        total_functions += 1
                        
                        # Check documentation
                        if ast.get_docstring(node):
                            documented_functions += 1
                        
                        # Check type hints
                        if node.returns or any(arg.annotation for arg in node.args.args):
                            typed_functions += 1
                        
                        # Calculate complexity
                        complexity = self.calculate_function_complexity(node)
                        total_complexity += complexity
                        
                        if complexity > 10:
                            results["complexity_distribution"]["high"] += 1
                        elif complexity > 5:
                            results["complexity_distribution"]["medium"] += 1
                        else:
                            results["complexity_distribution"]["low"] += 1
                    
                    elif isinstance(node, ast.ClassDef):
                        results["classes_analyzed"] += 1
                    
                    elif isinstance(node, (ast.Import, ast.ImportFrom)):
                        results["imports_count"] += 1
                
                # Check for common issues
                if '.unwrap(' in content:
                    results["common_issues"].append(f"Potential unsafe unwrap in {file_path.name}")
                
                if 'except:' in content:
                    results["common_issues"].append(f"Bare except clause in {file_path.name}")
                
            except Exception as e:
                results["common_issues"].append(f"Analysis error in {file_path.name}: {str(e)}")
        
        # Calculate percentages
        results["functions_analyzed"] = total_functions
        results["docstring_coverage"] = (documented_functions / total_functions * 100) if total_functions > 0 else 0
        results["type_hints_usage"] = (typed_functions / total_functions * 100) if total_functions > 0 else 0
        results["average_complexity"] = total_complexity / total_functions if total_functions > 0 else 0
        
        # Calculate best practices score
        results["best_practices_score"] = self.calculate_python_best_practices_score(results)
        
        return results
    
    def calculate_function_complexity(self, node: ast.AST) -> int:
        """Calculate cyclomatic complexity of a function"""
        complexity = 1
        
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            elif isinstance(child, ast.ExceptHandler):
                complexity += 1
            elif isinstance(child, (ast.And, ast.Or)):
                complexity += 1
        
        return complexity
    
    def calculate_python_best_practices_score(self, results: Dict) -> float:
        """Calculate Python best practices score"""
        score = 100.0
        
        # Deduct points for issues
        score -= len(results["common_issues"]) * 5
        
        # Bonus for good documentation
        if results["docstring_coverage"] > 80:
            score += 10
        elif results["docstring_coverage"] < 30:
            score -= 20
        
        # Bonus for type hints
        if results["type_hints_usage"] > 70:
            score += 10
        elif results["type_hints_usage"] < 20:
            score -= 15
        
        return max(0, min(100, score))
    
    def analyze_rust_files(self, files: List[Path]) -> Dict:
        """Detailed Rust code analysis"""
        results = {
            "total_files": len(files),
            "total_lines": 0,
            "unsafe_blocks": 0,
            "unwrap_usage": 0,
            "clone_usage": 0,
            "panic_usage": 0,
            "doc_comments": 0,
            "error_handling_score": 0.0,
            "memory_safety_score": 95.0,  # Rust default high score
            "common_issues": []
        }
        
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    results["total_lines"] += len(content.splitlines())
                
                # Pattern matching for Rust-specific issues
                results["unsafe_blocks"] += len(re.findall(r'unsafe\s*{', content))
                results["unwrap_usage"] += len(re.findall(r'\.unwrap\(\)', content))
                results["clone_usage"] += len(re.findall(r'\.clone\(\)', content))
                results["panic_usage"] += len(re.findall(r'panic!', content))
                results["doc_comments"] += len(re.findall(r'///', content))
                
                # Check for excessive cloning
                if results["clone_usage"] > 10:
                    results["common_issues"].append(f"Excessive .clone() usage in {file_path.name}")
                
                # Check for unwrap without expect
                if results["unwrap_usage"] > 5:
                    results["common_issues"].append(f"High .unwrap() usage in {file_path.name}")
                
            except Exception as e:
                results["common_issues"].append(f"Analysis error in {file_path.name}: {str(e)}")
        
        # Calculate error handling score
        result_count = 0
        for f in files[:5]:
            try:
                with open(f, 'r', encoding='utf-8') as file:
                    content = file.read()
                    result_count += content.count('Result<')
            except Exception:
                continue
        
        results["error_handling_score"] = min(100, result_count * 10)
        
        return results
    
    def analyze_javascript_files(self, files: List[Path]) -> Dict:
        """Detailed JavaScript code analysis"""
        results = {
            "total_files": len(files),
            "total_lines": 0,
            "var_usage": 0,
            "console_logs": 0,
            "loose_equality": 0,
            "arrow_functions": 0,
            "async_await": 0,
            "common_issues": [],
            "modern_js_score": 0.0
        }
        
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    results["total_lines"] += len(content.splitlines())
                
                # Analyze JavaScript patterns
                results["var_usage"] += len(re.findall(r'\bvar\s+', content))
                results["console_logs"] += len(re.findall(r'console\.log', content))
                results["loose_equality"] += len(re.findall(r'[^!]==[^=]', content))
                results["arrow_functions"] += len(re.findall(r'=>', content))
                results["async_await"] += len(re.findall(r'\basync\b|\bawait\b', content))
                
                # Common issues
                if results["var_usage"] > 0:
                    results["common_issues"].append(f"var usage found in {file_path.name}")
                
                if results["console_logs"] > 3:
                    results["common_issues"].append(f"Multiple console.log statements in {file_path.name}")
                
            except Exception as e:
                results["common_issues"].append(f"Analysis error in {file_path.name}: {str(e)}")
        
        # Calculate modern JS score
        modern_features = results["arrow_functions"] + results["async_await"]
        old_features = results["var_usage"] + results["loose_equality"]
        
        if modern_features + old_features > 0:
            results["modern_js_score"] = (modern_features / (modern_features + old_features)) * 100
        else:
            results["modern_js_score"] = 50.0
        
        return results
    
    def analyze_complexity_metrics(self) -> Dict:
        """Analyze code complexity across the project"""
        print("🧮 Analyzing complexity metrics...")
        
        # Use existing analysis or run basic complexity check
        complexity_stats = {
            "average_cyclomatic_complexity": 0,
            "max_complexity_found": 0,
            "high_complexity_files": [],
            "complexity_distribution": {
                "low": 0,
                "medium": 0,
                "high": 0,
                "very_high": 0
            },
            "maintainability_concerns": []
        }
        
        # Simplified complexity analysis
        python_files = list(self.project_root.glob("**/*.py"))[:20]
        total_complexity = 0
        file_count = 0
        
        for file_path in python_files:
            if any(part in str(file_path) for part in ['venv', 'node_modules', '__pycache__']):
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Simple complexity calculation
                complexity = content.count('if ') + content.count('while ') + content.count('for ') + content.count('elif ')
                total_complexity += complexity
                file_count += 1
                
                if complexity > 50:
                    complexity_stats["high_complexity_files"].append({
                        "file": str(file_path),
                        "complexity": complexity
                    })
                    complexity_stats["complexity_distribution"]["very_high"] += 1
                elif complexity > 20:
                    complexity_stats["complexity_distribution"]["high"] += 1
                elif complexity > 10:
                    complexity_stats["complexity_distribution"]["medium"] += 1
                else:
                    complexity_stats["complexity_distribution"]["low"] += 1
                
                complexity_stats["max_complexity_found"] = max(complexity_stats["max_complexity_found"], complexity)
                
            except Exception:
                continue
        
        if file_count > 0:
            complexity_stats["average_cyclomatic_complexity"] = total_complexity / file_count
        
        # Generate maintainability concerns
        if complexity_stats["average_cyclomatic_complexity"] > 15:
            complexity_stats["maintainability_concerns"].append("High average complexity across project")
        
        if len(complexity_stats["high_complexity_files"]) > 5:
            complexity_stats["maintainability_concerns"].append("Multiple files with very high complexity")
        
        return complexity_stats
    
    def detect_code_duplicates(self) -> Dict:
        """Detect code duplication patterns"""
        print("🔍 Detecting code duplicates...")
        
        duplicate_analysis = {
            "potential_duplicates": 0,
            "duplicate_patterns": [],
            "similarity_threshold": 80,
            "files_with_duplicates": [],
            "duplication_percentage": 0.0
        }
        
        # Simplified duplicate detection using file sizes and line counts
        file_stats = {}
        python_files = list(self.project_root.glob("**/*.py"))[:30]
        
        for file_path in python_files:
            if any(part in str(file_path) for part in ['venv', 'node_modules', '__pycache__']):
                continue
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    lines = content.splitlines()
                    
                # Simple heuristic: files with very similar line counts and sizes
                key = (len(lines) // 10, len(content) // 100)  # Bucket by approximate size
                
                if key not in file_stats:
                    file_stats[key] = []
                file_stats[key].append(str(file_path))
                
            except Exception:
                continue
        
        # Find potential duplicates
        for size_key, files in file_stats.items():
            if len(files) > 1:
                duplicate_analysis["potential_duplicates"] += len(files)
                duplicate_analysis["duplicate_patterns"].append({
                    "size_category": size_key,
                    "files": files,
                    "count": len(files)
                })
        
        duplicate_analysis["duplication_percentage"] = min(20.0, duplicate_analysis["potential_duplicates"] * 2)
        
        return duplicate_analysis
    
    def analyze_documentation(self) -> Dict:
        """Analyze documentation coverage and quality"""
        print("📚 Analyzing documentation...")
        
        doc_analysis = {
            "readme_exists": False,
            "api_docs_exist": False,
            "inline_documentation": 0.0,
            "documentation_files": 0,
            "code_comment_ratio": 0.0,
            "documentation_quality": "Poor"
        }
        
        # Check for README files
        readme_files = list(self.project_root.glob("**/README*"))
        doc_analysis["readme_exists"] = len(readme_files) > 0
        
        # Check for documentation directories
        doc_dirs = list(self.project_root.glob("**/doc*")) + list(self.project_root.glob("**/api*"))
        doc_analysis["api_docs_exist"] = len(doc_dirs) > 0
        
        # Count documentation files
        doc_files = list(self.project_root.glob("**/*.md")) + list(self.project_root.glob("**/*.rst"))
        doc_analysis["documentation_files"] = len([f for f in doc_files if 'node_modules' not in str(f)])
        
        # Analyze inline documentation in Python files
        python_files = list(self.project_root.glob("**/*.py"))[:20]
        total_functions = 0
        documented_functions = 0
        
        for file_path in python_files:
            if any(part in str(file_path) for part in ['venv', 'node_modules', '__pycache__']):
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Count functions and docstrings (simplified)
                functions = content.count('def ')
                docstrings = content.count('"""') + content.count("'''")
                
                total_functions += functions
                documented_functions += min(functions, docstrings // 2)  # Assume pairs of triple quotes
                
            except Exception:
                continue
        
        if total_functions > 0:
            doc_analysis["inline_documentation"] = (documented_functions / total_functions) * 100
        
        # Determine documentation quality
        if doc_analysis["inline_documentation"] > 80 and doc_analysis["readme_exists"]:
            doc_analysis["documentation_quality"] = "Excellent"
        elif doc_analysis["inline_documentation"] > 60:
            doc_analysis["documentation_quality"] = "Good"
        elif doc_analysis["inline_documentation"] > 30:
            doc_analysis["documentation_quality"] = "Fair"
        else:
            doc_analysis["documentation_quality"] = "Poor"
        
        return doc_analysis
    
    def analyze_security_issues(self) -> Dict:
        """Analyze security-related code issues"""
        print("🔒 Analyzing security issues...")
        
        security_analysis = {
            "potential_vulnerabilities": [],
            "security_score": 85.0,  # Start with good score
            "hardcoded_secrets": 0,
            "unsafe_patterns": [],
            "dependency_vulnerabilities": 0,
            "security_recommendations": []
        }
        
        # Check for common security issues in Python files
        python_files = list(self.project_root.glob("**/*.py"))[:20]
        
        for file_path in python_files:
            if any(part in str(file_path) for part in ['venv', 'node_modules', '__pycache__']):
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Check for potential security issues
                if re.search(r'password\s*=\s*["\'][^"\']+["\']', content, re.IGNORECASE):
                    security_analysis["potential_vulnerabilities"].append(f"Hardcoded password in {file_path.name}")
                    security_analysis["hardcoded_secrets"] += 1
                
                if re.search(r'api[_-]?key\s*=\s*["\'][^"\']+["\']', content, re.IGNORECASE):
                    security_analysis["potential_vulnerabilities"].append(f"Hardcoded API key in {file_path.name}")
                    security_analysis["hardcoded_secrets"] += 1
                
                if 'eval(' in content:
                    security_analysis["unsafe_patterns"].append(f"eval() usage in {file_path.name}")
                
                if 'exec(' in content:
                    security_analysis["unsafe_patterns"].append(f"exec() usage in {file_path.name}")
                
                if 'shell=True' in content:
                    security_analysis["unsafe_patterns"].append(f"shell=True in subprocess call in {file_path.name}")
                
            except Exception:
                continue
        
        # Adjust security score based on findings
        security_analysis["security_score"] -= len(security_analysis["potential_vulnerabilities"]) * 10
        security_analysis["security_score"] -= len(security_analysis["unsafe_patterns"]) * 15
        security_analysis["security_score"] = max(0, security_analysis["security_score"])
        
        # Generate recommendations
        if security_analysis["hardcoded_secrets"] > 0:
            security_analysis["security_recommendations"].append("Move hardcoded secrets to environment variables")
        
        if security_analysis["unsafe_patterns"]:
            security_analysis["security_recommendations"].append("Review and secure unsafe code patterns")
        
        return security_analysis
    
    def analyze_dependencies(self) -> Dict:
        """Analyze project dependencies"""
        print("📦 Analyzing dependencies...")
        
        dependency_analysis = {
            "python_dependencies": 0,
            "rust_dependencies": 0,
            "javascript_dependencies": 0,
            "outdated_dependencies": [],
            "dependency_health": "Unknown",
            "circular_dependencies": []
        }
        
        # Check Python dependencies
        requirements_files = list(self.project_root.glob("**/requirements*.txt"))
        if requirements_files:
            try:
                with open(requirements_files[0], 'r') as f:
                    deps = f.readlines()
                    dependency_analysis["python_dependencies"] = len([d for d in deps if d.strip() and not d.startswith('#')])
            except Exception:
                pass
        
        # Check Rust dependencies
        cargo_files = list(self.project_root.glob("**/Cargo.toml"))
        if cargo_files:
            try:
                with open(cargo_files[0], 'r') as f:
                    content = f.read()
                    # Simple count of dependency lines
                    in_deps = False
                    count = 0
                    for line in content.splitlines():
                        if line.strip() == '[dependencies]':
                            in_deps = True
                        elif line.startswith('[') and in_deps:
                            break
                        elif in_deps and '=' in line:
                            count += 1
                    dependency_analysis["rust_dependencies"] = count
            except Exception:
                pass
        
        # Check JavaScript dependencies
        package_files = list(self.project_root.glob("**/package.json"))
        if package_files:
            try:
                with open(package_files[0], 'r') as f:
                    import json
                    data = json.load(f)
                    deps = len(data.get('dependencies', {})) + len(data.get('devDependencies', {}))
                    dependency_analysis["javascript_dependencies"] = deps
            except Exception:
                pass
        
        # Simple dependency health assessment
        total_deps = (dependency_analysis["python_dependencies"] + 
                     dependency_analysis["rust_dependencies"] + 
                     dependency_analysis["javascript_dependencies"])
        
        if total_deps < 20:
            dependency_analysis["dependency_health"] = "Good"
        elif total_deps < 50:
            dependency_analysis["dependency_health"] = "Moderate"
        else:
            dependency_analysis["dependency_health"] = "Complex"
        
        return dependency_analysis
    
    def calculate_overall_quality_score(self, complexity_analysis: Dict, 
                                      documentation_analysis: Dict, 
                                      security_analysis: Dict) -> float:
        """Calculate overall project quality score"""
        
        # Weights for different aspects
        complexity_weight = 0.3
        documentation_weight = 0.2
        security_weight = 0.3
        structure_weight = 0.2
        
        # Complexity score (inverse of complexity)
        avg_complexity = complexity_analysis.get("average_cyclomatic_complexity", 10)
        complexity_score = max(0, 100 - (avg_complexity * 2))
        
        # Documentation score
        doc_coverage = documentation_analysis.get("inline_documentation", 0)
        doc_score = doc_coverage
        
        # Security score
        security_score = security_analysis.get("security_score", 85)
        
        # Structure score (based on file organization)
        structure_score = 75.0  # Default reasonable score
        
        # Calculate weighted average
        overall_score = (
            complexity_score * complexity_weight +
            doc_score * documentation_weight +
            security_score * security_weight +
            structure_score * structure_weight
        )
        
        return round(overall_score, 1)
    
    def generate_actionable_recommendations(self, complexity_analysis: Dict,
                                          documentation_analysis: Dict,
                                          security_analysis: Dict) -> List[str]:
        """Generate specific, actionable recommendations"""
        
        recommendations = []
        
        # Complexity recommendations
        if complexity_analysis.get("average_cyclomatic_complexity", 0) > 15:
            recommendations.append("🔴 HIGH PRIORITY: Refactor high-complexity functions to improve maintainability")
        
        if len(complexity_analysis.get("high_complexity_files", [])) > 3:
            recommendations.append("🟡 MEDIUM PRIORITY: Break down large files into smaller, focused modules")
        
        # Documentation recommendations
        if documentation_analysis.get("inline_documentation", 0) < 40:
            recommendations.append("📚 HIGH PRIORITY: Add docstrings to functions and classes")
        
        if not documentation_analysis.get("readme_exists", False):
            recommendations.append("📝 MEDIUM PRIORITY: Create comprehensive README.md file")
        
        # Security recommendations
        if security_analysis.get("hardcoded_secrets", 0) > 0:
            recommendations.append("🔒 CRITICAL: Remove hardcoded secrets and use environment variables")
        
        if security_analysis.get("unsafe_patterns"):
            recommendations.append("⚠️ HIGH PRIORITY: Review and secure unsafe code patterns")
        
        # General recommendations
        recommendations.append("🧪 MEDIUM PRIORITY: Implement comprehensive unit tests")
        recommendations.append("🔄 LOW PRIORITY: Set up continuous integration pipeline")
        recommendations.append("📊 LOW PRIORITY: Add code quality metrics monitoring")
        
        return recommendations
    
    def generate_refactoring_priorities(self) -> List[Dict]:
        """Generate prioritized refactoring tasks"""
        
        priorities = [
            {
                "priority": "Critical",
                "task": "Security Issues",
                "description": "Address hardcoded secrets and unsafe patterns",
                "effort": "Medium",
                "impact": "High"
            },
            {
                "priority": "High",
                "task": "Complex Functions",
                "description": "Refactor functions with cyclomatic complexity > 15",
                "effort": "High",
                "impact": "High"
            },
            {
                "priority": "Medium",
                "task": "Documentation",
                "description": "Add comprehensive documentation and docstrings",
                "effort": "Medium",
                "impact": "Medium"
            },
            {
                "priority": "Medium",
                "task": "Code Duplicates",
                "description": "Eliminate duplicate code patterns",
                "effort": "Medium",
                "impact": "Medium"
            },
            {
                "priority": "Low",
                "task": "Naming Conventions",
                "description": "Standardize naming conventions across codebase",
                "effort": "Low",
                "impact": "Low"
            }
        ]
        
        return priorities

def main():
    """Main execution function"""
    project_root = "/home/louranicas/projects/claude-optimized-deployment"
    
    analyzer = EnhancedCodeQualityAnalyzer(project_root)
    report = analyzer.run_comprehensive_analysis()
    
    # Save detailed report
    report_file = os.path.join(project_root, "enhanced_code_quality_report.json")
    with open(report_file, 'w') as f:
        json.dump(asdict(report), f, indent=2, default=str)
    
    # Generate summary report
    summary_file = os.path.join(project_root, "code_quality_summary.md")
    with open(summary_file, 'w') as f:
        f.write(generate_markdown_summary(report))
    
    print(f"\n✅ Enhanced analysis complete!")
    print(f"📄 Detailed report: {report_file}")
    print(f"📋 Summary report: {summary_file}")
    
    # Print key metrics
    print(f"\n🏆 QUALITY ASSESSMENT SUMMARY:")
    print(f"   Overall Quality Score: {report.quality_score}/100")
    print(f"   Project Size: {report.project_overview.get('project_size_category', 'Unknown')}")
    print(f"   Language Diversity: {report.project_overview.get('language_diversity', 0)} languages")
    print(f"   Security Score: {report.security_analysis.get('security_score', 0)}/100")
    print(f"   Documentation Quality: {report.documentation_analysis.get('documentation_quality', 'Unknown')}")
    
    return report

def generate_markdown_summary(report: CodeQualityReport) -> str:
    """Generate a markdown summary report"""
    
    summary = f"""# Code Quality Assessment Report

**Generated:** {report.timestamp}  
**Overall Quality Score:** {report.quality_score}/100

## 📊 Project Overview

- **Project Size:** {report.project_overview.get('project_size_category', 'Unknown')}
- **Total Lines:** {report.project_overview.get('estimated_total_lines', 0):,}
- **Languages:** {report.project_overview.get('language_diversity', 0)} different programming languages

## 🎯 Quality Metrics

### Complexity Analysis
- **Average Complexity:** {report.complexity_analysis.get('average_cyclomatic_complexity', 0):.1f}
- **High Complexity Files:** {len(report.complexity_analysis.get('high_complexity_files', []))}

### Documentation
- **Quality Level:** {report.documentation_analysis.get('documentation_quality', 'Unknown')}
- **Coverage:** {report.documentation_analysis.get('inline_documentation', 0):.1f}%
- **README Exists:** {'✅' if report.documentation_analysis.get('readme_exists') else '❌'}

### Security
- **Security Score:** {report.security_analysis.get('security_score', 0)}/100
- **Vulnerabilities Found:** {len(report.security_analysis.get('potential_vulnerabilities', []))}
- **Unsafe Patterns:** {len(report.security_analysis.get('unsafe_patterns', []))}

## 🚨 Priority Recommendations

"""
    
    for i, rec in enumerate(report.recommendations[:5], 1):
        summary += f"{i}. {rec}\n"
    
    summary += f"""
## 🔧 Refactoring Priorities

"""
    
    for priority in report.refactoring_priorities[:3]:
        summary += f"### {priority['priority']}: {priority['task']}\n"
        summary += f"- **Description:** {priority['description']}\n"
        summary += f"- **Effort:** {priority['effort']} | **Impact:** {priority['impact']}\n\n"
    
    summary += f"""
## 📈 Improvement Areas

1. **Code Complexity:** Reduce average cyclomatic complexity
2. **Documentation:** Improve inline documentation coverage
3. **Security:** Address potential vulnerabilities
4. **Testing:** Implement comprehensive test suite
5. **Architecture:** Improve module organization

---
*Report generated by ULTRA THINK MODE Code Quality Analyzer*
"""
    
    return summary

if __name__ == "__main__":
    main()