#!/usr/bin/env python3
"""
AGENT 6: Comprehensive Modularity and Architecture Analysis
"""

import os
import re
import json
import ast
from pathlib import Path
from collections import defaultdict, Counter
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, asdict
from datetime import datetime


@dataclass
class ModuleMetrics:
    """Metrics for a single module."""
    name: str
    path: str
    lines_of_code: int
    import_count: int
    internal_imports: List[str]
    external_imports: List[str]
    classes: List[str]
    functions: List[str]
    cyclomatic_complexity: int
    cohesion_score: float
    coupling_score: float
    responsibilities: List[str]


@dataclass
class ArchitectureMetrics:
    """Overall architecture metrics."""
    total_modules: int
    total_loc: int
    average_module_size: float
    coupling_matrix: Dict[str, Dict[str, int]]
    circular_dependencies: List[List[str]]
    layer_violations: List[str]
    interface_quality_score: float
    modularity_score: float
    solid_compliance: Dict[str, float]


class ModularityAnalyzer:
    """Comprehensive modularity and architecture analyzer."""
    
    def __init__(self, src_path: str = "src"):
        self.src_path = Path(src_path)
        self.modules: Dict[str, ModuleMetrics] = {}
        self.dependencies: Dict[str, Set[str]] = defaultdict(set)
        self.reverse_dependencies: Dict[str, Set[str]] = defaultdict(set)
        
        # Architecture layers (from low to high level)
        self.layers = {
            'core': 1,
            'database': 2,
            'auth': 3,
            'mcp': 4,
            'circle_of_experts': 5,
            'monitoring': 6,
            'api': 7,
            'platform': 8
        }
    
    def analyze(self) -> ArchitectureMetrics:
        """Run complete modularity analysis."""
        print("🔍 Starting comprehensive modularity analysis...")
        
        self._scan_modules()
        self._analyze_dependencies()
        circular_deps = self._detect_circular_dependencies()
        layer_violations = self._detect_layer_violations()
        
        metrics = ArchitectureMetrics(
            total_modules=len(self.modules),
            total_loc=sum(m.lines_of_code for m in self.modules.values()),
            average_module_size=sum(m.lines_of_code for m in self.modules.values()) / len(self.modules) if self.modules else 0,
            coupling_matrix=self._build_coupling_matrix(),
            circular_dependencies=circular_deps,
            layer_violations=layer_violations,
            interface_quality_score=self._calculate_interface_quality(),
            modularity_score=self._calculate_modularity_score(),
            solid_compliance=self._analyze_solid_compliance()
        )
        
        return metrics
    
    def _scan_modules(self):
        """Scan all Python modules and extract metrics."""
        print("📁 Scanning modules...")
        
        for py_file in self.src_path.rglob("*.py"):
            if py_file.name.startswith('.') or 'test' in py_file.name:
                continue
                
            module_name = self._get_module_name(py_file)
            try:
                metrics = self._analyze_file(py_file, module_name)
                self.modules[module_name] = metrics
            except Exception as e:
                print(f"⚠️  Error analyzing {py_file}: {e}")
    
    def _get_module_name(self, file_path: Path) -> str:
        """Get module name from file path."""
        rel_path = file_path.relative_to(self.src_path)
        if rel_path.name == "__init__.py":
            return str(rel_path.parent).replace('/', '.')
        else:
            return str(rel_path.with_suffix('')).replace('/', '.')
    
    def _analyze_file(self, file_path: Path, module_name: str) -> ModuleMetrics:
        """Analyze a single Python file."""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Count lines of code (excluding empty lines and comments)
        lines = content.split('\n')
        loc = sum(1 for line in lines if line.strip() and not line.strip().startswith('#'))
        
        # Parse imports
        internal_imports, external_imports = self._parse_imports(content)
        
        # Parse AST for classes and functions
        try:
            tree = ast.parse(content)
            classes = [node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
            functions = [node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
            complexity = self._calculate_cyclomatic_complexity(tree)
        except SyntaxError:
            classes, functions, complexity = [], [], 1
        
        # Analyze responsibilities
        responsibilities = self._identify_responsibilities(content, classes, functions)
        
        return ModuleMetrics(
            name=module_name,
            path=str(file_path),
            lines_of_code=loc,
            import_count=len(internal_imports) + len(external_imports),
            internal_imports=internal_imports,
            external_imports=external_imports,
            classes=classes,
            functions=functions,
            cyclomatic_complexity=complexity,
            cohesion_score=self._calculate_cohesion(content, classes, functions),
            coupling_score=len(internal_imports),  # Simplified coupling metric
            responsibilities=responsibilities
        )
    
    def _parse_imports(self, content: str) -> Tuple[List[str], List[str]]:
        """Parse imports from module content."""
        internal_imports = []
        external_imports = []
        
        # Regular expressions for import patterns
        import_patterns = [
            r'^from\s+(src\.[^\s]+)',
            r'^import\s+(src\.[^\s]+)',
            r'^from\s+([^.\s][^\s]*)',
            r'^import\s+([^.\s][^\s]*)'
        ]
        
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('from ') or line.startswith('import '):
                for pattern in import_patterns:
                    match = re.match(pattern, line)
                    if match:
                        module = match.group(1).split('.')[0]
                        if module.startswith('src'):
                            internal_imports.append(match.group(1))
                        else:
                            external_imports.append(module)
                        break
        
        return list(set(internal_imports)), list(set(external_imports))
    
    def _calculate_cyclomatic_complexity(self, tree: ast.AST) -> int:
        """Calculate cyclomatic complexity of an AST."""
        complexity = 1  # Base complexity
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            elif isinstance(node, ast.ExceptHandler):
                complexity += 1
            elif isinstance(node, (ast.And, ast.Or)):
                complexity += 1
        
        return complexity
    
    def _calculate_cohesion(self, content: str, classes: List[str], functions: List[str]) -> float:
        """Calculate module cohesion score."""
        if not classes and not functions:
            return 0.0
        
        # Simple heuristic: measure how related the elements are
        # Higher score for modules with fewer distinct concerns
        concerns = set()
        
        # Extract domain terms from names
        all_names = classes + functions
        for name in all_names:
            # Split camelCase and snake_case
            words = re.split(r'[A-Z]|_', name.lower())
            concerns.update(word for word in words if len(word) > 2)
        
        # Lower concern count = higher cohesion
        if len(all_names) == 0:
            return 0.0
        
        cohesion = max(0.0, 1.0 - (len(concerns) / (len(all_names) * 2)))
        return min(1.0, cohesion)
    
    def _identify_responsibilities(self, content: str, classes: List[str], functions: List[str]) -> List[str]:
        """Identify module responsibilities."""
        responsibilities = set()
        
        # Common responsibility patterns
        patterns = {
            'authentication': r'(auth|login|token|password|credential)',
            'database': r'(db|database|repository|model|query|sql)',
            'networking': r'(http|request|response|client|server|api)',
            'monitoring': r'(metric|monitor|alert|log|trace)',
            'security': r'(security|encrypt|decrypt|hash|validate)',
            'configuration': r'(config|setting|environment|env)',
            'testing': r'(test|mock|fixture|assert)',
            'caching': r'(cache|redis|memory|store)',
            'validation': r'(valid|check|verify|sanitize)',
            'serialization': r'(json|xml|pickle|serialize)',
            'file_io': r'(file|read|write|path|directory)',
            'async': r'(async|await|coroutine|event|loop)'
        }
        
        content_lower = content.lower()
        all_names = ' '.join(classes + functions).lower()
        
        for responsibility, pattern in patterns.items():
            if re.search(pattern, content_lower) or re.search(pattern, all_names):
                responsibilities.add(responsibility)
        
        return list(responsibilities)
    
    def _analyze_dependencies(self):
        """Analyze module dependencies."""
        print("🔗 Analyzing dependencies...")
        
        for module_name, module in self.modules.items():
            for import_path in module.internal_imports:
                # Convert import path to module name
                target_module = import_path.replace('src.', '').split('.')[0]
                if target_module in [m.split('.')[0] for m in self.modules.keys()]:
                    self.dependencies[module_name].add(target_module)
                    self.reverse_dependencies[target_module].add(module_name)
    
    def _detect_circular_dependencies(self) -> List[List[str]]:
        """Detect circular dependencies using DFS."""
        print("🔄 Detecting circular dependencies...")
        
        visited = set()
        rec_stack = set()
        cycles = []
        
        def dfs(module: str, path: List[str]) -> bool:
            if module in rec_stack:
                # Found a cycle
                try:
                    cycle_start = path.index(module)
                    cycle = path[cycle_start:] + [module]
                    cycles.append(cycle)
                except ValueError:
                    # Module not in path, add current path as cycle
                    cycles.append(path + [module])
                return True
            
            if module in visited:
                return False
            
            visited.add(module)
            rec_stack.add(module)
            path.append(module)
            
            for dep in self.dependencies.get(module, []):
                dfs_path = path.copy()  # Create a copy to avoid modification issues
                if dfs(dep, dfs_path):
                    pass  # Continue checking other dependencies
            
            rec_stack.remove(module)
            if path and path[-1] == module:
                path.pop()
            return False
        
        for module in self.modules.keys():
            if module not in visited:
                dfs(module, [])
        
        return cycles
    
    def _detect_layer_violations(self) -> List[str]:
        """Detect architectural layer violations."""
        print("🏗️  Detecting layer violations...")
        
        violations = []
        
        for module_name, deps in self.dependencies.items():
            module_layer = self._get_module_layer(module_name)
            
            for dep in deps:
                dep_layer = self._get_module_layer(dep)
                
                # Higher layer depending on lower layer is allowed
                # Lower layer depending on higher layer is a violation
                if module_layer < dep_layer:
                    violations.append(f"{module_name} (layer {module_layer}) -> {dep} (layer {dep_layer})")
        
        return violations
    
    def _get_module_layer(self, module_name: str) -> int:
        """Get architectural layer for a module."""
        for layer, level in self.layers.items():
            if module_name.startswith(layer):
                return level
        return 9  # Unknown layer
    
    def _build_coupling_matrix(self) -> Dict[str, Dict[str, int]]:
        """Build module coupling matrix."""
        print("📊 Building coupling matrix...")
        
        matrix = {}
        modules = list(self.modules.keys())
        
        for module in modules:
            matrix[module] = {}
            for other_module in modules:
                # Count direct dependencies
                coupling = 0
                if other_module in self.dependencies.get(module, set()):
                    coupling += 1
                if module in self.dependencies.get(other_module, set()):
                    coupling += 1
                
                matrix[module][other_module] = coupling
        
        return matrix
    
    def _calculate_interface_quality(self) -> float:
        """Calculate interface quality score."""
        if not self.modules:
            return 0.0
        
        total_score = 0.0
        
        for module in self.modules.values():
            # Factors for interface quality:
            # 1. Public API size (smaller is better for focused interfaces)
            # 2. Import/export ratio
            # 3. Documentation presence
            
            public_elements = len([name for name in module.classes + module.functions 
                                 if not name.startswith('_')])
            
            # Ideal range: 5-15 public elements
            size_score = max(0.0, 1.0 - abs(public_elements - 10) / 20.0)
            
            # Import/export balance
            import_export_ratio = module.import_count / max(1, public_elements)
            balance_score = max(0.0, 1.0 - abs(import_export_ratio - 1.0))
            
            module_score = (size_score + balance_score) / 2.0
            total_score += module_score
        
        return total_score / len(self.modules)
    
    def _calculate_modularity_score(self) -> float:
        """Calculate overall modularity score."""
        if not self.modules:
            return 0.0
        
        # Factors:
        # 1. Average cohesion (higher is better)
        # 2. Average coupling (lower is better)
        # 3. Module size variance (lower is better)
        # 4. Circular dependency penalty
        
        avg_cohesion = sum(m.cohesion_score for m in self.modules.values()) / len(self.modules)
        avg_coupling = sum(m.coupling_score for m in self.modules.values()) / len(self.modules)
        
        # Normalize coupling (assume max reasonable coupling is 10)
        normalized_coupling = min(1.0, avg_coupling / 10.0)
        
        # Size variance penalty
        sizes = [m.lines_of_code for m in self.modules.values()]
        avg_size = sum(sizes) / len(sizes)
        variance = sum((size - avg_size) ** 2 for size in sizes) / len(sizes)
        size_penalty = min(1.0, variance / (avg_size ** 2)) if avg_size > 0 else 0
        
        # Circular dependency penalty
        circular_penalty = len(self._detect_circular_dependencies()) * 0.1
        
        # Combine factors
        modularity = (avg_cohesion + (1.0 - normalized_coupling) + (1.0 - size_penalty)) / 3.0
        modularity = max(0.0, modularity - circular_penalty)
        
        return min(1.0, modularity)
    
    def _analyze_solid_compliance(self) -> Dict[str, float]:
        """Analyze SOLID principles compliance."""
        print("🏛️  Analyzing SOLID principles compliance...")
        
        srp_score = self._analyze_single_responsibility()
        ocp_score = self._analyze_open_closed()
        lsp_score = self._analyze_liskov_substitution()
        isp_score = self._analyze_interface_segregation()
        dip_score = self._analyze_dependency_inversion()
        
        return {
            'single_responsibility': srp_score,
            'open_closed': ocp_score,
            'liskov_substitution': lsp_score,
            'interface_segregation': isp_score,
            'dependency_inversion': dip_score,
            'overall': (srp_score + ocp_score + lsp_score + isp_score + dip_score) / 5.0
        }
    
    def _analyze_single_responsibility(self) -> float:
        """Analyze Single Responsibility Principle compliance."""
        if not self.modules:
            return 0.0
        
        total_score = 0.0
        
        for module in self.modules.values():
            # SRP: Each module should have only one reason to change
            # Measure by number of distinct responsibilities
            responsibility_count = len(module.responsibilities)
            
            if responsibility_count == 0:
                score = 0.5  # Neutral score for modules with no clear responsibilities
            elif responsibility_count == 1:
                score = 1.0  # Perfect SRP compliance
            else:
                # Penalty increases with more responsibilities
                score = max(0.0, 1.0 - (responsibility_count - 1) * 0.2)
            
            total_score += score
        
        return total_score / len(self.modules)
    
    def _analyze_open_closed(self) -> float:
        """Analyze Open/Closed Principle compliance."""
        # OCP: Software entities should be open for extension, closed for modification
        # Heuristic: Presence of abstract base classes, interfaces, and inheritance
        
        total_score = 0.0
        abstraction_count = 0
        
        for module in self.modules.values():
            score = 0.5  # Base score
            
            # Look for abstract patterns in class names
            abstract_patterns = ['base', 'abstract', 'interface', 'protocol']
            for class_name in module.classes:
                if any(pattern in class_name.lower() for pattern in abstract_patterns):
                    score += 0.2
                    abstraction_count += 1
            
            # Look for factory patterns
            factory_patterns = ['factory', 'builder', 'creator']
            for name in module.classes + module.functions:
                if any(pattern in name.lower() for pattern in factory_patterns):
                    score += 0.1
            
            total_score += min(1.0, score)
        
        return total_score / len(self.modules) if self.modules else 0.0
    
    def _analyze_liskov_substitution(self) -> float:
        """Analyze Liskov Substitution Principle compliance."""
        # LSP: Objects of a superclass should be replaceable with objects of a subclass
        # Heuristic: Consistent interface patterns and minimal overrides
        
        # This is difficult to analyze statically, so we use naming conventions
        # and inheritance patterns as proxies
        
        total_score = 0.0
        
        for module in self.modules.values():
            score = 0.8  # Assume good compliance unless evidence suggests otherwise
            
            # Look for potential LSP violations in naming
            violation_patterns = ['override', 'special', 'custom']
            for name in module.classes + module.functions:
                if any(pattern in name.lower() for pattern in violation_patterns):
                    score -= 0.1
            
            total_score += max(0.0, score)
        
        return total_score / len(self.modules) if self.modules else 0.0
    
    def _analyze_interface_segregation(self) -> float:
        """Analyze Interface Segregation Principle compliance."""
        # ISP: No client should be forced to depend on methods it does not use
        # Heuristic: Interface size and specificity
        
        return self._calculate_interface_quality()  # Reuse interface quality metric
    
    def _analyze_dependency_inversion(self) -> float:
        """Analyze Dependency Inversion Principle compliance."""
        # DIP: Depend on abstractions, not concretions
        # Heuristic: Dependency injection patterns and abstraction usage
        
        total_score = 0.0
        
        for module in self.modules.values():
            score = 0.5  # Base score
            
            # Look for dependency injection patterns
            di_patterns = ['inject', 'factory', 'provider', 'container', 'config']
            for name in module.classes + module.functions:
                if any(pattern in name.lower() for pattern in di_patterns):
                    score += 0.1
            
            # Penalty for direct concrete dependencies
            concrete_patterns = ['sqlite', 'mysql', 'postgres', 'redis']
            for import_name in module.external_imports:
                if any(pattern in import_name.lower() for pattern in concrete_patterns):
                    score -= 0.1
            
            total_score += max(0.0, min(1.0, score))
        
        return total_score / len(self.modules) if self.modules else 0.0
    
    def generate_report(self, metrics: ArchitectureMetrics) -> str:
        """Generate comprehensive modularity report."""
        report = f"""
# AGENT 6: MODULARITY AND ARCHITECTURE ANALYSIS REPORT
**Analysis Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## 📊 EXECUTIVE SUMMARY

### Overall Modularity Score: {metrics.modularity_score:.2f}/1.0
### Interface Quality Score: {metrics.interface_quality_score:.2f}/1.0

## 🏗️ ARCHITECTURE OVERVIEW

- **Total Modules**: {metrics.total_modules}
- **Total Lines of Code**: {metrics.total_loc:,}
- **Average Module Size**: {metrics.average_module_size:.1f} LOC
- **Circular Dependencies**: {len(metrics.circular_dependencies)}
- **Layer Violations**: {len(metrics.layer_violations)}

## 📈 MODULE METRICS

### Top 10 Largest Modules
"""
        
        # Sort modules by size
        sorted_modules = sorted(self.modules.values(), key=lambda m: m.lines_of_code, reverse=True)
        for i, module in enumerate(sorted_modules[:10], 1):
            report += f"{i:2d}. **{module.name}**: {module.lines_of_code} LOC, {len(module.responsibilities)} responsibilities\n"
        
        report += f"""
### Cohesion Analysis
"""
        
        # Cohesion distribution
        high_cohesion = [m for m in self.modules.values() if m.cohesion_score >= 0.7]
        medium_cohesion = [m for m in self.modules.values() if 0.4 <= m.cohesion_score < 0.7]
        low_cohesion = [m for m in self.modules.values() if m.cohesion_score < 0.4]
        
        report += f"- **High Cohesion** (≥0.7): {len(high_cohesion)} modules\n"
        report += f"- **Medium Cohesion** (0.4-0.69): {len(medium_cohesion)} modules\n"
        report += f"- **Low Cohesion** (<0.4): {len(low_cohesion)} modules\n\n"
        
        if low_cohesion:
            report += "**Low Cohesion Modules (Need Refactoring)**:\n"
            for module in sorted(low_cohesion, key=lambda m: m.cohesion_score):
                report += f"- {module.name}: {module.cohesion_score:.2f} ({len(module.responsibilities)} responsibilities)\n"
        
        report += f"""
### Coupling Analysis
"""
        
        # Coupling distribution
        high_coupling = [m for m in self.modules.values() if m.coupling_score >= 10]
        medium_coupling = [m for m in self.modules.values() if 5 <= m.coupling_score < 10]
        low_coupling = [m for m in self.modules.values() if m.coupling_score < 5]
        
        report += f"- **High Coupling** (≥10): {len(high_coupling)} modules\n"
        report += f"- **Medium Coupling** (5-9): {len(medium_coupling)} modules\n"
        report += f"- **Low Coupling** (<5): {len(low_coupling)} modules\n\n"
        
        if high_coupling:
            report += "**High Coupling Modules (Consider Decoupling)**:\n"
            for module in sorted(high_coupling, key=lambda m: m.coupling_score, reverse=True):
                report += f"- {module.name}: {module.coupling_score} dependencies\n"
        
        report += f"""
## 🔄 DEPENDENCY ANALYSIS

### Circular Dependencies
"""
        
        if metrics.circular_dependencies:
            for i, cycle in enumerate(metrics.circular_dependencies, 1):
                report += f"{i}. {' → '.join(cycle)}\n"
        else:
            report += "✅ No circular dependencies detected!\n"
        
        report += f"""
### Layer Violations
"""
        
        if metrics.layer_violations:
            for violation in metrics.layer_violations:
                report += f"- {violation}\n"
        else:
            report += "✅ No layer violations detected!\n"
        
        report += f"""
## 🏛️ SOLID PRINCIPLES COMPLIANCE

| Principle | Score | Status |
|-----------|-------|--------|
| Single Responsibility | {metrics.solid_compliance['single_responsibility']:.2f} | {'✅ Good' if metrics.solid_compliance['single_responsibility'] >= 0.7 else '⚠️ Needs Improvement' if metrics.solid_compliance['single_responsibility'] >= 0.5 else '❌ Poor'} |
| Open/Closed | {metrics.solid_compliance['open_closed']:.2f} | {'✅ Good' if metrics.solid_compliance['open_closed'] >= 0.7 else '⚠️ Needs Improvement' if metrics.solid_compliance['open_closed'] >= 0.5 else '❌ Poor'} |
| Liskov Substitution | {metrics.solid_compliance['liskov_substitution']:.2f} | {'✅ Good' if metrics.solid_compliance['liskov_substitution'] >= 0.7 else '⚠️ Needs Improvement' if metrics.solid_compliance['liskov_substitution'] >= 0.5 else '❌ Poor'} |
| Interface Segregation | {metrics.solid_compliance['interface_segregation']:.2f} | {'✅ Good' if metrics.solid_compliance['interface_segregation'] >= 0.7 else '⚠️ Needs Improvement' if metrics.solid_compliance['interface_segregation'] >= 0.5 else '❌ Poor'} |
| Dependency Inversion | {metrics.solid_compliance['dependency_inversion']:.2f} | {'✅ Good' if metrics.solid_compliance['dependency_inversion'] >= 0.7 else '⚠️ Needs Improvement' if metrics.solid_compliance['dependency_inversion'] >= 0.5 else '❌ Poor'} |
| **Overall SOLID Score** | **{metrics.solid_compliance['overall']:.2f}** | **{'✅ Excellent' if metrics.solid_compliance['overall'] >= 0.8 else '✅ Good' if metrics.solid_compliance['overall'] >= 0.7 else '⚠️ Needs Improvement' if metrics.solid_compliance['overall'] >= 0.5 else '❌ Poor'}** |

## 📋 DETAILED MODULE BREAKDOWN

"""
        
        # Detailed module analysis
        for module in sorted(self.modules.values(), key=lambda m: m.name):
            report += f"""
### {module.name}
- **Path**: `{module.path}`
- **Size**: {module.lines_of_code} LOC
- **Complexity**: {module.cyclomatic_complexity}
- **Cohesion**: {module.cohesion_score:.2f}
- **Coupling**: {module.coupling_score} dependencies
- **Classes**: {len(module.classes)} ({', '.join(module.classes[:3])}{'...' if len(module.classes) > 3 else ''})
- **Functions**: {len(module.functions)} ({', '.join(module.functions[:3])}{'...' if len(module.functions) > 3 else ''})
- **Responsibilities**: {', '.join(module.responsibilities) if module.responsibilities else 'None identified'}
- **Internal Dependencies**: {len(module.internal_imports)}
- **External Dependencies**: {len(module.external_imports)}
"""
        
        report += f"""
## 🎯 RECOMMENDATIONS

### High Priority Issues
"""
        
        recommendations = []
        
        # Circular dependencies
        if metrics.circular_dependencies:
            recommendations.append("🔄 **Break Circular Dependencies**: Refactor modules to eliminate circular imports")
        
        # Layer violations
        if metrics.layer_violations:
            recommendations.append("🏗️ **Fix Layer Violations**: Ensure lower layers don't depend on higher layers")
        
        # Low cohesion modules
        if low_cohesion:
            recommendations.append(f"🔧 **Improve Cohesion**: Refactor {len(low_cohesion)} modules with low cohesion")
        
        # High coupling modules
        if high_coupling:
            recommendations.append(f"🔗 **Reduce Coupling**: Decouple {len(high_coupling)} highly coupled modules")
        
        # SOLID violations
        if metrics.solid_compliance['overall'] < 0.7:
            recommendations.append("🏛️ **Improve SOLID Compliance**: Focus on dependency injection and interface design")
        
        if recommendations:
            for rec in recommendations:
                report += f"- {rec}\n"
        else:
            report += "✅ Architecture is in good shape! Consider minor optimizations.\n"
        
        report += f"""
### Architectural Improvements

1. **Dependency Injection**: Implement more dependency injection patterns
2. **Interface Segregation**: Create smaller, more focused interfaces
3. **Plugin Architecture**: Consider plugin systems for extensibility
4. **Configuration Management**: Centralize configuration handling
5. **Error Handling**: Standardize error handling patterns across modules

### Refactoring Priorities

1. **High**: Address circular dependencies and layer violations
2. **Medium**: Improve modules with low cohesion scores
3. **Low**: Optimize module sizes and reduce unnecessary coupling

## 📊 METRICS SUMMARY

| Metric | Value | Target | Status |
|--------|-------|--------|--------|
| Modularity Score | {metrics.modularity_score:.2f} | >0.8 | {'✅' if metrics.modularity_score > 0.8 else '⚠️' if metrics.modularity_score > 0.6 else '❌'} |
| Interface Quality | {metrics.interface_quality_score:.2f} | >0.7 | {'✅' if metrics.interface_quality_score > 0.7 else '⚠️' if metrics.interface_quality_score > 0.5 else '❌'} |
| SOLID Compliance | {metrics.solid_compliance['overall']:.2f} | >0.7 | {'✅' if metrics.solid_compliance['overall'] > 0.7 else '⚠️' if metrics.solid_compliance['overall'] > 0.5 else '❌'} |
| Circular Dependencies | {len(metrics.circular_dependencies)} | 0 | {'✅' if len(metrics.circular_dependencies) == 0 else '❌'} |
| Layer Violations | {len(metrics.layer_violations)} | 0 | {'✅' if len(metrics.layer_violations) == 0 else '❌'} |

---
*Generated by AGENT 6: Modularity and Architecture Analysis*
"""
        
        return report


def main():
    """Run the modularity analysis."""
    print("🚀 AGENT 6: Starting Modularity and Architecture Analysis")
    print("=" * 60)
    
    analyzer = ModularityAnalyzer()
    metrics = analyzer.analyze()
    
    # Generate report
    report = analyzer.generate_report(metrics)
    
    # Save report
    report_file = "AGENT_6_MODULARITY_ARCHITECTURE_ANALYSIS.md"
    with open(report_file, 'w') as f:
        f.write(report)
    
    # Save metrics as JSON
    metrics_file = "modularity_metrics.json"
    with open(metrics_file, 'w') as f:
        # Convert metrics to serializable format
        metrics_dict = asdict(metrics)
        json.dump(metrics_dict, f, indent=2)
    
    print(f"\n✅ Analysis complete!")
    print(f"📄 Report saved to: {report_file}")
    print(f"📊 Metrics saved to: {metrics_file}")
    print(f"\n🎯 Overall Modularity Score: {metrics.modularity_score:.2f}/1.0")
    print(f"🏛️  SOLID Compliance: {metrics.solid_compliance['overall']:.2f}/1.0")
    
    return metrics


if __name__ == "__main__":
    main()