"""BASH_GOD Optimization Engine - Advanced command optimization"""

import re
import time
import subprocess
from typing import Dict, List, Any, Tuple, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
import hashlib
from collections import defaultdict, Counter
import json


class OptimizationType(Enum):
    PERFORMANCE = "performance"
    MEMORY = "memory"
    PARALLELIZATION = "parallelization"
    TOOL_SUBSTITUTION = "tool_substitution"
    PIPELINE_FUSION = "pipeline_fusion"
    ALGORITHMIC = "algorithmic"


@dataclass
class OptimizationRule:
    """Represents an optimization rule"""
    rule_id: str
    name: str
    type: OptimizationType
    pattern: str
    replacement: str
    conditions: List[str]
    expected_improvement: float
    cpu_impact: float = 0.0
    memory_impact: float = 0.0
    description: str = ""
    examples: List[str] = field(default_factory=list)
    

@dataclass
class SystemProfile:
    """System resource profile"""
    cpu_cores: int
    memory_gb: float
    storage_type: str  # 'ssd', 'hdd', 'nvme'
    network_speed: str  # 'fast', 'medium', 'slow'
    available_tools: Set[str]
    

@dataclass
class OptimizationResult:
    """Result of optimization attempt"""
    original_command: str
    optimized_command: str
    optimizations_applied: List[str]
    expected_speedup: float
    confidence: float
    warnings: List[str] = field(default_factory=list)
    


class BashOptimizationEngine:
    """Advanced optimization engine for bash commands"""
    
    def __init__(self):
        self.optimization_rules: List[OptimizationRule] = []
        self.performance_cache: Dict[str, float] = {}
        self.tool_alternatives: Dict[str, List[str]] = {}
        self.system_profile: Optional[SystemProfile] = None
        
        self._initialize_rules()
        self._initialize_tool_alternatives()
        self._detect_system_profile()
    
    def _initialize_rules(self):
        """Initialize optimization rules"""
        
        # PIPELINE FUSION OPTIMIZATIONS
        self.optimization_rules.extend([
            OptimizationRule(
                rule_id="PF001",
                name="Cat Grep Elimination",
                type=OptimizationType.PIPELINE_FUSION,
                pattern=r"cat\s+(\S+)\s*\|\s*grep\s+(.+)",
                replacement="grep $2 $1",
                conditions=["file_readable"],
                expected_improvement=1.5,
                memory_impact=-0.2,
                description="Eliminate unnecessary cat when grep can read file directly",
                examples=["cat file.txt | grep pattern → grep pattern file.txt"]
            ),
            OptimizationRule(
                rule_id="PF002",
                name="Multiple Grep Fusion",
                type=OptimizationType.PIPELINE_FUSION,
                pattern=r"grep\s+'([^']+)'\s*\|\s*grep\s+'([^']+)'",
                replacement="grep -E '$1.*$2'",
                conditions=["compatible_patterns"],
                expected_improvement=1.8,
                description="Combine multiple grep patterns into single regex",
                examples=["grep 'error' | grep 'database' → grep -E 'error.*database'"]
            ),
            OptimizationRule(
                rule_id="PF003",
                name="Sort Uniq Combination",
                type=OptimizationType.PIPELINE_FUSION,
                pattern=r"sort\s*(.*?)\s*\|\s*uniq\b",
                replacement="sort -u $1",
                conditions=["no_uniq_flags"],
                expected_improvement=1.3,
                description="Combine sort and uniq operations",
                examples=["sort file | uniq → sort -u file"]
            ),
            OptimizationRule(
                rule_id="PF004",
                name="AWK Grep Fusion",
                type=OptimizationType.PIPELINE_FUSION,
                pattern=r"grep\s+'([^']+)'\s*\|\s*awk\s+'([^']+)'",
                replacement="awk '/$1/ { $2 }'",
                conditions=["valid_awk_syntax"],
                expected_improvement=1.6,
                description="Combine grep filtering with awk processing",
                examples=["grep 'error' | awk '{print $1}' → awk '/error/ {print $1}'"]
            )
        ])
        
        # TOOL SUBSTITUTION OPTIMIZATIONS
        self.optimization_rules.extend([
            OptimizationRule(
                rule_id="TS001",
                name="Ripgrep Substitution",
                type=OptimizationType.TOOL_SUBSTITUTION,
                pattern=r"grep\s+-r\s+(.+)",
                replacement="rg $1",
                conditions=["ripgrep_available"],
                expected_improvement=5.0,
                description="Use ripgrep for faster recursive searching",
                examples=["grep -r 'pattern' dir → rg 'pattern' dir"]
            ),
            OptimizationRule(
                rule_id="TS002",
                name="FD Substitution",
                type=OptimizationType.TOOL_SUBSTITUTION,
                pattern=r"find\s+(\S+)\s+-name\s+'([^']+)'",
                replacement="fd '$2' $1",
                conditions=["fd_available"],
                expected_improvement=3.0,
                description="Use fd for faster file finding",
                examples=["find . -name '*.txt' → fd '*.txt' ."]
            ),
            OptimizationRule(
                rule_id="TS003",
                name="Parallel Compression",
                type=OptimizationType.TOOL_SUBSTITUTION,
                pattern=r"gzip\s+(.+)",
                replacement="pigz $1",
                conditions=["pigz_available", "multi_core"],
                expected_improvement=4.0,
                cpu_impact=0.8,
                description="Use parallel gzip for faster compression",
                examples=["gzip large_file → pigz large_file"]
            ),
            OptimizationRule(
                rule_id="TS004",
                name="Parallel Decompression",
                type=OptimizationType.TOOL_SUBSTITUTION,
                pattern=r"gunzip\s+(.+)",
                replacement="unpigz $1",
                conditions=["pigz_available", "multi_core"],
                expected_improvement=3.5,
                description="Use parallel gunzip for faster decompression"
            )
        ])
        
        # PARALLELIZATION OPTIMIZATIONS
        self.optimization_rules.extend([
            OptimizationRule(
                rule_id="PAR001",
                name="Find Exec to Xargs",
                type=OptimizationType.PARALLELIZATION,
                pattern=r"find\s+(.*?)\s+-exec\s+(\S+)\s+(.*?)\s*\{\}\s*\\;",
                replacement="find $1 -print0 | xargs -0 -P$(nproc) $2 $3",
                conditions=["command_supports_multiple_args"],
                expected_improvement=3.0,
                cpu_impact=0.6,
                description="Parallelize find -exec operations with xargs",
                examples=["find . -exec grep pattern {} \\; → find . -print0 | xargs -0 -P$(nproc) grep pattern"]
            ),
            OptimizationRule(
                rule_id="PAR002",
                name="Loop Parallelization",
                type=OptimizationType.PARALLELIZATION,
                pattern=r"for\s+(\w+)\s+in\s+(.*?);\s*do\s+(.*?);\s*done",
                replacement="echo $2 | tr ' ' '\\n' | parallel -j+0 '$3'",
                conditions=["parallel_available", "independent_iterations"],
                expected_improvement=4.0,
                cpu_impact=0.9,
                description="Parallelize for loops with GNU parallel",
                examples=["for f in *.txt; do grep pattern $f; done → echo *.txt | tr ' ' '\\n' | parallel -j+0 'grep pattern'"]
            ),
            OptimizationRule(
                rule_id="PAR003",
                name="Xargs Parallelization",
                type=OptimizationType.PARALLELIZATION,
                pattern=r"xargs\s+(?!-P)(.+)",
                replacement="xargs -P$(nproc) $1",
                conditions=["multi_core", "command_parallel_safe"],
                expected_improvement=2.5,
                description="Add parallelization to xargs operations"
            )
        ])
        
        # ALGORITHMIC OPTIMIZATIONS
        self.optimization_rules.extend([
            OptimizationRule(
                rule_id="ALG001",
                name="Efficient File Processing",
                type=OptimizationType.ALGORITHMIC,
                pattern=r"cat\s+(\S+)\s*\|\s*wc\s+-l",
                replacement="wc -l < $1",
                conditions=["single_file"],
                expected_improvement=1.4,
                memory_impact=-0.3,
                description="Avoid unnecessary cat for line counting",
                examples=["cat file | wc -l → wc -l < file"]
            ),
            OptimizationRule(
                rule_id="ALG002",
                name="Efficient Sorting",
                type=OptimizationType.ALGORITHMIC,
                pattern=r"sort\s+(?!-S)(.+)",
                replacement="sort -S {memory_size}M $1",
                conditions=["large_file", "sufficient_memory"],
                expected_improvement=2.0,
                memory_impact=0.3,
                description="Use memory buffer for faster sorting",
                examples=["sort large_file → sort -S 1024M large_file"]
            ),
            OptimizationRule(
                rule_id="ALG003",
                name="Efficient Unique Counting",
                type=OptimizationType.ALGORITHMIC,
                pattern=r"sort\s*\|\s*uniq\s+-c\s*\|\s*sort\s+-nr",
                replacement="sort | uniq -c | sort -nr",
                conditions=["stable_sort"],
                expected_improvement=1.2,
                description="Optimize unique counting pipeline"
            )
        ])
        
        # MEMORY OPTIMIZATIONS
        self.optimization_rules.extend([
            OptimizationRule(
                rule_id="MEM001",
                name="Streaming Processing",
                type=OptimizationType.MEMORY,
                pattern=r"cat\s+(\S+)\s*\|\s*(.+)",
                replacement="$2 $1",
                conditions=["command_accepts_file"],
                expected_improvement=1.3,
                memory_impact=-0.4,
                description="Use direct file reading instead of cat pipe",
                examples=["cat file | grep pattern → grep pattern file"]
            ),
            OptimizationRule(
                rule_id="MEM002",
                name="Limit Memory Usage",
                type=OptimizationType.MEMORY,
                pattern=r"sort\s+(?!.*-S)(.+)",
                replacement="sort -S 256M $1",
                conditions=["limited_memory"],
                expected_improvement=1.1,
                memory_impact=-0.2,
                description="Limit sort memory usage in constrained environments"
            )
        ])
    
    def _initialize_tool_alternatives(self):
        """Initialize alternative tool mappings"""
        self.tool_alternatives = {
            'grep': ['rg', 'ag', 'ack'],
            'find': ['fd', 'fdfind'],
            'cat': ['bat', 'less'],
            'ls': ['exa', 'lsd'],
            'top': ['htop', 'btop', 'glances'],
            'du': ['dust', 'ncdu'],
            'gzip': ['pigz', 'zstd'],
            'tar': ['tar --use-compress-program=pigz'],
            'wget': ['curl', 'aria2c'],
            'sort': ['sort --parallel'],
        }
    
    def _detect_system_profile(self):
        """Detect system capabilities"""
        try:
            # CPU cores
            cpu_cores = int(subprocess.check_output("nproc", shell=True, text=True).strip())
            
            # Memory (approximate)
            try:
                memory_info = subprocess.check_output("free -g | grep Mem:", shell=True, text=True)
                memory_gb = float(memory_info.split()[1])
            except:
                memory_gb = 4.0  # Default assumption
            
            # Available tools
            available_tools = set()
            tools_to_check = ['rg', 'fd', 'pigz', 'parallel', 'htop', 'exa', 'bat']
            
            for tool in tools_to_check:
                try:
                    subprocess.run(['which', tool], check=True, capture_output=True)
                    available_tools.add(tool)
                except subprocess.CalledProcessError:
                    pass
            
            # Storage type (basic detection)
            storage_type = 'hdd'  # Default
            try:
                # Check if root filesystem is on SSD
                result = subprocess.check_output("lsblk -d -o name,rota | grep -E '(sda|nvme)'", 
                                               shell=True, text=True)
                if '0' in result:  # Non-rotating = SSD
                    storage_type = 'ssd'
                if 'nvme' in result:
                    storage_type = 'nvme'
            except:
                pass
            
            self.system_profile = SystemProfile(
                cpu_cores=cpu_cores,
                memory_gb=memory_gb,
                storage_type=storage_type,
                network_speed='medium',  # Default
                available_tools=available_tools
            )
            
        except Exception as e:
            # Fallback profile
            self.system_profile = SystemProfile(
                cpu_cores=2,
                memory_gb=4.0,
                storage_type='hdd',
                network_speed='medium',
                available_tools=set()
            )
    
    def optimize_command(self, command: str, context: Optional[Dict[str, Any]] = None) -> OptimizationResult:
        """Optimize a single command"""
        context = context or {}
        
        original_command = command
        current_command = command
        applied_optimizations = []
        total_speedup = 1.0
        warnings = []
        
        # Apply optimization rules in order of potential impact
        sorted_rules = sorted(
            self.optimization_rules, 
            key=lambda r: r.expected_improvement, 
            reverse=True
        )
        
        for rule in sorted_rules:
            if self._matches_pattern(current_command, rule.pattern):
                if self._check_conditions(rule, current_command, context):
                    # Apply optimization
                    optimized = self._apply_rule(current_command, rule, context)
                    if optimized != current_command:
                        applied_optimizations.append(f"{rule.name}: {rule.description}")
                        total_speedup *= rule.expected_improvement
                        current_command = optimized
                        
                        # Check for potential issues
                        rule_warnings = self._check_optimization_warnings(rule, context)
                        warnings.extend(rule_warnings)
        
        # Apply context-specific optimizations
        context_optimized = self._apply_context_optimizations(current_command, context)
        if context_optimized != current_command:
            applied_optimizations.append("Context-specific optimizations applied")
            current_command = context_optimized
        
        # Calculate confidence
        confidence = self._calculate_optimization_confidence(
            original_command, current_command, applied_optimizations
        )
        
        return OptimizationResult(
            original_command=original_command,
            optimized_command=current_command,
            optimizations_applied=applied_optimizations,
            expected_speedup=min(total_speedup, 10.0),  # Cap at 10x
            confidence=confidence,
            warnings=warnings
        )
    
    def _matches_pattern(self, command: str, pattern: str) -> bool:
        """Check if command matches optimization pattern"""
        return bool(re.search(pattern, command))
    
    def _check_conditions(self, rule: OptimizationRule, command: str, context: Dict[str, Any]) -> bool:
        """Check if optimization conditions are met"""
        for condition in rule.conditions:
            if not self._evaluate_condition(condition, command, context):
                return False
        return True
    
    def _evaluate_condition(self, condition: str, command: str, context: Dict[str, Any]) -> bool:
        """Evaluate a specific condition"""
        if condition == "file_readable":
            # Extract filename and check if readable
            match = re.search(r'cat\s+(\S+)', command)
            if match:
                filename = match.group(1).strip('"\'')
                return filename != '-' and not filename.startswith('<')
            return True
            
        elif condition == "ripgrep_available":
            return 'rg' in (self.system_profile.available_tools if self.system_profile else set())
            
        elif condition == "fd_available":
            return 'fd' in (self.system_profile.available_tools if self.system_profile else set())
            
        elif condition == "pigz_available":
            return 'pigz' in (self.system_profile.available_tools if self.system_profile else set())
            
        elif condition == "parallel_available":
            return 'parallel' in (self.system_profile.available_tools if self.system_profile else set())
            
        elif condition == "multi_core":
            return (self.system_profile.cpu_cores if self.system_profile else 1) > 1
            
        elif condition == "sufficient_memory":
            return (self.system_profile.memory_gb if self.system_profile else 0) > 2
            
        elif condition == "command_supports_multiple_args":
            # Commands that can process multiple files
            multi_arg_commands = ['grep', 'cat', 'wc', 'head', 'tail', 'sort']
            return any(cmd in command for cmd in multi_arg_commands)
            
        elif condition == "independent_iterations":
            # Check if loop iterations don't depend on each other
            return not any(dep in command for dep in ['>', '>>', 'previous', 'last'])
            
        elif condition == "large_file":
            return context.get('file_size_mb', 0) > 100
            
        elif condition == "limited_memory":
            return (self.system_profile.memory_gb if self.system_profile else 8) < 4
        
        return True
    
    def _apply_rule(self, command: str, rule: OptimizationRule, context: Dict[str, Any]) -> str:
        """Apply optimization rule to command"""
        optimized = command
        
        # Handle special cases that need context
        if rule.rule_id == "ALG002":  # Efficient sorting
            memory_size = min(int((self.system_profile.memory_gb or 2) * 256), 1024)
            replacement = rule.replacement.replace("{memory_size}", str(memory_size))
            optimized = re.sub(rule.pattern, replacement, command)
        else:
            # Standard regex replacement
            optimized = re.sub(rule.pattern, rule.replacement, command)
        
        return optimized
    
    def _apply_context_optimizations(self, command: str, context: Dict[str, Any]) -> str:
        """Apply context-specific optimizations"""
        optimized = command
        
        if not self.system_profile:
            return optimized
        
        # CPU-based optimizations
        if self.system_profile.cpu_cores > 4:
            # Add parallelization flags where beneficial
            if 'xargs' in optimized and '-P' not in optimized:
                optimized = optimized.replace('xargs', f'xargs -P{self.system_profile.cpu_cores}')
            
            if 'make' in optimized and '-j' not in optimized:
                optimized = optimized.replace('make', f'make -j{self.system_profile.cpu_cores}')
        
        # Memory-based optimizations
        if self.system_profile.memory_gb < 2:
            # Add memory constraints for memory-intensive operations
            if 'sort' in optimized and '-S' not in optimized:
                optimized = optimized.replace('sort', 'sort -S 256M')
        
        # Storage-based optimizations
        if self.system_profile.storage_type == 'ssd':
            # SSDs handle random I/O well, can use different strategies
            pass
        
        # Tool availability optimizations
        for tool, alternatives in self.tool_alternatives.items():
            if tool in optimized:
                for alt in alternatives:
                    alt_name = alt.split()[0]  # Get base command name
                    if alt_name in self.system_profile.available_tools:
                        optimized = optimized.replace(tool, alt, 1)
                        break
        
        return optimized
    
    def _check_optimization_warnings(self, rule: OptimizationRule, context: Dict[str, Any]) -> List[str]:
        """Check for potential issues with optimization"""
        warnings = []
        
        if rule.type == OptimizationType.PARALLELIZATION:
            if rule.cpu_impact > 0.7:
                warnings.append("High CPU usage optimization - monitor system load")
        
        if rule.type == OptimizationType.TOOL_SUBSTITUTION:
            warnings.append("Using alternative tool - verify output compatibility")
        
        if rule.memory_impact > 0.5:
            available_memory = self.system_profile.memory_gb if self.system_profile else 4
            if available_memory < 4:
                warnings.append("Memory-intensive optimization on limited memory system")
        
        return warnings
    
    def _calculate_optimization_confidence(self, original: str, optimized: str, optimizations: List[str]) -> float:
        """Calculate confidence in optimization result"""
        if original == optimized:
            return 1.0  # No changes = high confidence
        
        base_confidence = 0.8
        
        # Increase confidence for well-tested optimizations
        safe_optimizations = ["Cat Grep Elimination", "Sort Uniq Combination"]
        if any(opt.split(':')[0] in safe_optimizations for opt in optimizations):
            base_confidence += 0.1
        
        # Decrease confidence for multiple complex optimizations
        if len(optimizations) > 3:
            base_confidence -= 0.1
        
        # Decrease confidence for parallelization on unknown workloads
        if any('parallel' in opt.lower() for opt in optimizations):
            base_confidence -= 0.05
        
        return max(min(base_confidence, 1.0), 0.0)
    
    def benchmark_optimization(self, original: str, optimized: str, iterations: int = 3) -> Dict[str, float]:
        """Benchmark optimization performance (for testing)"""
        # This would run actual benchmarks in a real implementation
        # For now, return estimated performance based on rules
        
        results = {
            'original_time': 1.0,  # Baseline
            'optimized_time': 1.0,
            'speedup': 1.0,
            'memory_original': 100.0,  # MB
            'memory_optimized': 100.0,
        }
        
        # Calculate estimated improvements based on applied optimizations
        speedup_estimate = 1.0
        memory_factor = 1.0
        
        for rule in self.optimization_rules:
            if re.search(rule.pattern, original) and not re.search(rule.pattern, optimized):
                speedup_estimate *= rule.expected_improvement
                memory_factor += rule.memory_impact
        
        results['optimized_time'] = results['original_time'] / speedup_estimate
        results['speedup'] = speedup_estimate
        results['memory_optimized'] = results['memory_original'] * memory_factor
        
        return results
    
    def suggest_optimizations(self, command: str) -> List[str]:
        """Suggest potential optimizations without applying them"""
        suggestions = []
        
        for rule in self.optimization_rules:
            if self._matches_pattern(command, rule.pattern):
                confidence = "High" if rule.expected_improvement > 2.0 else "Medium"
                suggestions.append(
                    f"{rule.name} ({confidence} impact): {rule.description}"
                )
        
        return suggestions
    
    def get_optimization_stats(self) -> Dict[str, Any]:
        """Get optimization engine statistics"""
        if not self.system_profile:
            return {"error": "System profile not available"}
        
        return {
            'total_rules': len(self.optimization_rules),
            'rules_by_type': {
                opt_type.value: len([r for r in self.optimization_rules if r.type == opt_type])
                for opt_type in OptimizationType
            },
            'system_profile': {
                'cpu_cores': self.system_profile.cpu_cores,
                'memory_gb': self.system_profile.memory_gb,
                'storage_type': self.system_profile.storage_type,
                'available_tools': list(self.system_profile.available_tools),
            },
            'tool_alternatives': {
                tool: alts for tool, alts in self.tool_alternatives.items()
                if any(alt.split()[0] in self.system_profile.available_tools for alt in alts)
            }
        }