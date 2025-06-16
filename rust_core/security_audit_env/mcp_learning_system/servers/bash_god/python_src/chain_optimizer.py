"""Chain Optimizer - Optimizes command chains for performance"""

import re
from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass
import asyncio
from collections import defaultdict
import numpy as np


@dataclass
class OptimizationRule:
    """Represents an optimization rule"""
    name: str
    pattern: str
    replacement: str
    conditions: List[str]
    expected_improvement: float
    

class ChainOptimizer:
    """Optimizes bash command chains"""
    
    def __init__(self):
        self.optimization_rules = self._initialize_rules()
        self.performance_cache: Dict[str, float] = {}
        self.optimization_history: List[Dict[str, Any]] = []
        
    def _initialize_rules(self) -> List[OptimizationRule]:
        """Initialize optimization rules"""
        return [
            # Pipeline optimizations
            OptimizationRule(
                name="cat_grep_elimination",
                pattern=r"cat\s+(\S+)\s*\|\s*grep",
                replacement="grep {} $1",
                conditions=["file_exists"],
                expected_improvement=1.3
            ),
            OptimizationRule(
                name="multiple_grep_combination",
                pattern=r"grep\s+'([^']+)'\s*\|\s*grep\s+'([^']+)'",
                replacement="grep -E '$1.*$2'",
                conditions=["patterns_compatible"],
                expected_improvement=1.5
            ),
            OptimizationRule(
                name="sort_uniq_combination",
                pattern=r"sort\s*(.*?)\s*\|\s*uniq",
                replacement="sort -u $1",
                conditions=["no_special_uniq_flags"],
                expected_improvement=1.2
            ),
            
            # Find optimizations
            OptimizationRule(
                name="find_exec_to_xargs",
                pattern=r"find\s+(.*?)\s+-exec\s+(\S+)\s+\{\}\s*\\;",
                replacement="find $1 -print0 | xargs -0 $2",
                conditions=["command_supports_multiple_args"],
                expected_improvement=2.5
            ),
            OptimizationRule(
                name="find_type_optimization",
                pattern=r"find\s+(.*?)\s+-name\s+'([^']+)'(?!\s+-type)",
                replacement="find $1 -type f -name '$2'",
                conditions=["searching_files"],
                expected_improvement=1.1
            ),
            
            # AWK optimizations
            OptimizationRule(
                name="grep_awk_combination",
                pattern=r"grep\s+'([^']+)'\s*\|\s*awk\s+'([^']+)'",
                replacement="awk '/$1/ && $2'",
                conditions=["awk_pattern_valid"],
                expected_improvement=1.4
            ),
            OptimizationRule(
                name="multiple_awk_combination",
                pattern=r"awk\s+'([^']+)'\s*\|\s*awk\s+'([^']+)'",
                replacement="awk '$1; $2'",
                conditions=["awk_chainable"],
                expected_improvement=1.6
            ),
            
            # Loop optimizations
            OptimizationRule(
                name="for_loop_parallelization",
                pattern=r"for\s+(\w+)\s+in\s+(.*?);\s*do\s+(.*?);\s*done",
                replacement="echo $2 | tr ' ' '\\n' | parallel -j+0 '$3'",
                conditions=["parallel_safe", "independent_iterations"],
                expected_improvement=3.0
            ),
            
            # IO optimizations
            OptimizationRule(
                name="multiple_file_reads",
                pattern=r"cat\s+(\S+)\s*;\s*cat\s+(\S+)",
                replacement="cat $1 $2",
                conditions=["sequential_read"],
                expected_improvement=1.2
            ),
            OptimizationRule(
                name="redirect_optimization",
                pattern=r"echo\s+'([^']+)'\s*>>\s*(\S+)\s*;\s*echo\s+'([^']+)'\s*>>\s*\2",
                replacement="{ echo '$1'; echo '$3'; } >> $2",
                conditions=["same_target_file"],
                expected_improvement=1.3
            ),
            
            # Tool-specific optimizations
            OptimizationRule(
                name="use_ripgrep",
                pattern=r"grep\s+-r\s+'([^']+)'\s+(\S+)",
                replacement="rg '$1' $2",
                conditions=["ripgrep_available"],
                expected_improvement=5.0
            ),
            OptimizationRule(
                name="use_fd",
                pattern=r"find\s+(\S+)\s+-name\s+'([^']+)'",
                replacement="fd '$2' $1",
                conditions=["fd_available"],
                expected_improvement=3.0
            ),
        ]
    
    async def find_optimizations(self, sequences: List[Any]) -> List[Any]:
        """Find optimization opportunities in command sequences"""
        optimizations = []
        
        for sequence in sequences:
            # Check each command in sequence
            for i, command in enumerate(sequence.commands):
                # Check against optimization rules
                for rule in self.optimization_rules:
                    if self._matches_rule(command, rule):
                        optimization = await self._create_optimization(
                            command, rule, sequence.context
                        )
                        if optimization:
                            optimizations.append(optimization)
                
                # Check command pairs for fusion opportunities
                if i < len(sequence.commands) - 1:
                    next_command = sequence.commands[i + 1]
                    fusion_opt = self._check_fusion_opportunity(command, next_command)
                    if fusion_opt:
                        optimizations.append(fusion_opt)
        
        return optimizations
    
    def optimize_for_context(self, commands: List[str], context: Dict[str, Any]) -> List[str]:
        """Optimize commands based on context"""
        optimized = []
        
        for command in commands:
            opt_command = self._apply_context_optimizations(command, context)
            optimized.append(opt_command)
        
        # Check for chain-level optimizations
        optimized = self._optimize_chain(optimized, context)
        
        return optimized
    
    def _matches_rule(self, command: str, rule: OptimizationRule) -> bool:
        """Check if command matches optimization rule"""
        return bool(re.search(rule.pattern, command))
    
    async def _create_optimization(self, command: str, rule: OptimizationRule, 
                                 context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Create optimization opportunity"""
        # Check if conditions are met
        if not await self._check_conditions(rule.conditions, command, context):
            return None
        
        # Apply replacement
        optimized = re.sub(rule.pattern, rule.replacement, command)
        
        # Estimate improvement
        improvement = await self._estimate_improvement(command, optimized, rule)
        
        return {
            'original_pattern': command,
            'optimized_pattern': optimized,
            'improvement_factor': improvement,
            'applicable_contexts': [context.get('type', 'general')],
            'confidence': 0.8,
            'rule_name': rule.name,
        }
    
    async def _check_conditions(self, conditions: List[str], command: str, 
                              context: Dict[str, Any]) -> bool:
        """Check if optimization conditions are met"""
        for condition in conditions:
            if condition == "file_exists":
                # Check if file in command exists
                match = re.search(r'cat\s+(\S+)', command)
                if match:
                    # In real implementation, would check file existence
                    pass
                    
            elif condition == "patterns_compatible":
                # Check if grep patterns can be combined
                patterns = re.findall(r"grep\s+'([^']+)'", command)
                if len(patterns) >= 2:
                    # Check if patterns don't conflict
                    pass
                    
            elif condition == "parallel_safe":
                # Check if operations are independent
                if ">" in command or ">>" in command:
                    return False
                    
            elif condition == "ripgrep_available":
                return context.get('tools', {}).get('ripgrep', False)
                
            elif condition == "fd_available":
                return context.get('tools', {}).get('fd', False)
        
        return True
    
    async def _estimate_improvement(self, original: str, optimized: str, 
                                  rule: OptimizationRule) -> float:
        """Estimate performance improvement"""
        # Check cache
        cache_key = f"{original}|{optimized}"
        if cache_key in self.performance_cache:
            return self.performance_cache[cache_key]
        
        # Base improvement from rule
        improvement = rule.expected_improvement
        
        # Adjust based on command characteristics
        if 'parallel' in optimized and 'parallel' not in original:
            # Parallel processing can give significant speedup
            cpu_cores = 4  # Would get from context
            improvement *= min(cpu_cores / 2, 4.0)
        
        if 'xargs' in optimized and '-exec' in original:
            # xargs is much more efficient than -exec
            improvement *= 1.5
        
        if ('rg' in optimized or 'ripgrep' in optimized) and 'grep' in original:
            # ripgrep is significantly faster
            improvement *= 2.0
        
        # Cache result
        self.performance_cache[cache_key] = improvement
        
        return improvement
    
    def _check_fusion_opportunity(self, cmd1: str, cmd2: str) -> Optional[Dict[str, Any]]:
        """Check if two commands can be fused"""
        # Check for pipe fusion
        if cmd1.endswith('|') or cmd2.startswith('|'):
            return None
        
        # Check for similar operations
        cmd1_parts = cmd1.split()
        cmd2_parts = cmd2.split()
        
        if not cmd1_parts or not cmd2_parts:
            return None
        
        # Same command fusion
        if cmd1_parts[0] == cmd2_parts[0]:
            if cmd1_parts[0] == 'echo' and '>>' in cmd1 and '>>' in cmd2:
                # Multiple echo to same file
                return {
                    'original_pattern': f"{cmd1}; {cmd2}",
                    'optimized_pattern': self._fuse_echo_commands(cmd1, cmd2),
                    'improvement_factor': 1.3,
                    'applicable_contexts': ['general'],
                    'confidence': 0.9,
                }
        
        return None
    
    def _fuse_echo_commands(self, cmd1: str, cmd2: str) -> str:
        """Fuse multiple echo commands"""
        # Extract content and target
        match1 = re.search(r"echo\s+'([^']+)'\s*>>\s*(\S+)", cmd1)
        match2 = re.search(r"echo\s+'([^']+)'\s*>>\s*(\S+)", cmd2)
        
        if match1 and match2 and match1.group(2) == match2.group(2):
            return f"{{ echo '{match1.group(1)}'; echo '{match2.group(1)}'; }} >> {match1.group(2)}"
        
        return f"{cmd1}; {cmd2}"
    
    def _apply_context_optimizations(self, command: str, context: Dict[str, Any]) -> str:
        """Apply context-specific optimizations"""
        optimized = command
        
        # CPU optimizations
        cpu_cores = context.get('cpu_cores', 1)
        if cpu_cores > 2:
            # Add parallelization where beneficial
            if 'xargs' in command and '-P' not in command:
                optimized = optimized.replace('xargs', f'xargs -P{cpu_cores}')
            
            if 'find' in command and 'parallel' not in command and '|' in command:
                # Consider parallelizing find output processing
                parts = optimized.split('|', 1)
                if len(parts) == 2 and 'xargs' not in parts[1]:
                    optimized = f"{parts[0]} | parallel -j{cpu_cores} '{parts[1].strip()}'"
        
        # Memory optimizations
        available_memory = context.get('available_memory_mb', 1024)
        if available_memory < 512:
            # Add memory constraints
            if 'sort' in optimized and '-S' not in optimized:
                optimized = optimized.replace('sort', 'sort -S 256M')
            
            if 'parallel' in optimized and '-j' in optimized:
                # Reduce parallel jobs for low memory
                optimized = re.sub(r'-j\d+', '-j2', optimized)
        
        # Tool availability
        tools = context.get('tools', {})
        if tools.get('ripgrep') and 'grep -r' in optimized:
            optimized = optimized.replace('grep -r', 'rg')
        
        if tools.get('fd') and 'find' in optimized and '-name' in optimized:
            # Simple find to fd conversion
            optimized = self._convert_find_to_fd(optimized)
        
        return optimized
    
    def _convert_find_to_fd(self, command: str) -> str:
        """Convert find command to fd"""
        # Simple conversion for common patterns
        conversions = [
            (r"find\s+\.\s+-name\s+'([^']+)'", "fd '$1'"),
            (r"find\s+(\S+)\s+-name\s+'([^']+)'", "fd '$2' $1"),
            (r"find\s+\.\s+-type\s+f\s+-name\s+'([^']+)'", "fd -t f '$1'"),
            (r"find\s+\.\s+-type\s+d\s+-name\s+'([^']+)'", "fd -t d '$1'"),
        ]
        
        for pattern, replacement in conversions:
            if re.search(pattern, command):
                return re.sub(pattern, replacement, command)
        
        return command
    
    def _optimize_chain(self, commands: List[str], context: Dict[str, Any]) -> List[str]:
        """Optimize entire command chain"""
        optimized = commands.copy()
        
        # Look for redundant operations
        optimized = self._remove_redundancies(optimized)
        
        # Reorder for efficiency
        optimized = self._reorder_commands(optimized)
        
        # Batch similar operations
        optimized = self._batch_operations(optimized)
        
        return optimized
    
    def _remove_redundancies(self, commands: List[str]) -> List[str]:
        """Remove redundant operations"""
        cleaned = []
        seen_operations = set()
        
        for cmd in commands:
            # Create operation signature
            sig = self._get_operation_signature(cmd)
            
            if sig not in seen_operations:
                cleaned.append(cmd)
                seen_operations.add(sig)
            else:
                # Check if it's truly redundant
                if not self._is_stateful_command(cmd):
                    continue  # Skip redundant stateless operation
                else:
                    cleaned.append(cmd)  # Keep stateful operations
        
        return cleaned
    
    def _get_operation_signature(self, command: str) -> str:
        """Get signature of operation for redundancy checking"""
        # Remove variable parts
        sig = re.sub(r'\d+', 'N', command)  # Replace numbers
        sig = re.sub(r'/tmp/\S+', '/tmp/FILE', sig)  # Normalize temp files
        sig = re.sub(r'\$\w+', '$VAR', sig)  # Normalize variables
        return sig
    
    def _is_stateful_command(self, command: str) -> bool:
        """Check if command has side effects"""
        stateful_indicators = [
            '>', '>>', 'rm', 'mv', 'cp', 'mkdir', 'touch',
            'chmod', 'chown', 'ln', 'sed -i', 'awk -i'
        ]
        
        return any(indicator in command for indicator in stateful_indicators)
    
    def _reorder_commands(self, commands: List[str]) -> List[str]:
        """Reorder commands for efficiency"""
        # Simple reordering - put filters early
        filters = []
        others = []
        
        for cmd in commands:
            if any(f in cmd for f in ['grep', 'awk', 'sed', 'head', 'tail']):
                filters.append(cmd)
            else:
                others.append(cmd)
        
        # Put filters first to reduce data flow
        return filters + others
    
    def _batch_operations(self, commands: List[str]) -> List[str]:
        """Batch similar operations together"""
        batched = []
        i = 0
        
        while i < len(commands):
            cmd = commands[i]
            
            # Look for batchable operations
            if 'echo' in cmd and '>>' in cmd:
                # Batch multiple echoes to same file
                batch = [cmd]
                j = i + 1
                
                while j < len(commands):
                    next_cmd = commands[j]
                    if 'echo' in next_cmd and '>>' in next_cmd:
                        # Check if same target file
                        if self._same_redirect_target(cmd, next_cmd):
                            batch.append(next_cmd)
                            j += 1
                        else:
                            break
                    else:
                        break
                
                if len(batch) > 1:
                    # Create batched command
                    batched_cmd = self._create_batched_echo(batch)
                    batched.append(batched_cmd)
                    i = j
                else:
                    batched.append(cmd)
                    i += 1
            else:
                batched.append(cmd)
                i += 1
        
        return batched
    
    def _same_redirect_target(self, cmd1: str, cmd2: str) -> bool:
        """Check if two commands redirect to same file"""
        match1 = re.search(r'>>\s*(\S+)', cmd1)
        match2 = re.search(r'>>\s*(\S+)', cmd2)
        
        return match1 and match2 and match1.group(1) == match2.group(1)
    
    def _create_batched_echo(self, echo_commands: List[str]) -> str:
        """Create batched echo command"""
        contents = []
        target = None
        
        for cmd in echo_commands:
            match = re.search(r"echo\s+'([^']+)'\s*>>\s*(\S+)", cmd)
            if match:
                contents.append(match.group(1))
                target = match.group(2)
        
        if contents and target:
            echo_parts = [f"echo '{content}'" for content in contents]
            return f"{{ {'; '.join(echo_parts)}; }} >> {target}"
        
        return '; '.join(echo_commands)
    
    def get_optimization_stats(self) -> Dict[str, Any]:
        """Get optimization statistics"""
        if not self.optimization_history:
            return {'total_optimizations': 0}
        
        improvements = [opt['improvement_factor'] for opt in self.optimization_history]
        
        return {
            'total_optimizations': len(self.optimization_history),
            'average_improvement': np.mean(improvements),
            'max_improvement': max(improvements),
            'most_common_rules': self._get_most_common_rules(),
        }
    
    def _get_most_common_rules(self) -> List[Tuple[str, int]]:
        """Get most commonly applied rules"""
        rule_counts = defaultdict(int)
        
        for opt in self.optimization_history:
            rule_name = opt.get('rule_name', 'unknown')
            rule_counts[rule_name] += 1
        
        return sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:5]