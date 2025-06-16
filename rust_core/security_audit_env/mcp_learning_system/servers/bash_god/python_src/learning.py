"""BASH_GOD Learning System - Command Pattern Learning and Optimization"""

import asyncio
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
import json
import hashlib
from datetime import datetime
import numpy as np
from collections import defaultdict, Counter
import re

from .command_predictor import CommandPredictor
from .chain_optimizer import ChainOptimizer
from .context_analyzer import ContextAnalyzer
from .safety_learner import SafetyLearner


@dataclass
class CommandSequence:
    """Represents a sequence of related commands"""
    commands: List[str]
    context: Dict[str, Any]
    success_rate: float
    average_duration_ms: float
    frequency: int = 1
    
    
@dataclass
class OptimizationOpportunity:
    """Represents a potential optimization"""
    original_pattern: str
    optimized_pattern: str
    improvement_factor: float
    applicable_contexts: List[str]
    confidence: float
    

@dataclass
class ContextPattern:
    """Represents context-specific command patterns"""
    context_type: str
    common_commands: List[str]
    typical_sequences: List[List[str]]
    resource_requirements: Dict[str, float]
    

@dataclass
class SafetyRule:
    """Represents a learned safety rule"""
    pattern: str
    risk_level: str
    mitigations: List[str]
    learned_from: List[str]
    

@dataclass
class BashLearning:
    """Complete learning results"""
    sequences: List[CommandSequence]
    optimizations: List[OptimizationOpportunity]
    context_patterns: List[ContextPattern]
    safety_rules: List[SafetyRule]
    

class BashGodLearning:
    """Main learning system for BASH_GOD MCP Server"""
    
    def __init__(self):
        self.command_predictor = CommandPredictor()
        self.chain_optimizer = ChainOptimizer()
        self.context_analyzer = ContextAnalyzer()
        self.safety_learner = SafetyLearner()
        
        # Learning storage
        self.command_history: List[Dict[str, Any]] = []
        self.pattern_database: Dict[str, CommandSequence] = {}
        self.optimization_cache: Dict[str, OptimizationOpportunity] = {}
        self.context_cache: Dict[str, ContextPattern] = {}
        
    async def learn_bash_patterns(self, command_history: List[Dict[str, Any]]) -> BashLearning:
        """Learn patterns from command history"""
        self.command_history.extend(command_history)
        
        # Extract command sequences
        sequences = self.extract_sequences(command_history)
        
        # Find optimization opportunities
        optimizations = await self.chain_optimizer.find_optimizations(sequences)
        
        # Analyze context patterns
        context_patterns = await self.context_analyzer.analyze(command_history)
        
        # Extract safety rules
        safety_rules = await self.safety_learner.extract_rules(command_history)
        
        # Update internal databases
        self._update_databases(sequences, optimizations, context_patterns, safety_rules)
        
        return BashLearning(sequences, optimizations, context_patterns, safety_rules)
    
    def extract_sequences(self, command_history: List[Dict[str, Any]]) -> List[CommandSequence]:
        """Extract command sequences from history"""
        sequences = []
        sequence_map = defaultdict(list)
        
        # Group by task/context
        for entry in command_history:
            task = entry.get('task', 'unknown')
            command = entry.get('command', '')
            context = entry.get('context', {})
            
            key = self._generate_sequence_key(task, context)
            sequence_map[key].append(entry)
        
        # Analyze each sequence
        for key, entries in sequence_map.items():
            if len(entries) >= 2:  # Only consider sequences with multiple commands
                commands = [e['command'] for e in entries]
                success_rate = sum(1 for e in entries if e.get('success', False)) / len(entries)
                avg_duration = np.mean([e.get('duration_ms', 0) for e in entries])
                
                sequence = CommandSequence(
                    commands=commands,
                    context=entries[0].get('context', {}),
                    success_rate=success_rate,
                    average_duration_ms=avg_duration,
                    frequency=len(entries)
                )
                sequences.append(sequence)
        
        return sequences
    
    def generate_intelligent_command(self, task: str, context: Dict[str, Any]) -> List[str]:
        """Generate intelligent command chain for a task"""
        # Predict best approach
        approach = self.command_predictor.predict_approach(task, context)
        
        # Generate command chain
        commands = self._generate_chain(approach, task, context)
        
        # Optimize for context
        optimized = self.chain_optimizer.optimize_for_context(commands, context)
        
        # Add safety checks
        safe_commands = self.safety_learner.make_safe(optimized)
        
        return safe_commands
    
    def _generate_chain(self, approach: str, task: str, context: Dict[str, Any]) -> List[str]:
        """Generate command chain based on approach"""
        commands = []
        
        # Check pattern database
        pattern_key = self._generate_pattern_key(task, approach)
        if pattern_key in self.pattern_database:
            pattern = self.pattern_database[pattern_key]
            commands = self._adapt_pattern_to_context(pattern.commands, context)
        else:
            # Generate new chain
            commands = self._generate_new_chain(task, approach, context)
        
        return commands
    
    def _adapt_pattern_to_context(self, commands: List[str], context: Dict[str, Any]) -> List[str]:
        """Adapt learned pattern to current context"""
        adapted = []
        
        for cmd in commands:
            # Replace variables
            adapted_cmd = cmd
            for key, value in context.items():
                placeholder = f"{{{key}}}"
                if placeholder in adapted_cmd:
                    adapted_cmd = adapted_cmd.replace(placeholder, str(value))
            
            adapted.append(adapted_cmd)
        
        return adapted
    
    def _generate_new_chain(self, task: str, approach: str, context: Dict[str, Any]) -> List[str]:
        """Generate new command chain from scratch"""
        commands = []
        
        # Parse task to identify operations
        operations = self._parse_task_operations(task)
        
        for op in operations:
            if op == "find_files":
                cmd = self._generate_find_command(context)
            elif op == "process_files":
                cmd = self._generate_processing_command(context)
            elif op == "cleanup":
                cmd = self._generate_cleanup_command(context)
            else:
                cmd = self._generate_generic_command(op, context)
            
            if cmd:
                commands.append(cmd)
        
        return commands
    
    def _parse_task_operations(self, task: str) -> List[str]:
        """Parse task description to identify operations"""
        operations = []
        task_lower = task.lower()
        
        # Common operation patterns
        if "find" in task_lower or "search" in task_lower:
            operations.append("find_files")
        if "process" in task_lower or "analyze" in task_lower:
            operations.append("process_files")
        if "clean" in task_lower or "remove" in task_lower:
            operations.append("cleanup")
        if "backup" in task_lower:
            operations.append("backup")
        if "monitor" in task_lower:
            operations.append("monitor")
        
        return operations
    
    def _generate_find_command(self, context: Dict[str, Any]) -> str:
        """Generate find command based on context"""
        path = context.get('path', '.')
        pattern = context.get('pattern', '*')
        size = context.get('size')
        days = context.get('days')
        
        cmd_parts = ['find', path]
        
        if pattern != '*':
            cmd_parts.extend(['-name', f'"{pattern}"'])
        
        if size:
            cmd_parts.extend(['-size', f'+{size}M'])
        
        if days:
            cmd_parts.extend(['-mtime', f'+{days}'])
        
        return ' '.join(cmd_parts)
    
    def _generate_processing_command(self, context: Dict[str, Any]) -> str:
        """Generate processing command based on context"""
        operation = context.get('operation', 'list')
        
        if operation == 'count':
            return 'wc -l'
        elif operation == 'sum_size':
            return "awk '{sum += $1} END {print sum}'"
        elif operation == 'sort':
            return 'sort -nr'
        else:
            return 'xargs ls -lh'
    
    def _generate_cleanup_command(self, context: Dict[str, Any]) -> str:
        """Generate cleanup command based on context"""
        dry_run = context.get('dry_run', True)
        force = context.get('force', False)
        
        if dry_run:
            return 'xargs -I {} echo "Would remove: {}"'
        elif force:
            return 'xargs rm -f'
        else:
            return 'xargs rm -i'
    
    def _generate_generic_command(self, operation: str, context: Dict[str, Any]) -> str:
        """Generate generic command for operation"""
        command_templates = {
            'backup': 'tar -czf backup_$(date +%Y%m%d_%H%M%S).tar.gz',
            'monitor': 'watch -n 5',
            'compress': 'gzip -9',
            'decompress': 'gunzip',
            'encrypt': 'gpg -c',
            'decrypt': 'gpg -d',
        }
        
        return command_templates.get(operation, '')
    
    def _generate_sequence_key(self, task: str, context: Dict[str, Any]) -> str:
        """Generate unique key for sequence"""
        context_str = json.dumps(context, sort_keys=True)
        return hashlib.md5(f"{task}:{context_str}".encode()).hexdigest()[:16]
    
    def _generate_pattern_key(self, task: str, approach: str) -> str:
        """Generate unique key for pattern"""
        return hashlib.md5(f"{task}:{approach}".encode()).hexdigest()[:16]
    
    def _update_databases(self, sequences: List[CommandSequence],
                         optimizations: List[OptimizationOpportunity],
                         context_patterns: List[ContextPattern],
                         safety_rules: List[SafetyRule]):
        """Update internal learning databases"""
        # Update pattern database
        for seq in sequences:
            if seq.success_rate > 0.7 and seq.frequency > 2:
                key = self._generate_pattern_key(
                    seq.context.get('task', 'unknown'),
                    seq.context.get('approach', 'default')
                )
                self.pattern_database[key] = seq
        
        # Update optimization cache
        for opt in optimizations:
            if opt.confidence > 0.8:
                key = hashlib.md5(opt.original_pattern.encode()).hexdigest()[:16]
                self.optimization_cache[key] = opt
        
        # Update context cache
        for ctx in context_patterns:
            self.context_cache[ctx.context_type] = ctx
    
    def get_learning_stats(self) -> Dict[str, Any]:
        """Get current learning statistics"""
        return {
            'total_commands_learned': len(self.command_history),
            'patterns_identified': len(self.pattern_database),
            'optimizations_found': len(self.optimization_cache),
            'context_types': len(self.context_cache),
            'average_success_rate': np.mean([
                seq.success_rate for seq in self.pattern_database.values()
            ]) if self.pattern_database else 0.0,
        }
    
    def export_knowledge(self) -> Dict[str, Any]:
        """Export learned knowledge"""
        return {
            'patterns': {k: v.__dict__ for k, v in self.pattern_database.items()},
            'optimizations': {k: v.__dict__ for k, v in self.optimization_cache.items()},
            'contexts': {k: v.__dict__ for k, v in self.context_cache.items()},
            'stats': self.get_learning_stats(),
            'export_time': datetime.now().isoformat(),
        }
    
    def import_knowledge(self, knowledge: Dict[str, Any]):
        """Import previously learned knowledge"""
        # Import patterns
        for key, data in knowledge.get('patterns', {}).items():
            self.pattern_database[key] = CommandSequence(**data)
        
        # Import optimizations
        for key, data in knowledge.get('optimizations', {}).items():
            self.optimization_cache[key] = OptimizationOpportunity(**data)
        
        # Import contexts
        for key, data in knowledge.get('contexts', {}).items():
            self.context_cache[key] = ContextPattern(**data)