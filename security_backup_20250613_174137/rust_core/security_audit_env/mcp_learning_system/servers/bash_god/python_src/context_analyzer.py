"""Context Analyzer - Analyzes command contexts and patterns"""

import asyncio
from typing import List, Dict, Any, Tuple, Set
from collections import defaultdict, Counter
from dataclasses import dataclass, field
import numpy as np
import re
from datetime import datetime, timedelta


@dataclass
class ExecutionContext:
    """Represents execution context"""
    timestamp: datetime
    user: str
    working_directory: str
    environment: Dict[str, str]
    system_state: Dict[str, Any]
    

@dataclass 
class ContextCluster:
    """Represents a cluster of similar contexts"""
    cluster_id: str
    contexts: List[ExecutionContext] = field(default_factory=list)
    common_patterns: List[str] = field(default_factory=list)
    typical_commands: List[str] = field(default_factory=list)
    resource_profile: Dict[str, float] = field(default_factory=dict)


class ContextAnalyzer:
    """Analyzes command execution contexts"""
    
    def __init__(self):
        self.context_history: List[ExecutionContext] = []
        self.context_clusters: Dict[str, ContextCluster] = {}
        self.pattern_frequency: Counter = Counter()
        self.time_patterns: Dict[str, List[datetime]] = defaultdict(list)
        self.directory_patterns: Dict[str, List[str]] = defaultdict(list)
        
    async def analyze(self, command_history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze command history for context patterns"""
        # Extract contexts
        contexts = self._extract_contexts(command_history)
        
        # Cluster similar contexts
        clusters = await self._cluster_contexts(contexts)
        
        # Analyze patterns per cluster
        patterns = []
        for cluster in clusters:
            pattern = await self._analyze_cluster_patterns(cluster, command_history)
            patterns.append(pattern)
        
        # Analyze temporal patterns
        temporal_patterns = self._analyze_temporal_patterns(command_history)
        
        # Analyze directory-specific patterns
        directory_patterns = self._analyze_directory_patterns(command_history)
        
        # Combine all patterns
        combined_patterns = self._combine_patterns(patterns, temporal_patterns, directory_patterns)
        
        return combined_patterns
    
    def _extract_contexts(self, command_history: List[Dict[str, Any]]) -> List[ExecutionContext]:
        """Extract execution contexts from history"""
        contexts = []
        
        for entry in command_history:
            context = ExecutionContext(
                timestamp=datetime.fromtimestamp(entry.get('timestamp', 0)),
                user=entry.get('user', 'unknown'),
                working_directory=entry.get('cwd', '/'),
                environment=entry.get('environment', {}),
                system_state=entry.get('system_state', {})
            )
            contexts.append(context)
            self.context_history.append(context)
        
        return contexts
    
    async def _cluster_contexts(self, contexts: List[ExecutionContext]) -> List[ContextCluster]:
        """Cluster similar contexts together"""
        clusters = []
        
        # Simple clustering by working directory and user
        cluster_map = defaultdict(list)
        
        for context in contexts:
            key = f"{context.user}:{context.working_directory}"
            cluster_map[key].append(context)
        
        # Create clusters
        for key, context_list in cluster_map.items():
            if len(context_list) >= 2:  # Only create clusters with multiple contexts
                cluster = ContextCluster(
                    cluster_id=key,
                    contexts=context_list,
                    resource_profile=self._calculate_resource_profile(context_list)
                )
                clusters.append(cluster)
                self.context_clusters[key] = cluster
        
        return clusters
    
    async def _analyze_cluster_patterns(self, cluster: ContextCluster, 
                                      command_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze patterns within a context cluster"""
        # Filter commands for this cluster
        cluster_commands = []
        for entry in command_history:
            if (entry.get('user') == cluster.contexts[0].user and 
                entry.get('cwd') == cluster.contexts[0].working_directory):
                cluster_commands.append(entry['command'])
        
        # Find common command patterns
        common_patterns = self._find_common_patterns(cluster_commands)
        cluster.common_patterns = common_patterns
        
        # Find typical command sequences
        typical_sequences = self._find_typical_sequences(cluster_commands)
        cluster.typical_commands = typical_sequences
        
        return {
            'context_type': cluster.cluster_id,
            'common_commands': common_patterns,
            'typical_sequences': typical_sequences,
            'resource_requirements': cluster.resource_profile,
        }
    
    def _calculate_resource_profile(self, contexts: List[ExecutionContext]) -> Dict[str, float]:
        """Calculate average resource requirements for contexts"""
        cpu_usage = []
        memory_usage = []
        
        for context in contexts:
            state = context.system_state
            if 'cpu_usage' in state:
                cpu_usage.append(state['cpu_usage'])
            if 'memory_usage' in state:
                memory_usage.append(state['memory_usage'])
        
        return {
            'avg_cpu': np.mean(cpu_usage) if cpu_usage else 0.0,
            'max_cpu': max(cpu_usage) if cpu_usage else 0.0,
            'avg_memory': np.mean(memory_usage) if memory_usage else 0.0,
            'max_memory': max(memory_usage) if memory_usage else 0.0,
        }
    
    def _find_common_patterns(self, commands: List[str]) -> List[str]:
        """Find common command patterns"""
        # Extract command bases (first word)
        command_bases = [cmd.split()[0] if cmd else '' for cmd in commands]
        base_counter = Counter(command_bases)
        
        # Extract command patterns (command + first flag)
        patterns = []
        for cmd in commands:
            parts = cmd.split()
            if len(parts) >= 2:
                pattern = f"{parts[0]} {parts[1]}" if parts[1].startswith('-') else parts[0]
                patterns.append(pattern)
            elif parts:
                patterns.append(parts[0])
        
        pattern_counter = Counter(patterns)
        
        # Get most common patterns
        common_patterns = []
        for pattern, count in pattern_counter.most_common(10):
            if count >= 2:  # Pattern appears at least twice
                common_patterns.append(pattern)
                self.pattern_frequency[pattern] += count
        
        return common_patterns
    
    def _find_typical_sequences(self, commands: List[str]) -> List[List[str]]:
        """Find typical command sequences"""
        sequences = []
        
        # Look for 2-3 command sequences
        for i in range(len(commands) - 1):
            # 2-command sequences
            seq2 = [commands[i], commands[i + 1]]
            sequences.append(seq2)
            
            # 3-command sequences
            if i < len(commands) - 2:
                seq3 = [commands[i], commands[i + 1], commands[i + 2]]
                sequences.append(seq3)
        
        # Count sequence occurrences
        seq_counter = Counter(tuple(seq) for seq in sequences)
        
        # Get most common sequences
        typical_sequences = []
        for seq_tuple, count in seq_counter.most_common(5):
            if count >= 2:  # Sequence appears at least twice
                typical_sequences.append(list(seq_tuple))
        
        return typical_sequences
    
    def _analyze_temporal_patterns(self, command_history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze time-based patterns"""
        temporal_patterns = []
        
        # Group commands by hour of day
        hourly_commands = defaultdict(list)
        for entry in command_history:
            timestamp = datetime.fromtimestamp(entry.get('timestamp', 0))
            hour = timestamp.hour
            hourly_commands[hour].append(entry['command'])
            
            # Track time patterns
            cmd_base = entry['command'].split()[0] if entry['command'] else ''
            self.time_patterns[cmd_base].append(timestamp)
        
        # Find peak hours
        peak_hours = sorted(hourly_commands.items(), 
                          key=lambda x: len(x[1]), reverse=True)[:3]
        
        # Find scheduled/periodic commands
        periodic_commands = self._find_periodic_commands()
        
        temporal_patterns.append({
            'peak_hours': [hour for hour, _ in peak_hours],
            'periodic_commands': periodic_commands,
        })
        
        return temporal_patterns
    
    def _find_periodic_commands(self) -> List[Dict[str, Any]]:
        """Find commands that run periodically"""
        periodic = []
        
        for cmd, timestamps in self.time_patterns.items():
            if len(timestamps) >= 3:
                # Calculate time differences
                timestamps.sort()
                diffs = []
                for i in range(1, len(timestamps)):
                    diff = (timestamps[i] - timestamps[i-1]).total_seconds()
                    diffs.append(diff)
                
                # Check for regular intervals
                if diffs:
                    mean_diff = np.mean(diffs)
                    std_diff = np.std(diffs)
                    
                    # Low standard deviation indicates regular interval
                    if std_diff < mean_diff * 0.2:  # 20% variance
                        periodic.append({
                            'command': cmd,
                            'interval_seconds': mean_diff,
                            'interval_human': self._seconds_to_human(mean_diff),
                            'occurrences': len(timestamps),
                        })
        
        return periodic
    
    def _seconds_to_human(self, seconds: float) -> str:
        """Convert seconds to human-readable format"""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            return f"{int(seconds / 60)}m"
        elif seconds < 86400:
            return f"{int(seconds / 3600)}h"
        else:
            return f"{int(seconds / 86400)}d"
    
    def _analyze_directory_patterns(self, command_history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze directory-specific patterns"""
        directory_patterns = []
        
        # Group commands by directory
        for entry in command_history:
            cwd = entry.get('cwd', '/')
            command = entry.get('command', '')
            self.directory_patterns[cwd].append(command)
        
        # Analyze each directory
        for directory, commands in self.directory_patterns.items():
            if len(commands) >= 3:  # Need sufficient data
                patterns = self._find_common_patterns(commands)
                
                # Determine directory type
                dir_type = self._classify_directory(directory, commands)
                
                directory_patterns.append({
                    'directory': directory,
                    'type': dir_type,
                    'common_operations': patterns[:5],
                    'command_count': len(commands),
                })
        
        return directory_patterns
    
    def _classify_directory(self, directory: str, commands: List[str]) -> str:
        """Classify directory type based on commands"""
        # Count command types
        command_types = Counter()
        for cmd in commands:
            if cmd:
                base = cmd.split()[0]
                command_types[base] += 1
        
        # Classification rules
        if 'git' in command_types and command_types['git'] > len(commands) * 0.2:
            return 'git_repository'
        elif 'docker' in command_types or 'docker-compose' in command_types:
            return 'docker_project'
        elif 'npm' in command_types or 'yarn' in command_types:
            return 'node_project'
        elif 'python' in command_types or 'pip' in command_types:
            return 'python_project'
        elif 'make' in command_types:
            return 'build_directory'
        elif directory.startswith('/var/log'):
            return 'log_directory'
        elif directory.startswith('/etc'):
            return 'config_directory'
        elif directory == os.path.expanduser('~'):
            return 'home_directory'
        else:
            return 'general'
    
    def _combine_patterns(self, cluster_patterns: List[Dict[str, Any]],
                         temporal_patterns: List[Dict[str, Any]],
                         directory_patterns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Combine all pattern types"""
        combined = []
        
        # Add cluster patterns
        combined.extend(cluster_patterns)
        
        # Add temporal insights
        if temporal_patterns:
            combined.append({
                'context_type': 'temporal',
                'common_commands': [],
                'typical_sequences': [],
                'resource_requirements': {},
                'temporal_data': temporal_patterns[0],
            })
        
        # Add directory insights
        if directory_patterns:
            for dir_pattern in directory_patterns:
                combined.append({
                    'context_type': f"directory:{dir_pattern['type']}",
                    'common_commands': dir_pattern['common_operations'],
                    'typical_sequences': [],
                    'resource_requirements': {},
                    'directory': dir_pattern['directory'],
                })
        
        return combined
    
    def get_context_for_task(self, task: str, current_context: Dict[str, Any]) -> Dict[str, Any]:
        """Get best matching context for a task"""
        # Find similar historical contexts
        similar_contexts = self._find_similar_contexts(current_context)
        
        if similar_contexts:
            # Use most recent similar context
            return similar_contexts[0]
        
        # Create new context
        return current_context
    
    def _find_similar_contexts(self, target_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find contexts similar to target"""
        similar = []
        
        target_user = target_context.get('user', '')
        target_cwd = target_context.get('cwd', '')
        
        for context in self.context_history:
            similarity = 0.0
            
            # User match
            if context.user == target_user:
                similarity += 0.3
            
            # Directory match
            if context.working_directory == target_cwd:
                similarity += 0.4
            elif target_cwd.startswith(context.working_directory):
                similarity += 0.2
            
            # Time proximity (same hour)
            if hasattr(context, 'timestamp'):
                if context.timestamp.hour == datetime.now().hour:
                    similarity += 0.1
            
            if similarity > 0.5:
                similar.append({
                    'user': context.user,
                    'cwd': context.working_directory,
                    'environment': context.environment,
                    'similarity': similarity,
                })
        
        # Sort by similarity
        similar.sort(key=lambda x: x['similarity'], reverse=True)
        
        return similar
    
    def suggest_commands_for_context(self, context: Dict[str, Any]) -> List[str]:
        """Suggest commands based on context"""
        suggestions = []
        
        # Check directory type
        cwd = context.get('cwd', '/')
        if cwd in self.directory_patterns:
            # Get common commands for this directory
            dir_commands = self.directory_patterns[cwd]
            command_counter = Counter(cmd.split()[0] for cmd in dir_commands if cmd)
            
            for cmd, _ in command_counter.most_common(5):
                suggestions.append(cmd)
        
        # Check user patterns
        user = context.get('user', '')
        user_key = f"{user}:{cwd}"
        if user_key in self.context_clusters:
            cluster = self.context_clusters[user_key]
            suggestions.extend(cluster.common_patterns[:3])
        
        # Remove duplicates while preserving order
        seen = set()
        unique_suggestions = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique_suggestions.append(s)
        
        return unique_suggestions