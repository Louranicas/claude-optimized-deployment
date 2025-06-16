"""Safety Learner - Learns safety patterns and rules from command execution"""

import re
import asyncio
from typing import List, Dict, Any, Tuple, Set, Optional
from dataclasses import dataclass, field
from collections import defaultdict, Counter
import hashlib
from datetime import datetime


@dataclass
class SafetyIncident:
    """Represents a safety incident"""
    command: str
    error_type: str
    error_message: str
    severity: str
    timestamp: datetime
    context: Dict[str, Any]
    

@dataclass
class LearnedSafetyRule:
    """Represents a learned safety rule"""
    rule_id: str
    pattern: str
    risk_level: str
    mitigations: List[str]
    learned_from: List[SafetyIncident]
    confidence: float
    

class SafetyLearner:
    """Learns safety patterns from command execution history"""
    
    def __init__(self):
        self.incidents: List[SafetyIncident] = []
        self.safety_rules: Dict[str, LearnedSafetyRule] = {}
        self.dangerous_patterns: Set[str] = set()
        self.safe_patterns: Set[str] = set()
        self.mitigation_strategies: Dict[str, List[str]] = defaultdict(list)
        
        # Initialize with known dangerous patterns
        self._initialize_known_dangers()
        
    def _initialize_known_dangers(self):
        """Initialize with known dangerous patterns"""
        self.dangerous_patterns.update([
            r'rm\s+-rf\s+/',
            r'chmod\s+777',
            r':\(\)\s*\{\s*:\|:&\s*\};',  # Fork bomb
            r'dd\s+.*of=/dev/[sh]d',
            r'mkfs\.',
            r'>\s*/dev/[sh]d',
            r'curl.*\|\s*(sudo\s+)?sh',
            r'wget.*\|\s*(sudo\s+)?sh',
        ])
        
        self.mitigation_strategies.update({
            'rm_root': [
                'Use --preserve-root flag',
                'Verify target path before execution',
                'Consider using trash-cli instead',
            ],
            'chmod_777': [
                'Use more restrictive permissions (755 or 644)',
                'Only grant necessary permissions',
                'Consider using ACLs for fine-grained control',
            ],
            'curl_pipe': [
                'Download script first and review',
                'Verify script source and integrity',
                'Run in isolated environment first',
            ],
            'dd_device': [
                'Double-check device path',
                'Use block size and count limits',
                'Create backup before writing to device',
            ],
        })
    
    async def extract_rules(self, command_history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract safety rules from command history"""
        # Analyze failed commands
        incidents = self._analyze_failures(command_history)
        self.incidents.extend(incidents)
        
        # Learn patterns from incidents
        learned_rules = await self._learn_from_incidents(incidents)
        
        # Analyze risky but successful commands
        risky_patterns = self._analyze_risky_successes(command_history)
        
        # Generate safety rules
        safety_rules = self._generate_safety_rules(learned_rules, risky_patterns)
        
        return safety_rules
    
    def _analyze_failures(self, command_history: List[Dict[str, Any]]) -> List[SafetyIncident]:
        """Analyze failed commands for safety issues"""
        incidents = []
        
        for entry in command_history:
            if not entry.get('success', True) or entry.get('exit_code', 0) != 0:
                incident = self._create_incident(entry)
                if incident:
                    incidents.append(incident)
        
        return incidents
    
    def _create_incident(self, entry: Dict[str, Any]) -> Optional[SafetyIncident]:
        """Create safety incident from failed command"""
        command = entry.get('command', '')
        error = entry.get('error', '')
        
        # Classify error type
        error_type = self._classify_error(error)
        if not error_type:
            return None
        
        # Determine severity
        severity = self._determine_severity(command, error_type)
        
        return SafetyIncident(
            command=command,
            error_type=error_type,
            error_message=error,
            severity=severity,
            timestamp=datetime.fromtimestamp(entry.get('timestamp', 0)),
            context=entry.get('context', {})
        )
    
    def _classify_error(self, error: str) -> str:
        """Classify error type"""
        error_lower = error.lower()
        
        if 'permission denied' in error_lower:
            return 'permission_error'
        elif 'no such file' in error_lower:
            return 'file_not_found'
        elif 'command not found' in error_lower:
            return 'command_not_found'
        elif 'no space left' in error_lower:
            return 'disk_full'
        elif 'cannot remove' in error_lower:
            return 'removal_error'
        elif 'is a directory' in error_lower:
            return 'directory_error'
        elif 'resource busy' in error_lower:
            return 'resource_busy'
        elif 'broken pipe' in error_lower:
            return 'pipe_error'
        elif 'segmentation fault' in error_lower:
            return 'segfault'
        else:
            return 'unknown_error'
    
    def _determine_severity(self, command: str, error_type: str) -> str:
        """Determine incident severity"""
        # Critical severity for system-damaging operations
        if any(pattern in command for pattern in ['rm -rf /', 'dd of=/dev/', 'mkfs']):
            return 'critical'
        
        # High severity for permission and removal errors
        if error_type in ['permission_error', 'removal_error']:
            if any(path in command for path in ['/etc', '/usr', '/bin', '/lib']):
                return 'high'
        
        # Medium severity for common errors
        if error_type in ['file_not_found', 'directory_error', 'resource_busy']:
            return 'medium'
        
        # Low severity for benign errors
        return 'low'
    
    async def _learn_from_incidents(self, incidents: List[SafetyIncident]) -> List[LearnedSafetyRule]:
        """Learn safety patterns from incidents"""
        learned_rules = []
        
        # Group incidents by pattern
        pattern_incidents = defaultdict(list)
        
        for incident in incidents:
            # Extract command pattern
            pattern = self._extract_command_pattern(incident.command)
            pattern_incidents[pattern].append(incident)
        
        # Create rules for repeated patterns
        for pattern, incidents_list in pattern_incidents.items():
            if len(incidents_list) >= 2:  # Pattern appears multiple times
                rule = self._create_safety_rule(pattern, incidents_list)
                learned_rules.append(rule)
                self.safety_rules[rule.rule_id] = rule
        
        return learned_rules
    
    def _extract_command_pattern(self, command: str) -> str:
        """Extract generalizable pattern from command"""
        # Remove specific paths and filenames
        pattern = re.sub(r'/[^\s]+', '/PATH', command)
        
        # Remove specific numbers
        pattern = re.sub(r'\b\d+\b', 'NUM', pattern)
        
        # Remove quoted strings
        pattern = re.sub(r"'[^']*'", "'STRING'", pattern)
        pattern = re.sub(r'"[^"]*"', '"STRING"', pattern)
        
        # Normalize whitespace
        pattern = ' '.join(pattern.split())
        
        return pattern
    
    def _create_safety_rule(self, pattern: str, incidents: List[SafetyIncident]) -> LearnedSafetyRule:
        """Create safety rule from incidents"""
        # Determine risk level based on severity
        severities = [inc.severity for inc in incidents]
        if 'critical' in severities:
            risk_level = 'critical'
        elif 'high' in severities:
            risk_level = 'high'
        elif 'medium' in severities:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        # Generate mitigations
        mitigations = self._generate_mitigations(pattern, incidents)
        
        # Calculate confidence
        confidence = min(len(incidents) / 10.0, 1.0)  # More incidents = higher confidence
        
        return LearnedSafetyRule(
            rule_id=f"learned_{hashlib.md5(pattern.encode()).hexdigest()[:8]}",
            pattern=pattern,
            risk_level=risk_level,
            mitigations=mitigations,
            learned_from=incidents,
            confidence=confidence
        )
    
    def _generate_mitigations(self, pattern: str, incidents: List[SafetyIncident]) -> List[str]:
        """Generate mitigation strategies"""
        mitigations = []
        
        # Check for known mitigation patterns
        if 'rm' in pattern:
            mitigations.extend(self.mitigation_strategies['rm_root'])
        elif 'chmod' in pattern:
            mitigations.extend(self.mitigation_strategies['chmod_777'])
        elif 'curl' in pattern or 'wget' in pattern:
            mitigations.extend(self.mitigation_strategies['curl_pipe'])
        elif 'dd' in pattern:
            mitigations.extend(self.mitigation_strategies['dd_device'])
        
        # Generate specific mitigations based on errors
        error_types = set(inc.error_type for inc in incidents)
        
        if 'permission_error' in error_types:
            mitigations.append('Check file permissions before operation')
            mitigations.append('Consider using sudo if appropriate')
        
        if 'file_not_found' in error_types:
            mitigations.append('Verify file/directory exists before operation')
            mitigations.append('Use conditional execution: [ -f file ] && command')
        
        if 'disk_full' in error_types:
            mitigations.append('Check available disk space before operation')
            mitigations.append('Clean up temporary files regularly')
        
        return list(set(mitigations))  # Remove duplicates
    
    def _analyze_risky_successes(self, command_history: List[Dict[str, Any]]) -> List[str]:
        """Analyze successful but potentially risky commands"""
        risky_patterns = []
        
        for entry in command_history:
            if entry.get('success', False):
                command = entry.get('command', '')
                
                # Check against known dangerous patterns
                for pattern in self.dangerous_patterns:
                    if re.search(pattern, command):
                        risky_patterns.append(command)
                        break
                
                # Check for sudo usage
                if command.startswith('sudo') or 'sudo ' in command:
                    risky_patterns.append(command)
                
                # Check for system modification commands
                system_commands = ['systemctl', 'service', 'mount', 'umount', 
                                 'iptables', 'useradd', 'groupadd']
                if any(cmd in command for cmd in system_commands):
                    risky_patterns.append(command)
        
        return risky_patterns
    
    def _generate_safety_rules(self, learned_rules: List[LearnedSafetyRule], 
                              risky_patterns: List[str]) -> List[Dict[str, Any]]:
        """Generate final safety rules"""
        safety_rules = []
        
        # Add learned rules
        for rule in learned_rules:
            safety_rules.append({
                'pattern': rule.pattern,
                'risk_level': rule.risk_level,
                'mitigations': rule.mitigations,
                'learned_from': [inc.command for inc in rule.learned_from][:3],  # Sample
                'confidence': rule.confidence,
            })
        
        # Add rules for risky patterns
        risky_counter = Counter(self._extract_command_pattern(cmd) for cmd in risky_patterns)
        
        for pattern, count in risky_counter.most_common(10):
            if count >= 2:  # Pattern appears multiple times
                safety_rules.append({
                    'pattern': pattern,
                    'risk_level': 'medium',
                    'mitigations': ['Review command carefully before execution',
                                  'Consider running in test environment first'],
                    'learned_from': [],
                    'confidence': 0.5,
                })
        
        return safety_rules
    
    def make_safe(self, commands: List[str]) -> List[str]:
        """Add safety checks to commands"""
        safe_commands = []
        
        for command in commands:
            safe_cmd = self._add_safety_checks(command)
            safe_commands.append(safe_cmd)
        
        return safe_commands
    
    def _add_safety_checks(self, command: str) -> str:
        """Add safety checks to a single command"""
        # Check if command matches dangerous patterns
        for pattern in self.dangerous_patterns:
            if re.search(pattern, command):
                # Add confirmation prompt
                return f'read -p "WARNING: This command is potentially dangerous. Continue? (y/N) " -n 1 -r; echo; [[ $REPLY =~ ^[Yy]$ ]] && {command}'
        
        # Add existence checks for file operations
        if any(cmd in command for cmd in ['rm', 'mv', 'cp']):
            # Extract filename (simple heuristic)
            parts = command.split()
            if len(parts) >= 2:
                target = parts[-1]
                if not target.startswith('-'):
                    return f'[ -e {target} ] && {command} || echo "Target does not exist: {target}"'
        
        # Add dry-run for mass operations
        if 'find' in command and any(op in command for op in ['-delete', '-exec rm']):
            # Suggest dry-run first
            dry_run = command.replace('-delete', '-print').replace('-exec rm', '-exec echo')
            return f'# Dry run: {dry_run}\n{command}'
        
        # Add safety flags
        if 'rm ' in command and '-i' not in command and '-f' not in command:
            command = command.replace('rm ', 'rm -i ')
        
        if 'cp ' in command and '-i' not in command:
            command = command.replace('cp ', 'cp -i ')
        
        if 'mv ' in command and '-i' not in command:
            command = command.replace('mv ', 'mv -i ')
        
        return command
    
    def assess_risk(self, command: str) -> Dict[str, Any]:
        """Assess risk level of a command"""
        risk_score = 0
        risk_factors = []
        
        # Check against dangerous patterns
        for pattern in self.dangerous_patterns:
            if re.search(pattern, command):
                risk_score += 10
                risk_factors.append(f"Matches dangerous pattern: {pattern}")
        
        # Check for sudo
        if 'sudo' in command:
            risk_score += 5
            risk_factors.append("Elevated privileges required")
        
        # Check for system paths
        system_paths = ['/etc', '/usr', '/bin', '/lib', '/boot', '/dev']
        for path in system_paths:
            if path in command:
                risk_score += 3
                risk_factors.append(f"Operates on system path: {path}")
        
        # Check for wildcards in dangerous contexts
        if '*' in command and any(cmd in command for cmd in ['rm', 'mv', 'chmod']):
            risk_score += 4
            risk_factors.append("Wildcard with potentially destructive command")
        
        # Check for output redirection to important files
        if '>' in command and any(path in command for path in ['/etc', '.conf', '.cfg']):
            risk_score += 3
            risk_factors.append("Output redirection to configuration file")
        
        # Determine risk level
        if risk_score >= 10:
            risk_level = 'high'
        elif risk_score >= 5:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return {
            'risk_level': risk_level,
            'risk_score': risk_score,
            'risk_factors': risk_factors,
            'mitigations': self._suggest_mitigations(risk_factors),
        }
    
    def _suggest_mitigations(self, risk_factors: List[str]) -> List[str]:
        """Suggest mitigations based on risk factors"""
        mitigations = []
        
        for factor in risk_factors:
            if 'dangerous pattern' in factor:
                mitigations.append("Review command carefully before execution")
            elif 'Elevated privileges' in factor:
                mitigations.append("Ensure sudo is necessary for this operation")
            elif 'system path' in factor:
                mitigations.append("Create backup before modifying system files")
            elif 'Wildcard' in factor:
                mitigations.append("Test wildcard expansion with echo first")
            elif 'Output redirection' in factor:
                mitigations.append("Backup target file before overwriting")
        
        return list(set(mitigations))  # Remove duplicates