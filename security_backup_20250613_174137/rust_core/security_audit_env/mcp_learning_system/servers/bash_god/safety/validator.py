"""BASH_GOD Safety Validator - Advanced safety checking and validation"""

import re
import os
import subprocess
from typing import Dict, List, Any, Tuple, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
import hashlib
from pathlib import Path


class RiskLevel(Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ValidationResult(Enum):
    APPROVED = "approved"
    WARNING = "warning"
    BLOCKED = "blocked"
    REQUIRES_CONFIRMATION = "requires_confirmation"


@dataclass
class SafetyRule:
    """Represents a safety validation rule"""
    rule_id: str
    name: str
    pattern: str
    risk_level: RiskLevel
    description: str
    mitigations: List[str]
    auto_fix: Optional[str] = None
    

@dataclass
class ValidationReport:
    """Result of safety validation"""
    result: ValidationResult
    risk_level: RiskLevel
    violations: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    suggested_command: Optional[str] = None
    confidence: float = 1.0
    

class BashSafetyValidator:
    """Advanced safety validator for bash commands"""
    
    def __init__(self):
        self.safety_rules: List[SafetyRule] = []
        self.protected_paths: Set[str] = set()
        self.dangerous_commands: Set[str] = set()
        self.user_whitelist: Set[str] = set()
        
        self._initialize_rules()
        self._initialize_protected_paths()
        self._initialize_dangerous_commands()
    
    def _initialize_rules(self):
        """Initialize built-in safety rules"""
        
        # CRITICAL RULES
        self.safety_rules.extend([
            SafetyRule(
                rule_id="CRIT001",
                name="Root Directory Deletion",
                pattern=r"rm\s+(-[rf]*r[rf]*|--recursive)\s+(-[rf]*f[rf]*|--force)?\s*/\s*$",
                risk_level=RiskLevel.CRITICAL,
                description="Attempting to delete root directory",
                mitigations=[
                    "NEVER delete the root directory",
                    "Use --preserve-root flag with rm",
                    "Specify exact paths instead of wildcards"
                ]
            ),
            SafetyRule(
                rule_id="CRIT002",
                name="Fork Bomb",
                pattern=r":\(\)\s*\{\s*:\|:&\s*\};?\s*:",
                risk_level=RiskLevel.CRITICAL,
                description="Fork bomb pattern detected",
                mitigations=[
                    "This command will crash the system",
                    "Do not execute under any circumstances"
                ]
            ),
            SafetyRule(
                rule_id="CRIT003",
                name="Block Device Overwrite",
                pattern=r"(dd|cat|echo)\s+.*>\s*/dev/[sh]d[a-z]",
                risk_level=RiskLevel.CRITICAL,
                description="Writing directly to block device",
                mitigations=[
                    "This will destroy all data on the device",
                    "Double-check device path",
                    "Use appropriate partitioning tools instead"
                ]
            ),
            SafetyRule(
                rule_id="CRIT004",
                name="Filesystem Creation",
                pattern=r"mkfs\.",
                risk_level=RiskLevel.CRITICAL,
                description="Creating filesystem will destroy all data",
                mitigations=[
                    "This will permanently erase all data",
                    "Ensure this is the correct device",
                    "Create backup before proceeding"
                ]
            )
        ])
        
        # HIGH RISK RULES
        self.safety_rules.extend([
            SafetyRule(
                rule_id="HIGH001",
                name="Permissive Permissions",
                pattern=r"chmod\s+(777|666|o\+w)",
                risk_level=RiskLevel.HIGH,
                description="Setting overly permissive file permissions",
                mitigations=[
                    "Use more restrictive permissions (755, 644)",
                    "Only grant necessary permissions",
                    "Consider using ACLs for fine-grained control"
                ],
                auto_fix="chmod 755"
            ),
            SafetyRule(
                rule_id="HIGH002",
                name="Curl Pipe Shell",
                pattern=r"curl\s+.*\|\s*(sudo\s+)?(sh|bash)",
                risk_level=RiskLevel.HIGH,
                description="Piping curl output directly to shell",
                mitigations=[
                    "Download script first and review it",
                    "Verify source trustworthiness",
                    "Run in isolated environment"
                ]
            ),
            SafetyRule(
                rule_id="HIGH003",
                name="Mass File Deletion",
                pattern=r"rm\s+-rf?\s+\*",
                risk_level=RiskLevel.HIGH,
                description="Deleting all files with wildcard",
                mitigations=[
                    "Specify exact files/patterns",
                    "Test with 'ls' first",
                    "Use interactive mode (-i flag)"
                ],
                auto_fix="rm -i"
            ),
            SafetyRule(
                rule_id="HIGH004",
                name="System Directory Operations",
                pattern=r"(rm|mv|chmod|chown)\s+.*/(bin|boot|dev|etc|lib|proc|root|sbin|sys|usr)",
                risk_level=RiskLevel.HIGH,
                description="Modifying critical system directories",
                mitigations=[
                    "System directories are critical for OS function",
                    "Use package manager for system changes",
                    "Create backup before modifying"
                ]
            )
        ])
        
        # MEDIUM RISK RULES
        self.safety_rules.extend([
            SafetyRule(
                rule_id="MED001",
                name="Sudo Usage",
                pattern=r"sudo\s+",
                risk_level=RiskLevel.MEDIUM,
                description="Using elevated privileges",
                mitigations=[
                    "Ensure sudo is necessary",
                    "Use principle of least privilege",
                    "Consider using specific sudo rules"
                ]
            ),
            SafetyRule(
                rule_id="MED002",
                name="File Truncation",
                pattern=r">\s*/\w+",
                risk_level=RiskLevel.MEDIUM,
                description="Truncating file with output redirection",
                mitigations=[
                    "This will overwrite the entire file",
                    "Use >> for appending instead",
                    "Create backup before truncating"
                ]
            ),
            SafetyRule(
                rule_id="MED003",
                name="Process Killing",
                pattern=r"(kill|killall|pkill)\s+(-9\s+|-KILL\s+)",
                risk_level=RiskLevel.MEDIUM,
                description="Force killing processes",
                mitigations=[
                    "Try graceful termination first (TERM signal)",
                    "Allow processes to clean up properly",
                    "Use KILL only as last resort"
                ],
                auto_fix="kill -TERM"
            ),
            SafetyRule(
                rule_id="MED004",
                name="Network Downloads",
                pattern=r"(wget|curl)\s+.*https?://",
                risk_level=RiskLevel.MEDIUM,
                description="Downloading files from internet",
                mitigations=[
                    "Verify URL trustworthiness",
                    "Check downloaded files for malware",
                    "Use secure connections (HTTPS)"
                ]
            )
        ])
        
        # LOW RISK RULES
        self.safety_rules.extend([
            SafetyRule(
                rule_id="LOW001",
                name="Missing Error Handling",
                pattern=r"^[^|;&]*\|\s*[^|;&]*$",
                risk_level=RiskLevel.LOW,
                description="Pipeline without error handling",
                mitigations=[
                    "Consider using 'set -e' for error handling",
                    "Add '|| exit 1' for critical commands",
                    "Use 'set -o pipefail' for pipeline errors"
                ]
            ),
            SafetyRule(
                rule_id="LOW002",
                name="Unquoted Variables",
                pattern=r"\$\w+(?![\"'])",
                risk_level=RiskLevel.LOW,
                description="Unquoted variable expansion",
                mitigations=[
                    "Quote variables to prevent word splitting",
                    "Use \"$var\" instead of $var",
                    "Consider ${var} for clarity"
                ]
            )
        ])
    
    def _initialize_protected_paths(self):
        """Initialize protected system paths"""
        self.protected_paths.update([
            "/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64",
            "/proc", "/root", "/sbin", "/sys", "/usr", "/var/log",
            "/var/run", "/var/lib", "/opt"
        ])
    
    def _initialize_dangerous_commands(self):
        """Initialize known dangerous commands"""
        self.dangerous_commands.update([
            "dd", "mkfs", "fdisk", "parted", "cfdisk",
            "shred", "wipe", "secure-delete",
            "iptables", "ip6tables", "ufw",
            "systemctl", "service", "init",
            "mount", "umount", "fsck",
            "useradd", "userdel", "usermod",
            "groupadd", "groupdel", "passwd"
        ])
    
    def validate_command(self, command: str, context: Optional[Dict[str, Any]] = None) -> ValidationReport:
        """Validate a bash command for safety"""
        context = context or {}
        
        violations = []
        warnings = []
        mitigations = []
        max_risk = RiskLevel.SAFE
        suggested_fixes = []
        
        # Check against safety rules
        for rule in self.safety_rules:
            if re.search(rule.pattern, command, re.IGNORECASE):
                if rule.risk_level == RiskLevel.CRITICAL:
                    violations.append(f"{rule.name}: {rule.description}")
                    max_risk = RiskLevel.CRITICAL
                elif rule.risk_level == RiskLevel.HIGH:
                    violations.append(f"{rule.name}: {rule.description}")
                    max_risk = max(max_risk, RiskLevel.HIGH)
                elif rule.risk_level == RiskLevel.MEDIUM:
                    warnings.append(f"{rule.name}: {rule.description}")
                    max_risk = max(max_risk, RiskLevel.MEDIUM)
                else:
                    warnings.append(f"{rule.name}: {rule.description}")
                    max_risk = max(max_risk, RiskLevel.LOW)
                
                mitigations.extend(rule.mitigations)
                
                if rule.auto_fix:
                    suggested_fixes.append(rule.auto_fix)
        
        # Additional context-based validation
        context_violations = self._validate_context(command, context)
        violations.extend(context_violations)
        
        # Path validation
        path_warnings = self._validate_paths(command)
        warnings.extend(path_warnings)
        
        # Command existence validation
        existence_warnings = self._validate_command_existence(command)
        warnings.extend(existence_warnings)
        
        # Generate suggested command if fixes available
        suggested_command = None
        if suggested_fixes:
            suggested_command = self._apply_auto_fixes(command, suggested_fixes)
        
        # Determine final result
        if max_risk == RiskLevel.CRITICAL:
            result = ValidationResult.BLOCKED
        elif max_risk == RiskLevel.HIGH:
            result = ValidationResult.REQUIRES_CONFIRMATION
        elif max_risk in [RiskLevel.MEDIUM, RiskLevel.LOW]:
            result = ValidationResult.WARNING
        else:
            result = ValidationResult.APPROVED
        
        return ValidationReport(
            result=result,
            risk_level=max_risk,
            violations=list(set(violations)),
            warnings=list(set(warnings)),
            mitigations=list(set(mitigations)),
            suggested_command=suggested_command,
            confidence=self._calculate_confidence(command, violations, warnings)
        )
    
    def _validate_context(self, command: str, context: Dict[str, Any]) -> List[str]:
        """Validate command against execution context"""
        violations = []
        
        # Check user permissions
        user = context.get('user', 'unknown')
        if user == 'root' and 'rm' in command:
            violations.append("Root user executing deletion command")
        
        # Check working directory
        cwd = context.get('cwd', '/')
        if cwd in self.protected_paths and any(cmd in command for cmd in ['rm', 'mv', 'chmod']):
            violations.append(f"Modifying files in protected directory: {cwd}")
        
        # Check if running in production
        if context.get('environment') == 'production':
            if any(cmd in command for cmd in ['kill', 'restart', 'stop']):
                violations.append("Potentially disruptive command in production environment")
        
        return violations
    
    def _validate_paths(self, command: str) -> List[str]:
        """Validate file paths in command"""
        warnings = []
        
        # Extract potential paths
        path_patterns = [
            r'/[^\s]*',  # Absolute paths
            r'~/[^\s]*',  # Home relative paths
            r'\./[^\s]*',  # Current dir relative paths
        ]
        
        paths = []
        for pattern in path_patterns:
            paths.extend(re.findall(pattern, command))
        
        for path in paths:
            # Clean up path
            clean_path = path.strip('"\'')
            
            # Check if path is protected
            for protected in self.protected_paths:
                if clean_path.startswith(protected):
                    warnings.append(f"Operating on protected path: {clean_path}")
                    break
            
            # Check if path exists (for read operations)
            if any(cmd in command for cmd in ['cat', 'grep', 'awk', 'sed']) and clean_path.startswith('/'):
                if not os.path.exists(clean_path):
                    warnings.append(f"Path may not exist: {clean_path}")
        
        return warnings
    
    def _validate_command_existence(self, command: str) -> List[str]:
        """Validate that commands exist on system"""
        warnings = []
        
        # Extract command names
        cmd_parts = command.split()
        if not cmd_parts:
            return warnings
        
        # Get base command (remove sudo, nice, etc.)
        base_cmd = cmd_parts[0]
        if base_cmd in ['sudo', 'nice', 'nohup', 'timeout']:
            if len(cmd_parts) > 1:
                base_cmd = cmd_parts[1]
        
        # Check if command exists
        try:
            subprocess.run(['which', base_cmd], check=True, 
                         capture_output=True, text=True)
        except subprocess.CalledProcessError:
            warnings.append(f"Command may not be installed: {base_cmd}")
        
        return warnings
    
    def _apply_auto_fixes(self, command: str, fixes: List[str]) -> str:
        """Apply automatic fixes to command"""
        fixed_command = command
        
        for fix in fixes:
            if fix == "chmod 755":
                fixed_command = re.sub(r'chmod\s+777', 'chmod 755', fixed_command)
            elif fix == "rm -i":
                fixed_command = re.sub(r'rm\s+(?!-i)', 'rm -i ', fixed_command)
            elif fix == "kill -TERM":
                fixed_command = re.sub(r'kill\s+-9', 'kill -TERM', fixed_command)
                fixed_command = re.sub(r'kill\s+-KILL', 'kill -TERM', fixed_command)
        
        return fixed_command
    
    def _calculate_confidence(self, command: str, violations: List[str], warnings: List[str]) -> float:
        """Calculate confidence in validation result"""
        base_confidence = 0.9
        
        # Reduce confidence for complex commands
        complexity = len(command.split('|')) + len(command.split('&&')) + len(command.split(';'))
        confidence = base_confidence - (complexity * 0.05)
        
        # Reduce confidence for unknown commands
        if any('may not be installed' in w for w in warnings):
            confidence -= 0.2
        
        # High confidence for clear violations
        if violations:
            confidence = max(confidence, 0.85)
        
        return max(min(confidence, 1.0), 0.0)
    
    def add_custom_rule(self, rule: SafetyRule):
        """Add custom safety rule"""
        self.safety_rules.append(rule)
    
    def whitelist_user(self, username: str):
        """Add user to whitelist (reduced restrictions)"""
        self.user_whitelist.add(username)
    
    def is_whitelisted_user(self, username: str) -> bool:
        """Check if user is whitelisted"""
        return username in self.user_whitelist
    
    def create_safe_wrapper(self, command: str, risk_level: RiskLevel) -> str:
        """Create safe wrapper for risky command"""
        if risk_level == RiskLevel.CRITICAL:
            return f"""echo "CRITICAL: This command is extremely dangerous!"
echo "Command: {command}"
read -p "Type 'I UNDERSTAND THE RISKS' to proceed: " confirmation
if [ "$confirmation" = "I UNDERSTAND THE RISKS" ]; then
    {command}
else
    echo "Command aborted for safety"
fi"""
        
        elif risk_level == RiskLevel.HIGH:
            return f"""echo "WARNING: This command has high risk!"
echo "Command: {command}"
read -p "Continue? (type 'yes' to proceed): " confirmation
if [ "$confirmation" = "yes" ]; then
    {command}
else
    echo "Command aborted"
fi"""
        
        elif risk_level == RiskLevel.MEDIUM:
            return f"""echo "CAUTION: {command}"
read -p "Proceed? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    {command}
fi"""
        
        else:
            return command
    
    def get_safety_report(self) -> Dict[str, Any]:
        """Generate comprehensive safety report"""
        return {
            'total_rules': len(self.safety_rules),
            'rules_by_risk': {
                level.value: len([r for r in self.safety_rules if r.risk_level == level])
                for level in RiskLevel
            },
            'protected_paths': list(self.protected_paths),
            'dangerous_commands': list(self.dangerous_commands),
            'whitelisted_users': list(self.user_whitelist),
        }
    
    def export_rules(self) -> List[Dict[str, Any]]:
        """Export safety rules for external use"""
        return [
            {
                'rule_id': rule.rule_id,
                'name': rule.name,
                'pattern': rule.pattern,
                'risk_level': rule.risk_level.value,
                'description': rule.description,
                'mitigations': rule.mitigations,
                'auto_fix': rule.auto_fix,
            }
            for rule in self.safety_rules
        ]