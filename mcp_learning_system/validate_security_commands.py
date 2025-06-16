#!/usr/bin/env python3
"""
Validation script for security monitoring commands
Tests command structure, safety, and integration readiness
"""

import json
import re
import subprocess
from datetime import datetime
from typing import Dict, List, Any, Tuple
from security_monitoring_expansion import SecurityMonitoringExpansion


class SecurityCommandValidator:
    """Validate security monitoring commands for production use"""
    
    def __init__(self):
        self.expansion = SecurityMonitoringExpansion()
        self.commands = self.expansion.get_all_security_commands()
        self.validation_results = {
            "timestamp": datetime.now().isoformat(),
            "total_commands": len(self.commands),
            "passed": 0,
            "failed": 0,
            "warnings": 0,
            "details": {}
        }
    
    def validate_command_structure(self) -> Dict[str, List[str]]:
        """Validate each command has required fields"""
        print("Validating command structure...")
        
        required_fields = ['id', 'name', 'description', 'command_template', 
                         'category', 'subcategory']
        optional_fields = ['examples', 'performance_hints', 'tags']
        
        errors = []
        warnings = []
        
        for i, cmd in enumerate(self.commands):
            cmd_id = cmd.get('id', f'unknown_{i}')
            
            # Check required fields
            for field in required_fields:
                if field not in cmd:
                    errors.append(f"Command {cmd_id} missing required field: {field}")
            
            # Validate field content
            if 'id' in cmd and not re.match(r'^sec_[a-z]+_[a-z_]+$', cmd['id']):
                warnings.append(f"Command {cmd_id} has non-standard ID format")
            
            if 'category' in cmd and cmd['category'] != 'security_monitoring':
                errors.append(f"Command {cmd_id} has wrong category: {cmd['category']}")
            
            if 'subcategory' in cmd:
                valid_subcats = ['network_security', 'system_security', 
                               'vulnerability_assessment', 'incident_response',
                               'compliance_auditing', 'threat_intelligence']
                if cmd['subcategory'] not in valid_subcats:
                    errors.append(f"Command {cmd_id} has invalid subcategory: {cmd['subcategory']}")
            
            # Check command template safety
            if 'command_template' in cmd:
                dangerous_patterns = [
                    r'rm\s+-rf\s+/',
                    r'dd\s+if=/dev/zero\s+of=/',
                    r'>\s*/dev/sd[a-z]',
                    r'mkfs\.',
                    r'format\s+[cC]:',
                ]
                
                for pattern in dangerous_patterns:
                    if re.search(pattern, cmd['command_template']):
                        warnings.append(f"Command {cmd_id} contains potentially dangerous pattern: {pattern}")
        
        return {"errors": errors, "warnings": warnings}
    
    def validate_command_safety(self) -> Dict[str, List[str]]:
        """Validate commands for safety in production"""
        print("Validating command safety...")
        
        safety_issues = []
        
        for cmd in self.commands:
            cmd_id = cmd.get('id', 'unknown')
            template = cmd.get('command_template', '')
            
            # Check for unsafe operations
            if 'sudo' in template and 'NOPASSWD' in template:
                safety_issues.append(f"{cmd_id}: Uses passwordless sudo")
            
            if re.search(r'\$\(.*\)', template) and 'eval' in template:
                safety_issues.append(f"{cmd_id}: Uses eval with command substitution")
            
            if re.search(r'curl.*\|.*sh', template):
                safety_issues.append(f"{cmd_id}: Pipes curl output to shell")
            
            if '{' in template and '}' in template:
                # Check for proper parameter validation
                params = re.findall(r'\{(\w+)\}', template)
                if len(params) > 3:
                    safety_issues.append(f"{cmd_id}: Too many parameters ({len(params)})")
        
        return {"safety_issues": safety_issues}
    
    def validate_command_dependencies(self) -> Dict[str, List[str]]:
        """Check for command dependencies"""
        print("Checking command dependencies...")
        
        common_tools = {
            'nmap': 'network scanning',
            'tcpdump': 'packet capture',
            'iptables': 'firewall management',
            'aide': 'file integrity',
            'auditd': 'system auditing',
            'snort': 'intrusion detection',
            'clamscan': 'malware scanning',
            'lynis': 'security auditing',
            'openvas': 'vulnerability scanning',
            'metasploit': 'penetration testing'
        }
        
        dependencies = {}
        
        for cmd in self.commands:
            cmd_id = cmd.get('id', 'unknown')
            template = cmd.get('command_template', '')
            
            cmd_deps = []
            for tool, purpose in common_tools.items():
                if tool in template:
                    cmd_deps.append(f"{tool} ({purpose})")
            
            if cmd_deps:
                dependencies[cmd_id] = cmd_deps
        
        return {"dependencies": dependencies}
    
    def test_command_syntax(self) -> Dict[str, List[str]]:
        """Test command syntax (dry run)"""
        print("Testing command syntax...")
        
        syntax_errors = []
        
        for cmd in self.commands[:10]:  # Test first 10 commands
            cmd_id = cmd.get('id', 'unknown')
            template = cmd.get('command_template', '')
            
            # Replace parameters with safe values
            safe_template = template
            safe_template = re.sub(r'\{target\}', '127.0.0.1', safe_template)
            safe_template = re.sub(r'\{port\}', '80', safe_template)
            safe_template = re.sub(r'\{interface\}', 'lo', safe_template)
            safe_template = re.sub(r'\{.*?\}', 'test', safe_template)
            
            # Test with bash -n (syntax check only)
            try:
                result = subprocess.run(
                    ['bash', '-n'],
                    input=safe_template,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode != 0:
                    syntax_errors.append(f"{cmd_id}: {result.stderr.strip()}")
            
            except Exception as e:
                syntax_errors.append(f"{cmd_id}: {str(e)}")
        
        return {"syntax_errors": syntax_errors}
    
    def generate_validation_report(self) -> None:
        """Generate comprehensive validation report"""
        print("\nRunning comprehensive validation...")
        
        # Structure validation
        structure_results = self.validate_command_structure()
        self.validation_results["structure_errors"] = len(structure_results["errors"])
        self.validation_results["structure_warnings"] = len(structure_results["warnings"])
        self.validation_results["details"]["structure"] = structure_results
        
        # Safety validation
        safety_results = self.validate_command_safety()
        self.validation_results["safety_issues"] = len(safety_results["safety_issues"])
        self.validation_results["details"]["safety"] = safety_results
        
        # Dependency check
        dependency_results = self.validate_command_dependencies()
        self.validation_results["total_dependencies"] = len(dependency_results["dependencies"])
        self.validation_results["details"]["dependencies"] = dependency_results
        
        # Syntax validation
        syntax_results = self.test_command_syntax()
        self.validation_results["syntax_errors"] = len(syntax_results["syntax_errors"])
        self.validation_results["details"]["syntax"] = syntax_results
        
        # Calculate totals
        self.validation_results["failed"] = (
            self.validation_results["structure_errors"] +
            self.validation_results["syntax_errors"]
        )
        self.validation_results["warnings"] = (
            self.validation_results["structure_warnings"] +
            self.validation_results["safety_issues"]
        )
        self.validation_results["passed"] = (
            self.validation_results["total_commands"] - 
            self.validation_results["failed"]
        )
        
        # Command statistics
        subcategory_stats = {}
        for cmd in self.commands:
            subcat = cmd.get('subcategory', 'unknown')
            subcategory_stats[subcat] = subcategory_stats.get(subcat, 0) + 1
        
        self.validation_results["subcategory_distribution"] = subcategory_stats
        
        # Write report
        report_file = "security_commands_validation_report.json"
        with open(report_file, 'w') as f:
            json.dump(self.validation_results, f, indent=2)
        
        print(f"\nValidation report saved to: {report_file}")
        
        # Print summary
        self.print_summary()
    
    def print_summary(self) -> None:
        """Print validation summary"""
        print("\n" + "=" * 60)
        print("SECURITY COMMAND VALIDATION SUMMARY")
        print("=" * 60)
        
        print(f"\nTotal Commands: {self.validation_results['total_commands']}")
        print(f"✅ Passed: {self.validation_results['passed']}")
        print(f"❌ Failed: {self.validation_results['failed']}")
        print(f"⚠️  Warnings: {self.validation_results['warnings']}")
        
        print("\nSubcategory Distribution:")
        for subcat, count in self.validation_results["subcategory_distribution"].items():
            print(f"  {subcat}: {count} commands")
        
        if self.validation_results["structure_errors"] > 0:
            print(f"\n❌ Structure Errors: {self.validation_results['structure_errors']}")
            for error in self.validation_results["details"]["structure"]["errors"][:5]:
                print(f"   - {error}")
        
        if self.validation_results["safety_issues"] > 0:
            print(f"\n⚠️  Safety Issues: {self.validation_results['safety_issues']}")
            for issue in self.validation_results["details"]["safety"]["safety_issues"][:5]:
                print(f"   - {issue}")
        
        print("\n📦 Top Dependencies:")
        deps = self.validation_results["details"]["dependencies"]["dependencies"]
        for cmd_id, cmd_deps in list(deps.items())[:5]:
            print(f"   {cmd_id}: {', '.join(cmd_deps)}")
        
        # Overall assessment
        print("\n" + "=" * 60)
        if self.validation_results["failed"] == 0:
            print("✅ All commands passed validation!")
        else:
            print("❌ Some commands need attention before production use.")
        
        if self.validation_results["warnings"] > 0:
            print("⚠️  Review warnings for potential security concerns.")
        
        print("\nRecommendations:")
        print("1. Install required dependencies for your use cases")
        print("2. Review and adjust command parameters for your environment")
        print("3. Test commands in a safe environment first")
        print("4. Implement proper access controls and logging")
        print("5. Set up monitoring for security command usage")


def main():
    """Run security command validation"""
    validator = SecurityCommandValidator()
    validator.generate_validation_report()


if __name__ == "__main__":
    main()