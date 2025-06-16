#!/usr/bin/env python3
"""
Integration script to add security monitoring commands to bash god MCP server
"""

import json
import sys
from datetime import datetime
from security_monitoring_expansion import SecurityMonitoringExpansion


def integrate_security_commands():
    """Integrate security monitoring commands into bash god server"""
    
    print("Security Monitoring Command Integration")
    print("=" * 50)
    
    # Get all security commands
    expansion = SecurityMonitoringExpansion()
    security_commands = expansion.get_all_security_commands()
    
    print(f"\nTotal commands to integrate: {len(security_commands)}")
    
    # Group by subcategory for reporting
    subcategories = {}
    for cmd in security_commands:
        subcat = cmd.get('subcategory', 'unknown')
        if subcat not in subcategories:
            subcategories[subcat] = []
        subcategories[subcat].append(cmd)
    
    # Display breakdown
    print("\nCommand breakdown by subcategory:")
    for subcat, cmds in sorted(subcategories.items()):
        print(f"  {subcat}: {len(cmds)} commands")
    
    # Create integration module
    integration_code = '''#!/usr/bin/env python3
"""
Security Monitoring Commands for Bash God MCP Server
Auto-generated integration module with 115+ security commands
Generated: {timestamp}
"""

from typing import List, Dict, Any


class SecurityMonitoringCommands:
    """Security monitoring command definitions for bash god"""
    
    @staticmethod
    def get_commands() -> List[Dict[str, Any]]:
        """Get all security monitoring commands"""
        return {commands}
    
    @staticmethod
    def get_command_count() -> Dict[str, int]:
        """Get command count by subcategory"""
        return {subcategory_counts}
    
    @staticmethod
    def validate_commands() -> bool:
        """Validate all commands have required fields"""
        required_fields = ['id', 'name', 'description', 'command_template', 'category']
        commands = SecurityMonitoringCommands.get_commands()
        
        for cmd in commands:
            for field in required_fields:
                if field not in cmd:
                    print(f"Command {{cmd.get('id', 'unknown')}} missing field: {{field}}")
                    return False
        
        return True


# Export commands for direct import
SECURITY_MONITORING_COMMANDS = SecurityMonitoringCommands.get_commands()
'''.format(
        timestamp=datetime.now().isoformat(),
        commands=json.dumps(security_commands, indent=4),
        subcategory_counts=json.dumps({k: len(v) for k, v in subcategories.items()})
    )
    
    # Write integration module
    integration_file = "bash_god_security_commands.py"
    with open(integration_file, 'w') as f:
        f.write(integration_code)
    
    print(f"\nIntegration module created: {integration_file}")
    
    # Create validation report
    validation_report = {
        "timestamp": datetime.now().isoformat(),
        "total_commands": len(security_commands),
        "subcategories": {k: len(v) for k, v in subcategories.items()},
        "command_samples": [],
        "validation_status": "pending"
    }
    
    # Add sample commands from each category
    for subcat, cmds in subcategories.items():
        if cmds:
            sample = cmds[0]
            validation_report["command_samples"].append({
                "subcategory": subcat,
                "id": sample["id"],
                "name": sample["name"],
                "template": sample["command_template"]
            })
    
    # Write validation report
    report_file = "security_commands_integration_report.json"
    with open(report_file, 'w') as f:
        json.dump(validation_report, f, indent=2)
    
    print(f"Validation report created: {report_file}")
    
    # Create integration instructions
    instructions = '''# Security Monitoring Commands Integration Instructions

## Overview
This integration adds 115+ real security monitoring commands to the bash god MCP server.

## Integration Steps

1. **Import the commands in bash_god_mcp_server.py:**
   ```python
   from bash_god_security_commands import SECURITY_MONITORING_COMMANDS
   ```

2. **Add to the command library in the appropriate section:**
   ```python
   # In the command initialization section
   for cmd in SECURITY_MONITORING_COMMANDS:
       self.commands[cmd['id']] = cmd
   ```

3. **Update category counts:**
   The security_monitoring category now has 115+ commands across 6 subcategories:
   - network_security: 25 commands
   - system_security: 25 commands
   - vulnerability_assessment: 20 commands
   - incident_response: 20 commands
   - compliance_auditing: 15 commands
   - threat_intelligence: 10 commands

## Command Structure
Each command includes:
- `id`: Unique identifier
- `name`: Human-readable name
- `description`: What the command does
- `command_template`: The actual command to execute
- `examples`: Usage examples
- `performance_hints`: Optimization tips
- `category`: Always "security_monitoring"
- `subcategory`: Specific security domain
- `tags`: Optional categorization tags

## Testing
Run the validation script to ensure all commands are properly formatted:
```bash
python3 validate_security_commands.py
```

## Security Considerations
- These are real security commands, not simulations
- Many require elevated privileges (sudo/root)
- Some commands can impact system performance
- Always test in a safe environment first
- Follow organizational security policies

## Production Deployment
1. Review all commands for your environment
2. Adjust paths and parameters as needed
3. Set up proper logging and monitoring
4. Configure rate limiting for sensitive operations
5. Implement access controls based on user roles

Generated: {timestamp}
'''
    
    instructions_file = "SECURITY_COMMANDS_INTEGRATION.md"
    with open(instructions_file, 'w') as f:
        f.write(instructions.format(timestamp=datetime.now().isoformat()))
    
    print(f"Integration instructions created: {instructions_file}")
    
    print("\n✅ Security command integration complete!")
    print("\nNext steps:")
    print("1. Review the generated files")
    print("2. Run validation tests")
    print("3. Integrate into bash_god_mcp_server.py")
    print("4. Test in development environment")
    print("5. Deploy to production with proper safeguards")


if __name__ == "__main__":
    integrate_security_commands()