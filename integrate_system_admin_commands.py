#!/usr/bin/env python3
"""
INTEGRATION SCRIPT - MITIGATION AGENT 3
Integrates 130+ system administration commands into bash_god_mcp_server.py
"""

import json
import re
from pathlib import Path

def load_expansion_commands():
    """Load the expanded system administration commands"""
    with open("system_admin_commands_expansion.json", "r") as f:
        return json.load(f)

def integrate_commands():
    """Integrate new commands into bash_god_mcp_server.py"""
    
    # Read the current server file
    server_path = Path("mcp_learning_system/bash_god_mcp_server.py")
    with open(server_path, "r") as f:
        content = f.read()
    
    # Find the system administration commands section
    # Look for the comment "# SYSTEM ADMINISTRATION (130 commands)"
    pattern = r'(# SYSTEM ADMINISTRATION \(130 commands\)\s*system_admin_commands = \[)(.*?)(\])'
    
    # Load our new commands
    new_commands = load_expansion_commands()
    
    # Format the commands for insertion
    formatted_commands = []
    for cmd in new_commands:
        # Convert enum references back to proper format
        cmd_str = json.dumps(cmd, indent=12)
        cmd_str = cmd_str.replace('"system_administration"', 'CommandCategory.SYSTEM_ADMINISTRATION')
        cmd_str = cmd_str.replace('"safe"', 'SafetyLevel.SAFE')
        cmd_str = cmd_str.replace('"low_risk"', 'SafetyLevel.LOW_RISK')
        cmd_str = cmd_str.replace('"medium_risk"', 'SafetyLevel.MEDIUM_RISK')
        cmd_str = cmd_str.replace('"high_risk"', 'SafetyLevel.HIGH_RISK')
        cmd_str = cmd_str.replace('"critical_risk"', 'SafetyLevel.CRITICAL_RISK')
        formatted_commands.append(cmd_str)
    
    # Join all commands
    commands_str = ",\n            ".join(formatted_commands)
    
    # Replace the old system_admin_commands with our new expanded set
    replacement = f'\\1\n            {commands_str}\n        \\3'
    
    # Perform the replacement
    new_content = re.sub(pattern, replacement, content, flags=re.DOTALL)
    
    # Save backup
    backup_path = server_path.with_suffix('.py.backup')
    with open(backup_path, "w") as f:
        f.write(content)
    
    # Write updated content
    with open(server_path, "w") as f:
        f.write(new_content)
    
    print(f"✓ Backup saved to: {backup_path}")
    print(f"✓ Updated bash god server with 130+ system administration commands")
    print(f"✓ Integration complete!")
    
    # Verify the update
    verify_integration()

def verify_integration():
    """Verify the integration was successful"""
    server_path = Path("mcp_learning_system/bash_god_mcp_server.py")
    with open(server_path, "r") as f:
        content = f.read()
    
    # Count occurrences of system administration command IDs
    command_ids = [
        "sys_cpu_freq_scaling",
        "sys_mem_hugepages", 
        "sys_proc_nice_batch",
        "sys_mon_cpu_frequency",
        "sys_hw_pci_rescan",
        "sys_cfg_kernel_params"
    ]
    
    found = 0
    for cmd_id in command_ids:
        if f'"{cmd_id}"' in content:
            found += 1
    
    print(f"\n✓ Verification: Found {found}/{len(command_ids)} sample commands")
    
    # Count total sys_ commands
    sys_cmd_count = len(re.findall(r'"sys_[^"]+",', content))
    print(f"✓ Total system administration commands found: {sys_cmd_count}")

if __name__ == "__main__":
    print("BASH GOD SYSTEM ADMINISTRATION INTEGRATION")
    print("=" * 60)
    
    try:
        integrate_commands()
    except Exception as e:
        print(f"❌ Integration failed: {e}")
        print("Please check the file paths and format")