#!/usr/bin/env python3
"""
PATCH SCRIPT - MITIGATION AGENT 3
Replaces minimal system administration commands with 130+ comprehensive commands
"""

import json
import shutil
from datetime import datetime
from pathlib import Path

# Import the expansion module
from bash_god_system_admin_expansion import generate_system_admin_commands

def create_backup(file_path):
    """Create a timestamped backup of the file"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = file_path.parent / f"{file_path.stem}_backup_{timestamp}{file_path.suffix}"
    shutil.copy2(file_path, backup_path)
    return backup_path

def generate_python_code_for_commands():
    """Generate Python code for the system administration commands"""
    commands = generate_system_admin_commands()
    
    # Start with the section header
    code_lines = ["        # SYSTEM ADMINISTRATION (130 commands)"]
    code_lines.append("        system_admin_commands = [")
    
    for i, cmd in enumerate(commands):
        code_lines.append("            {")
        
        # Add each field with proper formatting
        code_lines.append(f'                "id": "{cmd["id"]}",')
        code_lines.append(f'                "name": "{cmd["name"]}",')
        code_lines.append(f'                "description": "{cmd["description"]}",')
        
        # Escape any quotes in command template
        cmd_template = cmd["command_template"].replace('"', '\\"')
        code_lines.append(f'                "command_template": "{cmd_template}",')
        
        # Category enum
        code_lines.append(f'                "category": CommandCategory.SYSTEM_ADMINISTRATION,')
        
        # Safety level enum
        safety_level = cmd["safety_level"].value
        enum_map = {
            "safe": "SAFE",
            "low_risk": "LOW_RISK", 
            "medium_risk": "MEDIUM_RISK",
            "high_risk": "HIGH_RISK",
            "critical_risk": "CRITICAL_RISK"
        }
        code_lines.append(f'                "safety_level": SafetyLevel.{enum_map[safety_level]},')
        
        # Parameters
        params_str = json.dumps(cmd["parameters"])
        code_lines.append(f'                "parameters": {params_str},')
        
        # Examples
        examples_str = json.dumps(cmd["examples"])
        code_lines.append(f'                "examples": {examples_str},')
        
        # Performance hints
        hints_str = json.dumps(cmd["performance_hints"])
        code_lines.append(f'                "performance_hints": {hints_str},')
        
        # Dependencies
        deps_str = json.dumps(cmd["dependencies"])
        code_lines.append(f'                "dependencies": {deps_str},')
        
        # Optional fields
        if cmd.get("amd_ryzen_optimized", False):
            code_lines.append(f'                "amd_ryzen_optimized": True,')
        
        if cmd.get("parallel_execution", False):
            code_lines.append(f'                "parallel_execution": True,')
            
        if cmd.get("estimated_duration", 0.0) > 0:
            code_lines.append(f'                "estimated_duration": {cmd["estimated_duration"]},')
            
        if cmd.get("memory_requirement", 0) > 0:
            code_lines.append(f'                "memory_requirement": {cmd["memory_requirement"]},')
            
        if cmd.get("cpu_cores", 1) > 1:
            code_lines.append(f'                "cpu_cores": {cmd["cpu_cores"]}')
        else:
            # Remove trailing comma from last line
            code_lines[-1] = code_lines[-1].rstrip(',')
        
        if i < len(commands) - 1:
            code_lines.append("            },")
        else:
            code_lines.append("            }")
    
    code_lines.append("        ]")
    
    return "\n".join(code_lines)

def patch_bash_god_server():
    """Patch the bash god server with new system administration commands"""
    
    server_path = Path("mcp_learning_system/bash_god_mcp_server.py")
    
    # Create backup
    print(f"Creating backup...")
    backup_path = create_backup(server_path)
    print(f"✓ Backup created: {backup_path}")
    
    # Read the current file
    with open(server_path, "r") as f:
        lines = f.readlines()
    
    # Find the start and end of system_admin_commands
    start_idx = None
    end_idx = None
    
    for i, line in enumerate(lines):
        if "# SYSTEM ADMINISTRATION (130 commands)" in line:
            start_idx = i
        elif start_idx is not None and line.strip() == "]" and "system_admin_commands" in lines[start_idx + 1]:
            end_idx = i
            break
    
    if start_idx is None or end_idx is None:
        print("❌ Could not find system administration commands section")
        return False
    
    # Generate new code
    print("Generating new system administration commands...")
    new_code = generate_python_code_for_commands()
    
    # Replace the section
    new_lines = lines[:start_idx] + [new_code + "\n"] + lines[end_idx + 1:]
    
    # Write the updated file
    with open(server_path, "w") as f:
        f.writelines(new_lines)
    
    print("✓ Patched bash god server with 130 system administration commands")
    return True

def verify_patch():
    """Verify the patch was successful"""
    server_path = Path("mcp_learning_system/bash_god_mcp_server.py")
    
    with open(server_path, "r") as f:
        content = f.read()
    
    # Check for some of our new command IDs
    test_commands = [
        "sys_cpu_freq_scaling",
        "sys_cpu_core_parking",
        "sys_mem_hugepages",
        "sys_proc_nice_batch",
        "sys_mon_cpu_frequency",
        "sys_hw_pci_rescan",
        "sys_cfg_kernel_params"
    ]
    
    found = 0
    missing = []
    for cmd_id in test_commands:
        if f'"{cmd_id}"' in content:
            found += 1
        else:
            missing.append(cmd_id)
    
    print(f"\n✓ Verification: Found {found}/{len(test_commands)} test commands")
    if missing:
        print(f"❌ Missing commands: {missing}")
    
    # Count total system administration commands
    import re
    sys_cmd_count = len(re.findall(r'"sys_[^"]+",', content))
    print(f"✓ Total system administration commands: {sys_cmd_count}")
    
    # Verify it still has valid Python syntax
    try:
        compile(content, server_path, 'exec')
        print("✓ Python syntax is valid")
    except SyntaxError as e:
        print(f"❌ Syntax error: {e}")
        return False
    
    return found == len(test_commands)

if __name__ == "__main__":
    print("BASH GOD SYSTEM ADMINISTRATION PATCH")
    print("=" * 60)
    
    if patch_bash_god_server():
        print("\n✓ Patch applied successfully!")
        
        if verify_patch():
            print("\n✅ All verifications passed!")
            print("✅ System administration expansion complete!")
            print("\nDELIVERABLE COMPLETE:")
            print("- 130+ real system administration commands added")
            print("- AMD Ryzen 7 7800X3D optimizations included") 
            print("- Safety validation for each command")
            print("- Proper categorization and documentation")
            print("- Full integration with existing command library")
        else:
            print("\n⚠️  Some verifications failed")
    else:
        print("\n❌ Patch failed")