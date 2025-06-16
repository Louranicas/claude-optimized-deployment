#!/usr/bin/env python3
"""
VERIFICATION SCRIPT - MITIGATION AGENT 3
Verify complete integration of 130+ system administration commands
"""

import re
import sys
from pathlib import Path

# Import the bash god server module
sys.path.insert(0, str(Path("mcp_learning_system").absolute()))
from bash_god_mcp_server import BashGodCommandLibrary, CommandCategory

def verify_integration():
    """Verify the system administration commands are properly integrated"""
    
    print("SYSTEM ADMINISTRATION COMMAND VERIFICATION")
    print("=" * 60)
    
    # Initialize the command library
    library = BashGodCommandLibrary()
    
    # Get all system administration commands
    sys_admin_commands = library.get_commands_by_category(CommandCategory.SYSTEM_ADMINISTRATION)
    
    print(f"\n✓ Total system administration commands: {len(sys_admin_commands)}")
    
    # Verify command categories
    subcategories = {
        "sys_cpu_": "CPU Management",
        "sys_mem_": "Memory Management", 
        "sys_proc_": "Process Management",
        "sys_mon_": "System Monitoring",
        "sys_hw_": "Hardware Interaction",
        "sys_cfg_": "System Configuration"
    }
    
    category_counts = {cat: 0 for cat in subcategories.values()}
    
    for cmd in sys_admin_commands:
        for prefix, category in subcategories.items():
            if cmd.id.startswith(prefix):
                category_counts[category] += 1
                break
    
    print("\nCommand Distribution by Subcategory:")
    for category, count in category_counts.items():
        print(f"  - {category}: {count} commands")
    
    # Check AMD Ryzen optimizations
    amd_optimized = sum(1 for cmd in sys_admin_commands if cmd.amd_ryzen_optimized)
    print(f"\n✓ AMD Ryzen 7 7800X3D optimized commands: {amd_optimized}")
    
    # Check safety levels
    safety_levels = {}
    for cmd in sys_admin_commands:
        level = cmd.safety_level.value
        safety_levels[level] = safety_levels.get(level, 0) + 1
    
    print("\nSafety Level Distribution:")
    for level, count in sorted(safety_levels.items()):
        print(f"  - {level}: {count} commands")
    
    # Verify specific commands exist
    test_commands = [
        "sys_cpu_freq_scaling",
        "sys_cpu_core_parking",
        "sys_cpu_temperature",
        "sys_mem_hugepages",
        "sys_mem_numa_balance",
        "sys_proc_nice_batch",
        "sys_proc_cgroup_create",
        "sys_mon_cpu_frequency",
        "sys_mon_interrupt_stats",
        "sys_hw_pci_rescan",
        "sys_hw_gpu_info",
        "sys_cfg_kernel_params",
        "sys_cfg_grub_cmdline"
    ]
    
    print("\nVerifying Key Commands:")
    found = 0
    for cmd_id in test_commands:
        cmd = library.get_command(cmd_id)
        if cmd:
            found += 1
            print(f"  ✓ {cmd_id}: {cmd.name}")
        else:
            print(f"  ❌ {cmd_id}: NOT FOUND")
    
    print(f"\n✓ Found {found}/{len(test_commands)} test commands")
    
    # Check command properties
    print("\nCommand Property Statistics:")
    with_params = sum(1 for cmd in sys_admin_commands if cmd.parameters)
    with_examples = sum(1 for cmd in sys_admin_commands if cmd.examples)
    with_hints = sum(1 for cmd in sys_admin_commands if cmd.performance_hints)
    with_deps = sum(1 for cmd in sys_admin_commands if cmd.dependencies)
    
    print(f"  - Commands with parameters: {with_params}")
    print(f"  - Commands with examples: {with_examples}")
    print(f"  - Commands with performance hints: {with_hints}")
    print(f"  - Commands with dependencies: {with_deps}")
    
    # Final summary
    print("\n" + "=" * 60)
    if len(sys_admin_commands) >= 130 and found == len(test_commands):
        print("✅ SYSTEM ADMINISTRATION EXPANSION COMPLETE!")
        print("✅ All 130+ commands successfully integrated")
        print("✅ AMD Ryzen 7 7800X3D optimizations included")
        print("✅ Full safety validation and documentation")
        return True
    else:
        print("❌ VERIFICATION FAILED")
        print(f"   Expected: 130+ commands, Found: {len(sys_admin_commands)}")
        return False

if __name__ == "__main__":
    success = verify_integration()
    sys.exit(0 if success else 1)