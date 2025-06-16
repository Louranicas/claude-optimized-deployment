#!/usr/bin/env python3
"""
Validate the bash god MCP server command count and categories
"""

import sys
import importlib.util
import json

def load_module(file_path):
    """Dynamically load the bash_god_mcp_server module"""
    spec = importlib.util.spec_from_file_location("bash_god_mcp_server", file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def validate_commands():
    """Validate command library"""
    # Load the module
    module = load_module("bash_god_mcp_server.py")
    
    # Create library instance
    library = module.BashGodCommandLibrary()
    
    # Count commands by category
    category_counts = {}
    for cmd in library.commands.values():
        category = cmd.category.value
        category_counts[category] = category_counts.get(category, 0) + 1
    
    # Display results
    print("=== BASH GOD MCP SERVER COMMAND VALIDATION ===")
    print(f"\nTotal Commands: {len(library.commands)}")
    print("\nCommands by Category:")
    
    expected = {
        "system_administration": 130,
        "devops_pipeline": 125,
        "performance_optimization": 140,
        "security_monitoring": 115,
        "development_workflow": 100,
        "network_api_integration": 50,
        "database_storage": 50,
        "coordination_infrastructure": 138
    }
    
    total_expected = sum(expected.values())
    
    for category, count in sorted(category_counts.items()):
        expected_count = expected.get(category, 0)
        status = "✓" if count >= expected_count else "✗"
        print(f"  {status} {category}: {count}/{expected_count}")
    
    print(f"\nExpected Total: {total_expected}")
    print(f"Actual Total: {len(library.commands)}")
    
    if len(library.commands) >= 800:
        print("\n✓ SUCCESS: Command library has 800+ commands!")
    else:
        print(f"\n✗ FAILURE: Command library has only {len(library.commands)} commands (need 800+)")
        print(f"  Missing: {800 - len(library.commands)} commands")
    
    # Check for real commands (not placeholders)
    placeholder_count = 0
    for cmd in library.commands.values():
        if "echo 'Development command" in cmd.command_template or \
           "echo 'Example" in cmd.command_template:
            placeholder_count += 1
    
    if placeholder_count > 0:
        print(f"\n⚠ WARNING: Found {placeholder_count} placeholder commands that need to be replaced with real commands")
    
    # Save detailed report
    report = {
        "total_commands": len(library.commands),
        "category_counts": category_counts,
        "expected_counts": expected,
        "placeholder_commands": placeholder_count,
        "success": len(library.commands) >= 800 and placeholder_count == 0
    }
    
    with open("bash_god_command_validation_report.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print("\nDetailed report saved to: bash_god_command_validation_report.json")
    
    return len(library.commands) >= 800 and placeholder_count == 0

if __name__ == "__main__":
    success = validate_commands()
    sys.exit(0 if success else 1)