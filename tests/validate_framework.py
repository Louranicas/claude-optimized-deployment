#!/usr/bin/env python3
"""
MCP Testing Framework Validation Script

Quick validation script to ensure the testing framework is properly configured.
"""

import sys
import importlib
from pathlib import Path

def validate_imports():
    """Validate that all testing modules can be imported."""
    modules = [
        'mcp_testing_framework',
        'mcp_stress_testing', 
        'mcp_security_testing',
        'mcp_health_monitoring',
        'run_all_mcp_tests'
    ]
    
    results = {}
    
    for module in modules:
        try:
            importlib.import_module(module)
            results[module] = "✅ OK"
        except ImportError as e:
            results[module] = f"❌ Error: {e}"
        except Exception as e:
            results[module] = f"⚠️ Warning: {e}"
    
    return results

def validate_structure():
    """Validate directory structure."""
    base_path = Path(__file__).parent
    required_files = [
        'mcp_testing_framework.py',
        'mcp_stress_testing.py',
        'mcp_security_testing.py', 
        'mcp_health_monitoring.py',
        'run_all_mcp_tests.py',
        'README_MCP_TESTING_FRAMEWORK.md'
    ]
    
    results = {}
    
    for file in required_files:
        file_path = base_path / file
        if file_path.exists():
            results[file] = "✅ Found"
        else:
            results[file] = "❌ Missing"
    
    return results

def main():
    """Main validation function."""
    print("🧪 MCP Testing Framework Validation")
    print("=" * 50)
    
    # Check directory structure
    print("\n📁 Directory Structure:")
    structure_results = validate_structure()
    for file, status in structure_results.items():
        print(f"  {file}: {status}")
    
    # Check imports
    print("\n📦 Module Imports:")
    import_results = validate_imports()
    for module, status in import_results.items():
        print(f"  {module}: {status}")
    
    # Summary
    structure_ok = all("✅" in status for status in structure_results.values())
    imports_ok = all("✅" in status for status in import_results.values())
    
    print("\n" + "=" * 50)
    if structure_ok and imports_ok:
        print("✅ MCP Testing Framework validation PASSED")
        print("🚀 Framework is ready for testing!")
        return 0
    else:
        print("❌ MCP Testing Framework validation FAILED")
        if not structure_ok:
            print("   - Check file structure and missing files")
        if not imports_ok:
            print("   - Check import errors and dependencies")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)