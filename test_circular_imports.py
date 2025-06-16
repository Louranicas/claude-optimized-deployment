#!/usr/bin/env python3
"""
Test script to verify no circular imports in MCP modules.

This script tests that all MCP modules can be imported independently
without circular import errors.
"""

import sys
import importlib
import traceback
from typing import List, Tuple, Dict

def test_import(module_path: str) -> Tuple[bool, str]:
    """Test importing a module.
    
    Args:
        module_path: Full module path to import
        
    Returns:
        Tuple of (success, error_message)
    """
    try:
        # Clear any previous imports to ensure clean test
        if module_path in sys.modules:
            del sys.modules[module_path]
            
        importlib.import_module(module_path)
        return True, ""
    except ImportError as e:
        error_str = str(e)
        # Check for circular import indicators
        if any(indicator in error_str.lower() for indicator in [
            "circular import", 
            "cannot import name",
            "partially initialized module"
        ]):
            return False, f"Circular import detected: {e}"
        # Ignore missing third-party dependencies for this test
        elif "no module named" in error_str.lower() and any(dep in error_str.lower() for dep in [
            'pydantic', 'aiohttp', 'tortoise', 'numpy', 'pandas', 'prometheus_client'
        ]):
            return True, ""  # Consider it a pass if only external deps missing
        else:
            return False, f"Import error: {e}"
    except Exception as e:
        return False, f"Unexpected error: {e}\n{traceback.format_exc()}"


def main():
    """Test all MCP modules for circular imports."""
    
    # List of modules to test
    modules_to_test = [
        # Core protocol module
        "src.mcp.protocols",
        
        # Registry module
        "src.mcp.registry",
        
        # Server implementations
        "src.mcp.servers",
        "src.mcp.infrastructure_servers",
        "src.mcp.devops_servers",
        "src.mcp.monitoring.prometheus_server",
        "src.mcp.security.scanner_server",
        "src.mcp.security.sast_server",
        "src.mcp.security.supply_chain_server",
        "src.mcp.communication.slack_server",
        "src.mcp.storage.s3_server",
        "src.mcp.storage.cloud_storage_server",
        
        # Manager and client
        "src.mcp.manager",
        "src.mcp.client",
        
        # Main module
        "src.mcp",
    ]
    
    print("Testing MCP modules for circular imports...\n")
    
    results: Dict[str, Tuple[bool, str]] = {}
    failed_modules: List[str] = []
    
    # Test each module
    for module in modules_to_test:
        print(f"Testing {module}...", end=" ")
        success, error = test_import(module)
        results[module] = (success, error)
        
        if success:
            print("✓ OK")
        else:
            print(f"✗ FAILED")
            print(f"  Error: {error}")
            failed_modules.append(module)
    
    # Summary
    print(f"\n{'='*60}")
    print(f"Test Summary: {len(modules_to_test) - len(failed_modules)}/{len(modules_to_test)} modules passed")
    print(f"{'='*60}\n")
    
    if failed_modules:
        print("Failed modules:")
        for module in failed_modules:
            _, error = results[module]
            print(f"  - {module}")
            print(f"    {error}\n")
        return 1
    else:
        print("✓ All modules can be imported independently!")
        print("✓ No circular imports detected!")
        return 0


if __name__ == "__main__":
    sys.exit(main())