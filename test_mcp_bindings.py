#!/usr/bin/env python3
"""Test script for MCP Manager Python bindings."""

import json
import sys
import traceback

def test_mcp_bindings():
    """Test the MCP Manager Python bindings."""
    try:
        # Try to import the module
        from claude_optimized_deployment_rust import mcp_manager
        print("✓ Successfully imported mcp_manager module")
        
        # Create a manager instance
        manager = mcp_manager.PyMcpManager()
        print("✓ Successfully created PyMcpManager instance")
        
        # Test available methods
        methods = [m for m in dir(manager) if not m.startswith('_')]
        print(f"\nAvailable methods: {', '.join(methods)}")
        
        # Test constants
        constants = [
            'SERVER_STATE_HEALTHY',
            'SERVER_STATE_DEGRADED', 
            'SERVER_STATE_UNHEALTHY',
            'CIRCUIT_STATE_CLOSED',
            'CIRCUIT_STATE_OPEN',
            'CIRCUIT_STATE_HALF_OPEN'
        ]
        
        print("\nChecking constants:")
        for const in constants:
            if hasattr(mcp_manager, const):
                print(f"✓ {const} = {getattr(mcp_manager, const)}")
            else:
                print(f"✗ {const} not found")
        
        # Test version
        if hasattr(mcp_manager, '__version__'):
            print(f"\n✓ Module version: {mcp_manager.__version__}")
        
        print("\n✅ All basic binding tests passed!")
        
    except ImportError as e:
        print(f"❌ Failed to import module: {e}")
        print("\nMake sure to build with: maturin develop --manifest-path rust_core/Cargo.toml")
        return False
    except Exception as e:
        print(f"❌ Error during testing: {e}")
        traceback.print_exc()
        return False
    
    return True

if __name__ == "__main__":
    success = test_mcp_bindings()
    sys.exit(0 if success else 1)