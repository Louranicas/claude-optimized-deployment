#!/usr/bin/env python3
"""
Test MCP server constructor fixes.
"""
import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def test_security_servers():
    """Test that security servers can be imported and instantiated with permission_checker."""
    try:
        # Test SecurityScannerMCPServer
        from src.mcp.security.scanner_server import SecurityScannerMCPServer
        security_scanner = SecurityScannerMCPServer(permission_checker=None)
        print("✅ SecurityScannerMCPServer: Fixed - constructor accepts permission_checker")
        
        # Test SASTMCPServer  
        from src.mcp.security.sast_server import SASTMCPServer
        sast_server = SASTMCPServer(permission_checker=None)
        print("✅ SASTMCPServer: Fixed - constructor accepts permission_checker")
        
        # Test SupplyChainSecurityMCPServer
        from src.mcp.security.supply_chain_server import SupplyChainSecurityMCPServer
        supply_chain_server = SupplyChainSecurityMCPServer(permission_checker=None)
        print("✅ SupplyChainSecurityMCPServer: Fixed - constructor accepts permission_checker")
        
        return True
        
    except Exception as e:
        print(f"❌ Security server test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_exception_classes():
    """Test that MCP exception classes work correctly."""
    try:
        from src.core.exceptions import MCPToolNotFoundError, MCPToolExecutionError
        
        # Test MCPToolNotFoundError
        error1 = MCPToolNotFoundError("test_tool", "test_server")
        print("✅ MCPToolNotFoundError: Constructor works correctly")
        
        # Test MCPToolExecutionError
        error2 = MCPToolExecutionError("Test execution error", "test_tool", "test_server")
        print("✅ MCPToolExecutionError: Constructor works correctly")
        
        return True
        
    except Exception as e:
        print(f"❌ Exception test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_auth_module():
    """Test that auth module imports with AUDIT_SIGNING_KEY."""
    try:
        # Set environment variable if not set
        if not os.getenv('AUDIT_SIGNING_KEY'):
            os.environ['AUDIT_SIGNING_KEY'] = 'test_signing_key_for_audit'
        
        from src.auth import api
        print("✅ Auth module: Imports successfully with AUDIT_SIGNING_KEY")
        return True
        
    except Exception as e:
        print(f"❌ Auth module test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all MCP fix tests."""
    print("🧪 Testing MCP Server Constructor Fixes")
    print("=" * 50)
    
    success_count = 0
    total_tests = 3
    
    if test_security_servers():
        success_count += 1
    
    if test_exception_classes():
        success_count += 1
        
    if test_auth_module():
        success_count += 1
    
    print("\n" + "=" * 50)
    print(f"📊 Test Results: {success_count}/{total_tests} tests passed")
    
    if success_count == total_tests:
        print("🎉 All fixes validated successfully!")
        print("✅ Security server constructors now accept permission_checker")
        print("✅ Exception classes work correctly")
        print("✅ Auth module imports with environment variable")
        return True
    else:
        print("⚠️ Some tests failed - additional fixes may be needed")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)