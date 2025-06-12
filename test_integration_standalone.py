#!/usr/bin/env python3
# test_integration.py
import asyncio
from test_modules import test_module_imports

async def test_module_instantiation():
    """Test that all modules can be instantiated."""
    imports = test_module_imports()
    
    for name, result in imports.items():
        if result['status'] == 'SUCCESS':
            try:
                # Test instantiation
                instance = result['class']()
                print(f"✅ {name}: Instantiation successful")
                
                # Test MCP protocol compliance
                assert hasattr(instance, 'get_server_info'), f"{name} missing get_server_info"
                assert hasattr(instance, 'get_tools'), f"{name} missing get_tools"
                assert hasattr(instance, 'call_tool'), f"{name} missing call_tool"
                print(f"✅ {name}: MCP protocol compliance verified")
                
            except Exception as e:
                print(f"❌ {name}: Instantiation failed: {e}")

def test_tool_registration():
    """Test that all modules register their tools correctly."""
    imports = test_module_imports()
    
    for name, result in imports.items():
        if result['status'] == 'SUCCESS':
            try:
                instance = result['class']()
                tools = instance.get_tools()
                print(f"✅ {name}: {len(tools)} tools registered")
                
                # Verify tool structure
                for tool in tools:
                    assert hasattr(tool, 'name'), f"{name} tool missing name"
                    assert hasattr(tool, 'description'), f"{name} tool missing description"
                    
            except Exception as e:
                print(f"❌ {name}: Tool registration failed: {e}")

if __name__ == "__main__":
    print("Testing module instantiation...")
    asyncio.run(test_module_instantiation())
    print("\nTesting tool registration...")
    test_tool_registration()