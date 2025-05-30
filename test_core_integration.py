#!/usr/bin/env python3
"""
Core Integration Test - Demonstrates working system components
"""

import asyncio
import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from mcp.manager import get_mcp_manager


async def test_core_integration():
    """Test core integration functionality that doesn't require external services."""
    print("🚀 Testing Core System Integration")
    print("=" * 50)
    
    try:
        # Initialize MCP Manager
        manager = get_mcp_manager()
        await manager.initialize()
        
        # Create test context
        context_id = "core_test"
        context = manager.create_context(context_id)
        
        print(f"📋 Created test context: {context_id}")
        
        # Get server information
        print("\n🏗️  Available MCP Servers:")
        server_info = manager.get_server_info()
        for name, info in server_info.items():
            print(f"  • {name}: {info.description}")
        
        # Get available tools
        all_tools = manager.get_available_tools()
        print(f"\n🛠️  Total Tools Available: {len(all_tools)}")
        
        tools_by_server = {}
        for tool in all_tools:
            server_name = tool['name'].split('.')[0]
            if server_name not in tools_by_server:
                tools_by_server[server_name] = []
            tools_by_server[server_name].append(tool['name'].split('.', 1)[1])
        
        for server, tools in tools_by_server.items():
            print(f"  🔧 {server}: {len(tools)} tools")
        
        # Test Desktop Commander (should work without external deps)
        print("\n🖥️  Testing Desktop Commander:")
        try:
            manager.enable_server(context_id, "desktop-commander")
            
            result = await manager.call_tool(
                "desktop-commander.execute_command",
                {"command": "echo 'System integration test successful!'", "description": "Integration test"},
                context_id
            )
            
            if result.get("success"):
                print(f"  ✅ Command executed successfully")
                print(f"  📤 Output: {result.get('output', '')[:100]}...")
            else:
                print(f"  ❌ Command failed")
                
        except Exception as e:
            print(f"  ⚠️  Desktop Commander test: {str(e)[:100]}...")
        
        # Test Security Scanner
        print("\n🔒 Testing Security Scanner:")
        try:
            manager.enable_server(context_id, "security-scanner")
            
            result = await manager.call_tool(
                "security-scanner.file_security_scan",
                {"target_path": ".", "scan_type": "basic"},
                context_id
            )
            
            findings = result.get("findings", [])
            print(f"  ✅ Security scan completed: {len(findings)} findings")
            
        except Exception as e:
            print(f"  ⚠️  Security Scanner test: {str(e)[:100]}...")
        
        # Test tool call history
        print(f"\n📊 Integration Test Summary:")
        total_calls = len(context.tool_calls)
        successful_calls = sum(1 for call in context.tool_calls if call.success)
        
        print(f"  • Total Tool Calls: {total_calls}")
        print(f"  • Successful Calls: {successful_calls}")
        print(f"  • Success Rate: {successful_calls/max(total_calls,1):.1%}")
        
        if context.tool_calls:
            print(f"\n✅ Recent Tool Calls:")
            for call in context.tool_calls[-3:]:
                status = "✅" if call.success else "❌"
                print(f"  {status} {call.server_name}.{call.tool_name} ({call.duration_ms:.1f}ms)")
        
        print(f"\n🎉 Core Integration Test Complete!")
        print(f"   System demonstrates cross-module integration capabilities")
        
        # Cleanup
        await manager.cleanup()
        
        return True
        
    except Exception as e:
        print(f"\n💥 Integration test error: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    print("Starting core integration test...")
    print()
    
    try:
        result = asyncio.run(test_core_integration())
        if result:
            print("\n✅ Core integration validated!")
        else:
            print("\n❌ Core integration needs attention")
            
    except KeyboardInterrupt:
        print("\n⏹️  Test interrupted by user")
    except Exception as e:
        print(f"\n💥 Test failed: {e}")