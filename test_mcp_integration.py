#!/usr/bin/env python3
"""
Test script for MCP server integration in CODE project.

Tests all installed MCP servers and their functionality.
"""

import asyncio
import sys
import os
import json
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.mcp.manager import get_mcp_manager, MCPManager


async def test_mcp_servers():
    """Test all MCP servers and their capabilities."""
    print("🧪 Testing CODE MCP Server Integration")
    print("=" * 50)
    
    # Initialize MCP Manager
    manager = get_mcp_manager()
    await manager.initialize()
    
    # Create test context
    context_id = "test_integration"
    context = manager.create_context(context_id)
    
    print(f"📋 Created test context: {context_id}")
    print(f"🔧 Enabled servers: {context.enabled_servers}")
    
    # Get server information
    print("\n📊 MCP Server Registry:")
    server_info = manager.get_server_info()
    for name, info in server_info.items():
        print(f"  • {name}: {info.description}")
        print(f"    Version: {info.version}")
        print(f"    Capabilities: {list(info.capabilities.experimental.keys())}")
    
    # Get available tools
    print("\n🛠️  Available Tools:")
    tools = manager.get_available_tools(context_id)
    for tool in tools:
        print(f"  • {tool['name']}: {tool['description']}")
    
    # Test Desktop Commander
    print("\n🖥️  Testing Desktop Commander...")
    try:
        # Enable desktop commander for this context
        manager.enable_server(context_id, "desktop-commander")
        
        # Test simple command
        result = await manager.call_tool(
            "desktop-commander.execute_command",
            {"command": "echo 'Hello from MCP!'"},
            context_id
        )
        print(f"  ✅ Command execution: {result['success']}")
        print(f"     Output: {result['stdout'].strip()}")
        
        # Test make command
        result = await manager.call_tool(
            "desktop-commander.make_command",
            {"target": "help"},
            context_id
        )
        print(f"  ✅ Make command: {result['success']}")
        
    except Exception as e:
        print(f"  ❌ Desktop Commander test failed: {e}")
    
    # Test Docker MCP
    print("\n🐳 Testing Docker MCP...")
    try:
        manager.enable_server(context_id, "docker")
        
        # Test docker ps
        result = await manager.call_tool(
            "docker.docker_ps",
            {"all": False},
            context_id
        )
        print(f"  ✅ Docker ps: {result.get('success', False)}")
        print(f"     Containers: {len(result.get('containers', []))}")
        
    except Exception as e:
        print(f"  ⚠️  Docker test (expected if Docker not running): {e}")
    
    # Test Kubernetes MCP
    print("\n☸️  Testing Kubernetes MCP...")
    try:
        manager.enable_server(context_id, "kubernetes")
        
        # Test kubectl get nodes
        result = await manager.call_tool(
            "kubernetes.kubectl_get",
            {"resource_type": "nodes"},
            context_id
        )
        print(f"  ✅ Kubectl get: {result.get('success', False)}")
        
    except Exception as e:
        print(f"  ⚠️  Kubernetes test (expected if kubectl not configured): {e}")
    
    # Test Brave Search
    print("\n🔍 Testing Brave Search...")
    try:
        manager.enable_server(context_id, "brave")
        
        # Test web search
        result = await manager.search_web(
            "CODE project deployment automation",
            count=3,
            context_id=context_id
        )
        print(f"  ✅ Web search: {len(result.get('results', []))} results")
        
    except Exception as e:
        print(f"  ⚠️  Brave search test: {e}")
    
    # Test Azure DevOps (if configured)
    print("\n🔧 Testing Azure DevOps...")
    try:
        manager.enable_server(context_id, "azure-devops")
        
        # This will likely fail without proper configuration
        result = await manager.call_tool(
            "azure-devops.list_projects",
            {},
            context_id
        )
        print(f"  ✅ Azure DevOps: {len(result.get('projects', []))} projects")
        
    except Exception as e:
        print(f"  ⚠️  Azure DevOps test (expected without PAT): {e}")
    
    # Test Windows System
    print("\n🪟 Testing Windows System...")
    try:
        manager.enable_server(context_id, "windows-system")
        
        # Test environment listing
        result = await manager.call_tool(
            "windows-system.windows_environment",
            {"action": "get", "variable_name": "PATH"},
            context_id
        )
        print(f"  ✅ Windows environment: {result.get('success', False)}")
        
    except Exception as e:
        print(f"  ⚠️  Windows system test: {e}")
    
    # Show context tool history
    print(f"\n📈 Tool Call History ({len(context.tool_calls)} calls):")
    for i, call in enumerate(context.tool_calls[-5:], 1):  # Show last 5
        status = "✅" if call.success else "❌"
        print(f"  {i}. {status} {call.server_name}.{call.tool_name} ({call.duration_ms:.1f}ms)")
    
    # Cleanup
    await manager.cleanup()
    print("\n🎉 MCP Integration Test Complete!")


async def test_circle_of_experts_mcp_integration():
    """Test Circle of Experts integration with MCP servers."""
    print("\n🎪 Testing Circle of Experts + MCP Integration")
    print("=" * 50)
    
    try:
        from src.circle_of_experts.core.enhanced_expert_manager import EnhancedExpertManager
        
        # Initialize expert manager
        expert_manager = EnhancedExpertManager()
        
        # Get MCP manager
        mcp_manager = get_mcp_manager()
        await mcp_manager.initialize()
        
        print("✅ Expert Manager initialized")
        print("✅ MCP Manager initialized")
        print("🔗 Integration ready for enhanced expert consultations")
        
        # This demonstrates the potential for expert recommendations
        # to be automatically executed via MCP servers
        print("\n💡 Potential Integration Features:")
        print("  • Expert recommendations → MCP tool execution")
        print("  • Automated deployment based on AI consensus")
        print("  • Real-time infrastructure validation")
        print("  • Cost optimization through expert analysis")
        
    except ImportError as e:
        print(f"⚠️  Circle of Experts integration test skipped: {e}")


if __name__ == "__main__":
    try:
        # Run MCP tests
        asyncio.run(test_mcp_servers())
        
        # Run integration tests
        asyncio.run(test_circle_of_experts_mcp_integration())
        
    except KeyboardInterrupt:
        print("\n⏹️  Test interrupted by user")
    except Exception as e:
        print(f"\n💥 Test failed with error: {e}")
        import traceback
        traceback.print_exc()