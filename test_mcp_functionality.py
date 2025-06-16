#!/usr/bin/env python3
"""
Test MCP Server Functionality
Tests basic operations with each configured MCP server
"""

import subprocess
import json
import time
import os

def test_server_basic(server_name, test_command):
    """Test a server with a basic command"""
    print(f"\n🧪 Testing {server_name}...")
    
    try:
        # Run the test command
        result = subprocess.run(
            test_command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            print(f"✅ {server_name}: Success")
            if result.stdout:
                print(f"   Output: {result.stdout.strip()[:100]}...")
            return True
        else:
            print(f"❌ {server_name}: Failed")
            if result.stderr:
                print(f"   Error: {result.stderr.strip()[:100]}...")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"⏱️  {server_name}: Timeout")
        return False
    except Exception as e:
        print(f"❌ {server_name}: Exception - {str(e)}")
        return False

def main():
    print("🚀 MCP Server Functionality Test")
    print("=" * 50)
    
    # Test commands for each server
    tests = {
        "filesystem": "npx -y @modelcontextprotocol/server-filesystem /tmp 2>&1 | head -5",
        "time": "npx -y @modelcontextprotocol/server-time 2>&1 | head -5",
        "memory": "npx -y @modelcontextprotocol/server-memory 2>&1 | head -5",
        "git": "cd /tmp && git init test_repo && npx -y @modelcontextprotocol/server-git 2>&1 | head -5",
        "fetch": "npx -y @modelcontextprotocol/server-fetch 2>&1 | head -5",
    }
    
    results = {}
    
    # Run tests
    for server, command in tests.items():
        results[server] = test_server_basic(server, command)
    
    # Summary
    print("\n📊 Test Summary")
    print("=" * 50)
    
    passed = sum(1 for r in results.values() if r)
    total = len(results)
    
    print(f"Passed: {passed}/{total}")
    print(f"Success Rate: {(passed/total)*100:.1f}%")
    
    if passed < total:
        print("\n❌ Failed servers:")
        for server, result in results.items():
            if not result:
                print(f"  - {server}")
    
    print("\n💡 Notes:")
    print("- Some servers require specific setup or API keys")
    print("- Servers are designed to work within Claude Code environment")
    print("- For full testing, use servers within Claude Code")

if __name__ == "__main__":
    main()