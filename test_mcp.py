#!/usr/bin/env python3
"""
MCP Server Test Script
Tests the availability and basic functionality of configured MCP servers
"""

import json
import subprocess
import os
import sys
from pathlib import Path

def load_mcp_config():
    """Load MCP configuration from Claude config"""
    config_path = Path.home() / ".config" / "claude" / "mcp.json"
    
    if not config_path.exists():
        print(f"❌ MCP configuration not found at: {config_path}")
        return None
    
    with open(config_path, 'r') as f:
        return json.load(f)

def test_npx_package(package_name):
    """Test if an npx package is available"""
    try:
        # Try to run the package with --version or --help
        result = subprocess.run(
            ["npx", "-y", package_name, "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            return True, "Available"
        
        # Try with --help if --version fails
        result = subprocess.run(
            ["npx", "-y", package_name, "--help"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        return result.returncode == 0, "Available (help)"
    
    except subprocess.TimeoutExpired:
        return False, "Timeout"
    except Exception as e:
        return False, str(e)

def check_prerequisites():
    """Check if required tools are installed"""
    print("🔍 Checking prerequisites...")
    
    # Check Node.js
    try:
        result = subprocess.run(["node", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ Node.js: {result.stdout.strip()}")
        else:
            print("❌ Node.js not found")
            return False
    except:
        print("❌ Node.js not found")
        return False
    
    # Check npm/npx
    try:
        result = subprocess.run(["npx", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ npx: {result.stdout.strip()}")
        else:
            print("❌ npx not found")
            return False
    except:
        print("❌ npx not found")
        return False
    
    return True

def test_mcp_servers(config):
    """Test each configured MCP server"""
    print("\n🧪 Testing MCP Servers")
    print("=" * 50)
    
    servers = config.get("mcpServers", {})
    results = {}
    
    for server_name, server_config in servers.items():
        print(f"\n📦 Testing: {server_name}")
        
        command = server_config.get("command", "")
        args = server_config.get("args", [])
        env = server_config.get("env", {})
        
        # Extract package name from args
        package_name = None
        for i, arg in enumerate(args):
            if arg == "-y" and i + 1 < len(args):
                package_name = args[i + 1]
                break
        
        if not package_name:
            print(f"  ❌ Could not determine package name")
            results[server_name] = "Configuration Error"
            continue
        
        print(f"  Package: {package_name}")
        
        # Check API keys
        missing_keys = []
        for key, value in env.items():
            if not value:
                missing_keys.append(key)
        
        if missing_keys:
            print(f"  ⚠️  Missing API keys: {', '.join(missing_keys)}")
        
        # Test package availability
        available, message = test_npx_package(package_name)
        
        if available:
            print(f"  ✅ Status: {message}")
            results[server_name] = "Available"
        else:
            print(f"  ❌ Status: {message}")
            results[server_name] = f"Error: {message}"
    
    return results

def print_summary(results):
    """Print test summary"""
    print("\n📊 Summary")
    print("=" * 50)
    
    total = len(results)
    available = sum(1 for status in results.values() if status == "Available")
    
    print(f"Total servers: {total}")
    print(f"Available: {available}")
    print(f"Unavailable: {total - available}")
    
    if available == total:
        print("\n✅ All MCP servers are properly configured!")
    else:
        print("\n⚠️  Some servers need attention:")
        for server, status in results.items():
            if status != "Available":
                print(f"  - {server}: {status}")

def main():
    print("🚀 MCP Server Test Tool")
    print("=" * 50)
    
    # Check prerequisites
    if not check_prerequisites():
        print("\n❌ Please install Node.js and npm first")
        sys.exit(1)
    
    # Load configuration
    config = load_mcp_config()
    if not config:
        sys.exit(1)
    
    print(f"\n📁 Loaded configuration from: ~/.config/claude/mcp.json")
    print(f"📦 Found {len(config.get('mcpServers', {}))} configured servers")
    
    # Test servers
    results = test_mcp_servers(config)
    
    # Print summary
    print_summary(results)
    
    print("\n💡 Next steps:")
    print("1. Add missing API keys using: ./configure_mcp_servers.sh")
    print("2. Restart Claude Code to load the configuration")
    print("3. Run 'claude mcp' to verify")
    print("\nFor usage examples, see: MCP_USAGE_EXAMPLES.md")

if __name__ == "__main__":
    main()