#!/usr/bin/env python3
"""Check status of running MCP servers"""

import subprocess
import json
from pathlib import Path

# ANSI colors
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

def get_running_processes():
    """Get all running MCP processes"""
    try:
        result = subprocess.run(
            ["ps", "aux"], 
            capture_output=True, 
            text=True
        )
        
        mcp_processes = []
        for line in result.stdout.split('\n'):
            if 'mcp-server' in line and 'grep' not in line:
                parts = line.split()
                if len(parts) > 10:
                    pid = parts[1]
                    cpu = parts[2]
                    mem = parts[3]
                    cmd = ' '.join(parts[10:])
                    
                    # Extract server name
                    server_name = "unknown"
                    if 'mcp-server-' in cmd:
                        server_name = cmd.split('mcp-server-')[1].split()[0]
                    
                    mcp_processes.append({
                        'pid': pid,
                        'cpu': cpu,
                        'mem': mem,
                        'name': server_name,
                        'cmd': cmd[:80] + '...' if len(cmd) > 80 else cmd
                    })
                    
        return mcp_processes
    except Exception as e:
        print(f"Error getting processes: {e}")
        return []

def load_configured_servers():
    """Load configured servers from mcp.json"""
    config_path = Path.home() / ".config" / "claude" / "mcp.json"
    if config_path.exists():
        with open(config_path) as f:
            config = json.load(f)
            return list(config.get("mcpServers", {}).keys())
    return []

def main():
    print(f"\n{BLUE}🔍 MCP Server Status Check{RESET}")
    print(f"{BLUE}{'='*60}{RESET}\n")
    
    # Get running processes
    processes = get_running_processes()
    
    # Get configured servers
    configured = load_configured_servers()
    
    # Map running servers
    running_servers = {p['name'] for p in processes}
    
    print(f"{GREEN}✓ Running MCP Servers ({len(processes)}):{RESET}")
    for proc in processes:
        print(f"  • {proc['name']:<20} PID: {proc['pid']:<8} CPU: {proc['cpu']:<6} MEM: {proc['mem']:<6}")
    
    print(f"\n{BLUE}📋 Configured Servers ({len(configured)}):{RESET}")
    for server in configured:
        status = f"{GREEN}✓ Running{RESET}" if any(server in p['name'] for p in processes) else f"{RED}✗ Not Running{RESET}"
        print(f"  • {server:<20} {status}")
    
    # Summary
    running_count = len(processes)
    configured_count = len(configured)
    
    print(f"\n{BLUE}{'='*60}{RESET}")
    print(f"Summary: {running_count}/{configured_count} servers running")
    
    if running_count < configured_count:
        print(f"\n{YELLOW}⚠ Some servers are not running. This could be due to:{RESET}")
        print("  • Missing API keys")
        print("  • Network issues")
        print("  • Server initialization errors")

if __name__ == "__main__":
    main()