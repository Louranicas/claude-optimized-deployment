#!/usr/bin/env python3
"""
Simple MCP Server Launcher
Launches all configured MCP servers based on the Claude configuration
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

# ANSI color codes
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

class MCPServerLauncher:
    def __init__(self):
        self.config_path = Path.home() / ".config" / "claude" / "mcp.json"
        self.servers = {}
        self.processes = {}
        
    def load_config(self) -> Dict:
        """Load MCP configuration from Claude config file"""
        if not self.config_path.exists():
            print(f"{RED}Error: Claude MCP config not found at {self.config_path}{RESET}")
            sys.exit(1)
            
        with open(self.config_path) as f:
            config = json.load(f)
            
        return config.get("mcpServers", {})
    
    def check_api_keys(self, server_config: Dict) -> List[str]:
        """Check if required API keys are set"""
        missing_keys = []
        env_vars = server_config.get("env", {})
        
        for key, value in env_vars.items():
            if "API_KEY" in key and not value:
                # Check if it's set in environment
                if not os.environ.get(key):
                    missing_keys.append(key)
                    
        return missing_keys
    
    def launch_server(self, name: str, config: Dict) -> Optional[subprocess.Popen]:
        """Launch a single MCP server"""
        # Check for missing API keys
        missing_keys = self.check_api_keys(config)
        if missing_keys:
            print(f"{YELLOW}⚠ {name}: Missing API keys: {', '.join(missing_keys)}{RESET}")
            return None
            
        # Build command
        command = config.get("command", "npx")
        args = config.get("args", [])
        env = os.environ.copy()
        env.update(config.get("env", {}))
        
        # Full command
        full_cmd = [command] + args
        
        try:
            print(f"{BLUE}→ Launching {name}...{RESET}")
            process = subprocess.Popen(
                full_cmd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Give it a moment to start
            time.sleep(0.5)
            
            # Check if process is still running
            if process.poll() is None:
                print(f"{GREEN}✓ {name} launched successfully (PID: {process.pid}){RESET}")
                return process
            else:
                stdout, stderr = process.communicate()
                print(f"{RED}✗ {name} failed to start{RESET}")
                if stderr:
                    print(f"  Error: {stderr.strip()}")
                return None
                
        except Exception as e:
            print(f"{RED}✗ {name} failed to launch: {e}{RESET}")
            return None
    
    def launch_all(self):
        """Launch all configured MCP servers"""
        print(f"{BLUE}🚀 MCP Server Launcher{RESET}")
        print(f"{BLUE}{'='*50}{RESET}")
        
        # Load configuration
        self.servers = self.load_config()
        print(f"Found {len(self.servers)} configured MCP servers\n")
        
        # Launch each server
        successful = 0
        failed = 0
        
        for name, config in self.servers.items():
            process = self.launch_server(name, config)
            if process:
                self.processes[name] = process
                successful += 1
            else:
                failed += 1
                
        # Summary
        print(f"\n{BLUE}{'='*50}{RESET}")
        print(f"{GREEN}✓ Successfully launched: {successful} servers{RESET}")
        if failed > 0:
            print(f"{RED}✗ Failed to launch: {failed} servers{RESET}")
            
        # Show running servers
        if self.processes:
            print(f"\n{BLUE}Running MCP Servers:{RESET}")
            for name, process in self.processes.items():
                print(f"  • {name} (PID: {process.pid})")
                
        print(f"\n{YELLOW}Press Ctrl+C to stop all servers{RESET}")
        
        # Keep running
        try:
            while True:
                time.sleep(1)
                # Check for dead processes
                for name, process in list(self.processes.items()):
                    if process.poll() is not None:
                        print(f"\n{RED}⚠ {name} has stopped unexpectedly{RESET}")
                        del self.processes[name]
                        
        except KeyboardInterrupt:
            print(f"\n{YELLOW}Stopping all servers...{RESET}")
            self.stop_all()
            
    def stop_all(self):
        """Stop all running MCP servers"""
        for name, process in self.processes.items():
            print(f"Stopping {name}...")
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                print(f"Force killing {name}...")
                process.kill()
                
        print(f"{GREEN}All servers stopped{RESET}")

if __name__ == "__main__":
    # Set any available API keys from environment
    env_mappings = {
        "GITHUB_TOKEN": os.environ.get("GITHUB_TOKEN", ""),
        "ANTHROPIC_API_KEY": os.environ.get("ANTHROPIC_API_KEY", ""),
        "OPENWEATHER_API_KEY": os.environ.get("OPENWEATHER_API_KEY", ""),
        "SLACK_BOT_TOKEN": os.environ.get("SLACK_BOT_TOKEN", ""),
        "SMITHERY_API_KEY": "d2bddad0-4155-4fdf-97a1-298122fecf7b"
    }
    
    for key, value in env_mappings.items():
        if value:
            os.environ[key] = value
    
    launcher = MCPServerLauncher()
    launcher.launch_all()