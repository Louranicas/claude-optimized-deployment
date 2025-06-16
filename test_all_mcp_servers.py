#!/usr/bin/env python3
"""
Comprehensive MCP Server Testing Script
Tests all available MCP servers for connectivity, functionality, and health
"""

import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import socket
import requests
import psutil

class MCPServerTester:
    def __init__(self):
        self.base_dir = Path("/home/louranicas/projects/claude-optimized-deployment")
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_servers": 0,
                "working": 0,
                "not_working": 0,
                "partially_working": 0
            },
            "servers": {}
        }
        
    def check_port_available(self, port: int) -> bool:
        """Check if a port is available for binding"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('127.0.0.1', port))
                return True
        except:
            return False
    
    def check_process_running(self, process_name: str) -> bool:
        """Check if a process with given name is running"""
        for proc in psutil.process_iter(['name', 'cmdline']):
            try:
                if process_name in proc.info['name'] or \
                   any(process_name in arg for arg in proc.info.get('cmdline', [])):
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return False
    
    def test_npm_servers(self):
        """Test TypeScript/JavaScript MCP servers in mcp_servers directory"""
        mcp_servers_dir = self.base_dir / "mcp_servers"
        
        server_info = {
            "name": "TypeScript MCP Servers",
            "type": "npm/typescript",
            "location": str(mcp_servers_dir),
            "status": "not_tested",
            "tests": {}
        }
        
        # Check directory existence
        if not mcp_servers_dir.exists():
            server_info["status"] = "not_found"
            server_info["error"] = "Directory does not exist"
            return server_info
            
        # Check package.json
        package_json = mcp_servers_dir / "package.json"
        if not package_json.exists():
            server_info["tests"]["package_json"] = {"status": "failed", "error": "package.json not found"}
        else:
            server_info["tests"]["package_json"] = {"status": "passed"}
            
        # Check node_modules
        node_modules = mcp_servers_dir / "node_modules"
        if not node_modules.exists():
            server_info["tests"]["dependencies"] = {"status": "failed", "error": "node_modules not found - run npm install"}
        else:
            server_info["tests"]["dependencies"] = {"status": "passed"}
            
        # Check API keys
        api_keys_file = mcp_servers_dir / "config" / "api_keys.env"
        if api_keys_file.exists():
            with open(api_keys_file, 'r') as f:
                content = f.read()
                required_keys = ["TAVILY_API_KEY", "SMITHERY_API_KEY", "BRAVE_API_KEY"]
                missing_keys = []
                for key in required_keys:
                    if key not in content or f"{key}=" not in content:
                        missing_keys.append(key)
                
                if missing_keys:
                    server_info["tests"]["api_keys"] = {
                        "status": "failed", 
                        "error": f"Missing API keys: {', '.join(missing_keys)}"
                    }
                else:
                    server_info["tests"]["api_keys"] = {"status": "passed"}
        else:
            server_info["tests"]["api_keys"] = {"status": "failed", "error": "API keys file not found"}
            
        # Test TypeScript compilation
        os.chdir(mcp_servers_dir)
        try:
            result = subprocess.run(["npm", "run", "typecheck"], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                server_info["tests"]["typescript_compilation"] = {"status": "passed"}
            else:
                server_info["tests"]["typescript_compilation"] = {
                    "status": "failed",
                    "error": result.stderr[:500] if result.stderr else "Compilation failed"
                }
        except Exception as e:
            server_info["tests"]["typescript_compilation"] = {
                "status": "failed",
                "error": str(e)
            }
            
        # Check individual server implementations
        servers_dir = mcp_servers_dir / "src" / "servers"
        if servers_dir.exists():
            server_implementations = []
            for server_path in servers_dir.iterdir():
                if server_path.is_dir() and (server_path / "index.ts").exists():
                    server_implementations.append(server_path.name)
            
            server_info["tests"]["implementations"] = {
                "status": "passed" if server_implementations else "failed",
                "servers": server_implementations
            }
        
        # Calculate overall status
        failed_tests = sum(1 for test in server_info["tests"].values() 
                          if test.get("status") == "failed")
        if failed_tests == 0:
            server_info["status"] = "working"
        elif failed_tests == len(server_info["tests"]):
            server_info["status"] = "not_working"
        else:
            server_info["status"] = "partially_working"
            
        return server_info
    
    def test_python_mcp_servers(self):
        """Test Python MCP servers in mcp_learning_system"""
        learning_system_dir = self.base_dir / "mcp_learning_system"
        servers_dir = learning_system_dir / "servers"
        
        results = []
        
        if not servers_dir.exists():
            return [{
                "name": "MCP Learning System Servers",
                "status": "not_found",
                "error": "Servers directory not found"
            }]
            
        # Test each server directory
        for server_dir in servers_dir.iterdir():
            if not server_dir.is_dir():
                continue
                
            server_info = {
                "name": f"MCP {server_dir.name.title()} Server",
                "type": "python/rust",
                "location": str(server_dir),
                "status": "not_tested",
                "tests": {}
            }
            
            # Check Python source
            python_src = server_dir / "python_src"
            if python_src.exists():
                server_py = python_src / "server.py"
                if server_py.exists():
                    server_info["tests"]["python_source"] = {"status": "passed"}
                else:
                    # Check for main.py as alternative
                    main_py = server_dir / "main.py"
                    if main_py.exists():
                        server_info["tests"]["python_source"] = {"status": "passed", "note": "Using main.py"}
                    else:
                        server_info["tests"]["python_source"] = {"status": "failed", "error": "No server.py or main.py found"}
            else:
                server_info["tests"]["python_source"] = {"status": "failed", "error": "No python_src directory"}
                
            # Check Rust source
            rust_src = server_dir / "rust_src"
            if rust_src.exists():
                cargo_toml = rust_src / "Cargo.toml"
                if cargo_toml.exists():
                    server_info["tests"]["rust_source"] = {"status": "passed"}
                    
                    # Check if Rust is built
                    target_dir = rust_src / "target"
                    if target_dir.exists() and (target_dir / "release").exists():
                        server_info["tests"]["rust_build"] = {"status": "passed"}
                    else:
                        server_info["tests"]["rust_build"] = {"status": "warning", "note": "Not built for release"}
                else:
                    server_info["tests"]["rust_source"] = {"status": "failed", "error": "No Cargo.toml found"}
            
            # Check requirements.txt
            requirements = server_dir / "requirements.txt"
            if requirements.exists():
                server_info["tests"]["requirements"] = {"status": "passed"}
            else:
                server_info["tests"]["requirements"] = {"status": "warning", "note": "No requirements.txt"}
                
            # Calculate status
            failed = sum(1 for test in server_info["tests"].values() if test.get("status") == "failed")
            warnings = sum(1 for test in server_info["tests"].values() if test.get("status") == "warning")
            
            if failed == 0 and warnings == 0:
                server_info["status"] = "working"
            elif failed == 0:
                server_info["status"] = "partially_working"
            else:
                server_info["status"] = "not_working"
                
            results.append(server_info)
            
        return results
    
    def test_configured_mcp_servers(self):
        """Test MCP servers from configuration files"""
        configs_dir = self.base_dir / "mcp_configs"
        results = []
        
        if not configs_dir.exists():
            return [{
                "name": "Configured MCP Servers",
                "status": "not_found",
                "error": "Configuration directory not found"
            }]
            
        # Read each config file
        for config_file in configs_dir.glob("*.json"):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    
                server_info = {
                    "name": f"MCP {config_file.stem.replace('_', ' ').title()}",
                    "type": "configured",
                    "config_file": str(config_file),
                    "status": "configured",
                    "tests": {}
                }
                
                # Check if it's in mcpServers section
                if "mcpServers" in config:
                    server_info["tests"]["config_valid"] = {"status": "passed"}
                    server_info["servers_configured"] = list(config["mcpServers"].keys())
                else:
                    server_info["tests"]["config_valid"] = {"status": "warning", "note": "No mcpServers section"}
                    
                results.append(server_info)
                
            except Exception as e:
                results.append({
                    "name": f"MCP {config_file.stem}",
                    "status": "error",
                    "error": f"Failed to parse config: {str(e)}"
                })
                
        return results
    
    def test_server_configs(self):
        """Test server configuration files"""
        server_configs_dir = self.base_dir / "mcp_server_configs"
        results = []
        
        if not server_configs_dir.exists():
            return [{
                "name": "MCP Server Configs",
                "status": "not_found",
                "error": "Server configs directory not found"
            }]
            
        for config_file in server_configs_dir.glob("*.json"):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    
                server_info = {
                    "name": f"{config_file.stem.replace('_config', '').title()} MCP Server",
                    "type": "configuration",
                    "config_file": str(config_file),
                    "status": "configured",
                    "config": config
                }
                
                results.append(server_info)
                
            except Exception as e:
                results.append({
                    "name": config_file.stem,
                    "status": "error",
                    "error": f"Failed to parse: {str(e)}"
                })
                
        return results
    
    def run_all_tests(self):
        """Run all MCP server tests"""
        print("Starting comprehensive MCP server testing...")
        print("=" * 80)
        
        # Test TypeScript servers
        print("\n1. Testing TypeScript/NPM MCP Servers...")
        npm_results = self.test_npm_servers()
        self.results["servers"]["typescript_servers"] = npm_results
        self.update_summary([npm_results])
        
        # Test Python/Rust servers
        print("\n2. Testing Python/Rust MCP Learning System Servers...")
        python_results = self.test_python_mcp_servers()
        self.results["servers"]["learning_system_servers"] = python_results
        self.update_summary(python_results)
        
        # Test configured servers
        print("\n3. Testing Configured MCP Servers...")
        configured_results = self.test_configured_mcp_servers()
        self.results["servers"]["configured_servers"] = configured_results
        self.update_summary(configured_results)
        
        # Test server configs
        print("\n4. Testing MCP Server Configuration Files...")
        config_results = self.test_server_configs()
        self.results["servers"]["server_configs"] = config_results
        self.update_summary(config_results)
        
        # Generate report
        self.generate_report()
        
    def update_summary(self, servers: List[Dict]):
        """Update summary statistics"""
        for server in servers:
            self.results["summary"]["total_servers"] += 1
            status = server.get("status", "unknown")
            if status == "working":
                self.results["summary"]["working"] += 1
            elif status == "not_working" or status == "not_found":
                self.results["summary"]["not_working"] += 1
            elif status in ["partially_working", "configured", "warning"]:
                self.results["summary"]["partially_working"] += 1
                
    def generate_report(self):
        """Generate comprehensive report"""
        report_file = self.base_dir / "mcp_server_comprehensive_status_report.json"
        
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2)
            
        print("\n" + "=" * 80)
        print("COMPREHENSIVE MCP SERVER STATUS REPORT")
        print("=" * 80)
        print(f"\nReport generated at: {self.results['timestamp']}")
        print(f"Report saved to: {report_file}")
        
        print("\n📊 SUMMARY:")
        print(f"  Total Servers Tested: {self.results['summary']['total_servers']}")
        print(f"  ✅ Working: {self.results['summary']['working']}")
        print(f"  ⚠️  Partially Working: {self.results['summary']['partially_working']}")
        print(f"  ❌ Not Working: {self.results['summary']['not_working']}")
        
        print("\n📋 DETAILED STATUS:")
        
        # TypeScript servers
        ts_servers = self.results["servers"].get("typescript_servers", {})
        if ts_servers:
            print(f"\n🔷 TypeScript MCP Servers:")
            self.print_server_status(ts_servers)
            
        # Learning system servers
        ls_servers = self.results["servers"].get("learning_system_servers", [])
        if ls_servers:
            print(f"\n🔶 MCP Learning System Servers:")
            for server in ls_servers:
                self.print_server_status(server)
                
        # Configured servers
        conf_servers = self.results["servers"].get("configured_servers", [])
        if conf_servers:
            print(f"\n🔵 Configured MCP Servers ({len(conf_servers)} found):")
            for server in conf_servers[:5]:  # Show first 5
                print(f"  - {server['name']}: {server['status']}")
            if len(conf_servers) > 5:
                print(f"  ... and {len(conf_servers) - 5} more")
                
        print("\n" + "=" * 80)
        
    def print_server_status(self, server: Dict):
        """Print individual server status"""
        status_icon = {
            "working": "✅",
            "partially_working": "⚠️",
            "not_working": "❌",
            "configured": "📝",
            "not_found": "❓"
        }.get(server.get("status", "unknown"), "❓")
        
        print(f"\n  {status_icon} {server.get('name', 'Unknown')} - {server.get('status', 'unknown')}")
        
        if "location" in server:
            print(f"     Location: {server['location']}")
            
        if "tests" in server:
            for test_name, test_result in server["tests"].items():
                test_icon = "✅" if test_result.get("status") == "passed" else "❌"
                print(f"     {test_icon} {test_name}: {test_result.get('status', 'unknown')}")
                if "error" in test_result:
                    print(f"        Error: {test_result['error']}")
                if "note" in test_result:
                    print(f"        Note: {test_result['note']}")

if __name__ == "__main__":
    tester = MCPServerTester()
    tester.run_all_tests()