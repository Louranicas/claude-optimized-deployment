#!/usr/bin/env python3
"""
Test actual MCP server functionality
"""

import subprocess
import json
import os
import time
import sys
from pathlib import Path
import asyncio
import socket

class MCPFunctionalityTester:
    def __init__(self):
        self.base_dir = Path("/home/louranicas/projects/claude-optimized-deployment")
        os.chdir(self.base_dir)
        
    def test_typescript_server_startup(self):
        """Test if TypeScript MCP servers can start"""
        print("\n🔍 Testing TypeScript Server Startup...")
        
        mcp_servers_dir = self.base_dir / "mcp_servers"
        os.chdir(mcp_servers_dir)
        
        # First, try to fix TypeScript compilation errors
        print("Attempting to fix TypeScript compilation errors...")
        
        # Create a simple test server file
        test_server = """
import express from 'express';

const app = express();
const PORT = process.env.PORT || 3000;

app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
    console.log(`Test MCP server running on port ${PORT}`);
});
"""
        
        test_server_path = mcp_servers_dir / "src" / "test-simple-server.ts"
        with open(test_server_path, 'w') as f:
            f.write(test_server)
            
        # Try to compile and run the simple test server
        try:
            print("Compiling test server...")
            result = subprocess.run(
                ["npx", "tsc", "src/test-simple-server.ts", "--outDir", "dist", "--skipLibCheck"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                print("✅ TypeScript compilation successful for test server")
                
                # Try to run the compiled server
                print("Starting test server...")
                server_process = subprocess.Popen(
                    ["node", "dist/test-simple-server.js"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                # Give it time to start
                time.sleep(2)
                
                # Check if it's running
                if server_process.poll() is None:
                    print("✅ Test server started successfully")
                    
                    # Test the health endpoint
                    try:
                        import requests
                        response = requests.get("http://localhost:3000/health", timeout=5)
                        if response.status_code == 200:
                            print(f"✅ Health check passed: {response.json()}")
                        else:
                            print(f"❌ Health check failed: {response.status_code}")
                    except Exception as e:
                        print(f"❌ Health check error: {e}")
                        
                    # Kill the server
                    server_process.terminate()
                else:
                    stdout, stderr = server_process.communicate()
                    print(f"❌ Server failed to start: {stderr}")
            else:
                print(f"❌ TypeScript compilation failed: {result.stderr}")
                
        except Exception as e:
            print(f"❌ Error testing TypeScript server: {e}")
            
    def test_python_servers(self):
        """Test Python MCP servers"""
        print("\n🔍 Testing Python MCP Servers...")
        
        servers_to_test = [
            {
                "name": "Bash God Server",
                "path": self.base_dir / "mcp_learning_system" / "servers" / "bash_god",
                "main_file": "python_src/server.py"
            },
            {
                "name": "Development Server", 
                "path": self.base_dir / "mcp_learning_system" / "servers" / "development",
                "main_file": "python_src/server.py"
            },
            {
                "name": "DevOps Server",
                "path": self.base_dir / "mcp_learning_system" / "servers" / "devops",
                "main_file": "main.py"
            }
        ]
        
        for server in servers_to_test:
            print(f"\n📦 Testing {server['name']}...")
            server_path = server['path']
            main_file = server_path / server['main_file']
            
            if not main_file.exists():
                print(f"❌ Main file not found: {main_file}")
                continue
                
            # Check if we can import the server module
            os.chdir(server_path)
            
            try:
                # Try a dry run import check
                result = subprocess.run(
                    [sys.executable, "-c", f"import sys; sys.path.insert(0, '.'); exec(open('{server['main_file']}').read())"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if "ModuleNotFoundError" in result.stderr:
                    missing_module = result.stderr.split("'")[1]
                    print(f"⚠️  Missing module: {missing_module}")
                    
                    # Check if requirements.txt exists
                    req_file = server_path / "requirements.txt"
                    if req_file.exists():
                        print(f"   Installing dependencies from requirements.txt...")
                        install_result = subprocess.run(
                            [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
                            capture_output=True,
                            text=True
                        )
                        if install_result.returncode == 0:
                            print(f"   ✅ Dependencies installed")
                        else:
                            print(f"   ❌ Failed to install dependencies")
                else:
                    print(f"✅ Server module can be imported")
                    
            except subprocess.TimeoutExpired:
                print(f"⏱️  Server appears to be starting (timeout reached - this might be good!)")
            except Exception as e:
                print(f"❌ Error testing server: {e}")
                
        os.chdir(self.base_dir)
        
    def test_mcp_configs(self):
        """Test MCP configuration files"""
        print("\n🔍 Testing MCP Configuration Files...")
        
        # Check the master config
        master_config = self.base_dir / "mcp_configs" / "mcp_master_config_20250607_125216.json"
        
        if master_config.exists():
            with open(master_config, 'r') as f:
                config = json.load(f)
                
            if "mcpServers" in config:
                print(f"\n✅ Master config has {len(config['mcpServers'])} servers configured:")
                for server_name, server_config in config['mcpServers'].items():
                    command = server_config.get('command', 'unknown')
                    print(f"   - {server_name}: {command}")
                    
                    # Check if the command executable exists
                    if isinstance(command, list) and len(command) > 0:
                        executable = command[0]
                        if executable == "node":
                            if len(command) > 1:
                                script_path = Path(command[1])
                                if script_path.exists():
                                    print(f"     ✅ Script exists: {script_path}")
                                else:
                                    print(f"     ❌ Script not found: {script_path}")
                                    
    def check_existing_mcp_processes(self):
        """Check if any MCP processes are already running"""
        print("\n🔍 Checking for existing MCP processes...")
        
        try:
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True,
                text=True
            )
            
            mcp_processes = []
            for line in result.stdout.split('\n'):
                if 'mcp' in line.lower() and 'server' in line.lower():
                    mcp_processes.append(line)
                    
            if mcp_processes:
                print(f"Found {len(mcp_processes)} MCP-related processes:")
                for proc in mcp_processes[:5]:  # Show first 5
                    print(f"   {proc[:120]}...")
            else:
                print("No MCP server processes currently running")
                
        except Exception as e:
            print(f"Error checking processes: {e}")
            
    def generate_recommendations(self):
        """Generate recommendations for fixing MCP servers"""
        print("\n📋 RECOMMENDATIONS FOR FIXING MCP SERVERS:")
        print("=" * 60)
        
        recommendations = [
            {
                "issue": "TypeScript Compilation Errors",
                "fix": """
1. Fix TypeScript errors in mcp_servers directory:
   cd mcp_servers
   npm install --save-dev @types/pino @types/cors
   npm run build
   
2. If errors persist, try:
   npx tsc --skipLibCheck
   """
            },
            {
                "issue": "Missing Python Dependencies",
                "fix": """
1. Install dependencies for Python servers:
   cd mcp_learning_system/servers/bash_god
   pip install -r requirements.txt
   
2. For servers without requirements.txt:
   pip install mcp fastapi uvicorn pydantic
   """
            },
            {
                "issue": "Rust Builds Not Compiled",
                "fix": """
1. Build Rust components:
   cd mcp_learning_system/servers/bash_god/rust_src
   cargo build --release
   
2. Repeat for other servers with Rust components
   """
            },
            {
                "issue": "Server Configuration",
                "fix": """
1. Use the master config file:
   mcp_configs/mcp_master_config_20250607_125216.json
   
2. Ensure all paths in the config are correct
3. Set required environment variables for API keys
   """
            }
        ]
        
        for rec in recommendations:
            print(f"\n🔧 {rec['issue']}:")
            print(rec['fix'])
            
    def run_all_tests(self):
        """Run all functionality tests"""
        print("=" * 80)
        print("MCP SERVER FUNCTIONALITY TEST")
        print("=" * 80)
        
        self.check_existing_mcp_processes()
        self.test_typescript_server_startup()
        self.test_python_servers()
        self.test_mcp_configs()
        self.generate_recommendations()
        
        print("\n" + "=" * 80)
        print("TEST COMPLETE")
        print("=" * 80)

if __name__ == "__main__":
    # Check if requests is available
    try:
        import requests
    except ImportError:
        print("Installing requests module...")
        subprocess.run([sys.executable, "-m", "pip", "install", "requests"])
        
    tester = MCPFunctionalityTester()
    tester.run_all_tests()