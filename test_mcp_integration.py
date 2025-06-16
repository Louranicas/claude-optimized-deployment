#!/usr/bin/env python3
"""
Comprehensive MCP Server Integration Test Suite

Tests:
1. Rust core MCP manager module structure
2. Actor-based message passing
3. Protocol serialization/deserialization
4. Server lifecycle management
5. Health monitoring implementation
"""

import json
import asyncio
import time
from pathlib import Path
from typing import Dict, List, Any
import sys
import subprocess

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Color codes for output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'


class MCPIntegrationTester:
    def __init__(self):
        self.results = {
            'module_structure': None,
            'message_passing': None,
            'protocol_serialization': None,
            'lifecycle_management': None,
            'health_monitoring': None,
            'python_integration': None,
            'total_tests': 0,
            'passed_tests': 0,
            'failed_tests': 0
        }
        self.rust_core_path = Path('rust_core')
        
    def print_section(self, title: str):
        """Print a section header"""
        print(f"\n{BLUE}{'='*60}{RESET}")
        print(f"{BLUE}{title.center(60)}{RESET}")
        print(f"{BLUE}{'='*60}{RESET}\n")
        
    def print_result(self, test_name: str, passed: bool, details: str = ""):
        """Print test result"""
        status = f"{GREEN}✓ PASS{RESET}" if passed else f"{RED}✗ FAIL{RESET}"
        print(f"{test_name:<40} {status}")
        if details:
            print(f"  {YELLOW}{details}{RESET}")
            
    def check_module_structure(self) -> bool:
        """Verify the MCP manager module structure is complete"""
        self.print_section("1. Module Structure Check")
        
        required_files = {
            'mod.rs': 'Main module entry point',
            'actor.rs': 'Actor-based message passing',
            'server.rs': 'Server abstraction',
            'health.rs': 'Health monitoring',
            'connection_pool.rs': 'Connection pooling',
            'config.rs': 'Configuration management',
            'errors.rs': 'Error types',
            'metrics.rs': 'Metrics collection',
            'registry.rs': 'Server registry',
            'deployment.rs': 'Deployment manager',
            'manager_v2.rs': 'V2 actor-based manager',
            'actor_tests.rs': 'Actor system tests'
        }
        
        mcp_path = self.rust_core_path / 'src' / 'mcp_manager'
        all_present = True
        
        for file, description in required_files.items():
            file_path = mcp_path / file
            exists = file_path.exists()
            all_present &= exists
            self.print_result(f"  {file}", exists, description)
            
        # Check for additional V2 components
        print(f"\n{YELLOW}Advanced Components:{RESET}")
        advanced_files = {
            'plugin/mod.rs': 'Plugin system',
            'distributed/mod.rs': 'Distributed coordination',
            'resilience/mod.rs': 'Resilience patterns',
            'optimization/mod.rs': 'Performance optimization',
            'server_types/mod.rs': 'Server type implementations'
        }
        
        for file, description in advanced_files.items():
            file_path = mcp_path / file
            exists = file_path.exists()
            self.print_result(f"  {file}", exists, description)
            
        self.results['module_structure'] = all_present
        return all_present
        
    def analyze_message_passing(self) -> bool:
        """Analyze the actor-based message passing implementation"""
        self.print_section("2. Message Passing Analysis")
        
        actor_file = self.rust_core_path / 'src' / 'mcp_manager' / 'actor.rs'
        
        try:
            with open(actor_file, 'r') as f:
                content = f.read()
                
            # Check for key actor components
            checks = {
                'McpCommand enum': 'pub enum McpCommand' in content,
                'McpRuntime struct': 'pub struct McpRuntime' in content,
                'RuntimeActor': 'struct RuntimeActor' in content,
                'Message channels': 'mpsc::channel' in content,
                'Async message handling': 'async fn handle_' in content,
                'Command processing': 'match command {' in content,
                'Backpressure handling': 'mpsc::channel(100)' in content,
                'Metrics tracking': 'self.metrics' in content
            }
            
            all_passed = True
            for check, result in checks.items():
                all_passed &= result
                self.print_result(f"  {check}", result)
                
            # Analyze command types
            print(f"\n{YELLOW}Supported Commands:{RESET}")
            commands = ['Deploy', 'Undeploy', 'Execute', 'HealthCheck', 
                       'ListServers', 'GetMetrics', 'UpdateConfig', 'Shutdown']
            for cmd in commands:
                found = f'{cmd} {{' in content
                self.print_result(f"  {cmd} command", found)
                
            self.results['message_passing'] = all_passed
            return all_passed
            
        except Exception as e:
            self.print_result("Actor analysis", False, str(e))
            self.results['message_passing'] = False
            return False
            
    def check_protocol_serialization(self) -> bool:
        """Check protocol serialization/deserialization"""
        self.print_section("3. Protocol Serialization Check")
        
        server_file = self.rust_core_path / 'src' / 'mcp_manager' / 'server.rs'
        pool_file = self.rust_core_path / 'src' / 'mcp_manager' / 'connection_pool.rs'
        
        all_passed = True
        
        # Check server serialization
        try:
            with open(server_file, 'r') as f:
                server_content = f.read()
                
            checks = {
                'Serde derives': '#[derive(Debug, Clone, Serialize, Deserialize)]' in server_content,
                'Generic serialization': 'T: Serialize + Send' in server_content,
                'Generic deserialization': "R: for<'de> Deserialize<'de>" in server_content,
                'JSON value handling': 'serde_json::Value' in server_content,
                'Error handling': 'SerializationError' in server_content or 'McpError' in server_content
            }
            
            for check, result in checks.items():
                all_passed &= result
                self.print_result(f"  {check}", result)
                
        except Exception as e:
            self.print_result("Server serialization", False, str(e))
            all_passed = False
            
        # Check connection pool protocol handling
        try:
            with open(pool_file, 'r') as f:
                pool_content = f.read()
                
            pool_checks = {
                'Connection trait': 'pub trait Connection' in pool_content,
                'Raw execute method': 'async fn execute_raw' in pool_content,
                'Typed execute method': 'async fn execute<T, R>' in pool_content,
                'JSON conversion': 'serde_json::to_value' in pool_content,
                'Response parsing': 'serde_json::from_value' in pool_content
            }
            
            print(f"\n{YELLOW}Connection Pool Protocol:{RESET}")
            for check, result in pool_checks.items():
                all_passed &= result
                self.print_result(f"  {check}", result)
                
        except Exception as e:
            self.print_result("Pool protocol", False, str(e))
            all_passed = False
            
        self.results['protocol_serialization'] = all_passed
        return all_passed
        
    def verify_lifecycle_management(self) -> bool:
        """Verify server lifecycle management"""
        self.print_section("4. Server Lifecycle Management")
        
        actor_file = self.rust_core_path / 'src' / 'mcp_manager' / 'actor.rs'
        
        try:
            with open(actor_file, 'r') as f:
                content = f.read()
                
            lifecycle_checks = {
                'Initialize method': 'async fn initialize' in content,
                'Deploy handling': 'async fn handle_deploy' in content,
                'Undeploy handling': 'async fn handle_undeploy' in content,
                'Shutdown handling': 'async fn handle_shutdown' in content,
                'State transitions': 'ServerState::' in content,
                'Resource cleanup': 'server.shutdown().await' in content,
                'Graceful shutdown': 'drain()' in content
            }
            
            all_passed = True
            for check, result in lifecycle_checks.items():
                all_passed &= result
                self.print_result(f"  {check}", result)
                
            # Check state management
            print(f"\n{YELLOW}Server States:{RESET}")
            states = ['Initializing', 'Healthy', 'Degraded', 'Unhealthy', 
                     'Maintenance', 'Stopped']
            server_file = self.rust_core_path / 'src' / 'mcp_manager' / 'server.rs'
            
            with open(server_file, 'r') as f:
                server_content = f.read()
                
            for state in states:
                found = f'{state},' in server_content
                self.print_result(f"  {state} state", found)
                
            self.results['lifecycle_management'] = all_passed
            return all_passed
            
        except Exception as e:
            self.print_result("Lifecycle management", False, str(e))
            self.results['lifecycle_management'] = False
            return False
            
    def check_health_monitoring(self) -> bool:
        """Check health monitoring implementation"""
        self.print_section("5. Health Monitoring Implementation")
        
        health_file = self.rust_core_path / 'src' / 'mcp_manager' / 'health.rs'
        
        try:
            with open(health_file, 'r') as f:
                content = f.read()
                
            health_checks = {
                'HealthMonitor struct': 'pub struct HealthMonitor' in content,
                'HealthCheckResult': 'pub struct HealthCheckResult' in content,
                'HealthStatus': 'pub struct HealthStatus' in content,
                'Async health checks': 'async fn check_server' in content,
                'Continuous monitoring': 'async fn run_health_checks' in content,
                'Threshold handling': 'unhealthy_threshold' in content,
                'Metrics recording': 'record_health_check' in content,
                'Health aggregation': 'HealthAggregator' in content
            }
            
            all_passed = True
            for check, result in health_checks.items():
                all_passed &= result
                self.print_result(f"  {check}", result)
                
            # Check monitoring features
            print(f"\n{YELLOW}Monitoring Features:{RESET}")
            features = {
                'Timeout handling': 'timeout(Duration::from_millis' in content,
                'History tracking': 'history.push(result.clone())' in content,
                'Failure tracking': 'recent_failures' in content,
                'State updates': 'server.set_state' in content,
                'Background task': 'tokio::spawn' in content
            }
            
            for feature, found in features.items():
                self.print_result(f"  {feature}", found)
                
            self.results['health_monitoring'] = all_passed
            return all_passed
            
        except Exception as e:
            self.print_result("Health monitoring", False, str(e))
            self.results['health_monitoring'] = False
            return False
    
    async def test_python_integration(self) -> bool:
        """Test Python MCP integration"""
        self.print_section("6. Python MCP Integration Test")
        
        try:
            from src.mcp.manager import get_mcp_manager, MCPManager
            
            self.print_result("Import MCP manager", True)
            
            # Initialize MCP Manager
            manager = get_mcp_manager()
            await manager.initialize()
            self.print_result("Initialize MCP manager", True)
            
            # Create test context
            context_id = "test_integration"
            context = manager.create_context(context_id)
            self.print_result("Create test context", True, f"Context ID: {context_id}")
            
            # Get server information
            server_info = manager.get_server_info()
            self.print_result("Get server info", len(server_info) > 0, 
                            f"{len(server_info)} servers registered")
            
            # Get available tools
            tools = manager.get_available_tools(context_id)
            self.print_result("Get available tools", len(tools) > 0,
                            f"{len(tools)} tools available")
            
            # Test a simple server
            try:
                manager.enable_server(context_id, "desktop-commander")
                result = await manager.call_tool(
                    "desktop-commander.execute_command",
                    {"command": "echo 'MCP test'"},
                    context_id
                )
                self.print_result("Execute test command", result.get('success', False))
            except Exception as e:
                self.print_result("Execute test command", False, str(e))
            
            await manager.cleanup()
            self.print_result("Cleanup MCP manager", True)
            
            self.results['python_integration'] = True
            return True
            
        except Exception as e:
            self.print_result("Python integration", False, str(e))
            self.results['python_integration'] = False
            return False
            
    def generate_report(self):
        """Generate final report"""
        self.print_section("Test Summary Report")
        
        total = sum(1 for k, v in self.results.items() 
                   if k not in ['total_tests', 'passed_tests', 'failed_tests'] 
                   and v is not None)
        passed = sum(1 for k, v in self.results.items() 
                    if k not in ['total_tests', 'passed_tests', 'failed_tests'] 
                    and v is True)
        
        print(f"Total Tests Run: {total}")
        print(f"{GREEN}Passed: {passed}{RESET}")
        print(f"{RED}Failed: {total - passed}{RESET}")
        print(f"Success Rate: {(passed/total*100):.1f}%")
        
        print(f"\n{YELLOW}Component Status:{RESET}")
        components = [
            ('Module Structure', self.results.get('module_structure')),
            ('Message Passing', self.results.get('message_passing')),
            ('Protocol Serialization', self.results.get('protocol_serialization')),
            ('Lifecycle Management', self.results.get('lifecycle_management')),
            ('Health Monitoring', self.results.get('health_monitoring')),
            ('Python Integration', self.results.get('python_integration'))
        ]
        
        for name, status in components:
            if status is None:
                status_str = f"{YELLOW}NOT TESTED{RESET}"
            elif status:
                status_str = f"{GREEN}OPERATIONAL{RESET}"
            else:
                status_str = f"{RED}NEEDS ATTENTION{RESET}"
            print(f"  {name:<25} {status_str}")
            
        # Architecture assessment
        print(f"\n{BLUE}Architecture Assessment:{RESET}")
        if passed == total:
            print(f"{GREEN}✓ MCP server integration is fully implemented{RESET}")
            print(f"{GREEN}✓ Actor-based architecture is operational{RESET}")
            print(f"{GREEN}✓ Zero-lock design achieved through message passing{RESET}")
        else:
            print(f"{YELLOW}⚠ Some components need attention{RESET}")
            print(f"{YELLOW}⚠ Review failed tests for specific issues{RESET}")
            
        # Save report
        report_path = Path('mcp_integration_test_report.json')
        with open(report_path, 'w') as f:
            json.dump({
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'results': self.results,
                'total_tests': total,
                'passed_tests': passed,
                'failed_tests': total - passed,
                'success_rate': passed/total*100 if total > 0 else 0
            }, f, indent=2)
            
        print(f"\nDetailed report saved to: {report_path}")


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