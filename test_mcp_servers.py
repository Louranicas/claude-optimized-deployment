#!/usr/bin/env python3
"""
MCP Server Testing Suite
Tests individual MCP servers and validates their functionality.
"""

import asyncio
import logging
import sys
import traceback
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

from src.mcp.servers import MCPServerRegistry
from src.auth.rbac import RBACManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class ServerTestResult:
    """Result of server testing."""
    server_name: str
    success: bool
    tests_run: int
    tests_passed: int
    duration: float
    errors: List[str]
    warnings: List[str]


class MCPServerTester:
    """Tests MCP servers individually with comprehensive validation."""
    
    def __init__(self):
        """Initialize the MCP server tester."""
        self.registry = None
        self.rbac_manager = None
        self.test_results: List[ServerTestResult] = []
    
    async def initialize(self):
        """Initialize testing dependencies."""
        logger.info("Initializing MCP server testing environment...")
        
        try:
            # Create RBAC manager for permission testing
            self.rbac_manager = RBACManager()
            
            # Create registry with mock permission checker
            class MockPermissionChecker:
                def check_permission(self, user, resource, action):
                    return True
            
            mock_checker = MockPermissionChecker()
            self.registry = MCPServerRegistry(mock_checker)
            
            logger.info("✓ Testing environment initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize testing environment: {e}")
            raise
    
    async def test_server_infrastructure(self, server_name: str) -> Tuple[List[str], List[str]]:
        """Test basic server infrastructure."""
        errors = []
        warnings = []
        
        try:
            server = self.registry.get(server_name)
            if not server:
                errors.append(f"Server {server_name} not found in registry")
                return errors, warnings
            
            # Test server info
            try:
                server_info = server.get_server_info()
                if not server_info:
                    errors.append("get_server_info() returned None")
                else:
                    if not hasattr(server_info, 'name') or not server_info.name:
                        warnings.append("Server info missing name")
                    if not hasattr(server_info, 'version') or not server_info.version:
                        warnings.append("Server info missing version")
                    if not hasattr(server_info, 'capabilities'):
                        warnings.append("Server info missing capabilities")
            except Exception as e:
                errors.append(f"get_server_info() failed: {e}")
            
            # Test tools listing
            try:
                tools = server.get_tools()
                if not isinstance(tools, list):
                    errors.append("get_tools() did not return a list")
                elif len(tools) == 0:
                    warnings.append("Server has no tools")
                else:
                    # Validate tool structure
                    for i, tool in enumerate(tools):
                        if not hasattr(tool, 'name'):
                            errors.append(f"Tool {i} missing name")
                        if not hasattr(tool, 'description'):
                            warnings.append(f"Tool {i} missing description")
                        if not hasattr(tool, 'parameters'):
                            warnings.append(f"Tool {i} missing parameters")
            except Exception as e:
                errors.append(f"get_tools() failed: {e}")
            
            # Test tool call interface
            try:
                if hasattr(server, 'call_tool'):
                    # This is a basic interface test, not actual tool execution
                    pass
                else:
                    warnings.append("Server missing call_tool method")
            except Exception as e:
                warnings.append(f"Tool call interface issue: {e}")
            
        except Exception as e:
            errors.append(f"Infrastructure test failed: {e}")
        
        return errors, warnings
    
    async def test_server_security(self, server_name: str) -> Tuple[List[str], List[str]]:
        """Test server security features."""
        errors = []
        warnings = []
        
        try:
            server = self.registry.get(server_name)
            if not server:
                return ["Server not found"], []
            
            # Check for permission checker integration
            if not hasattr(server, 'permission_checker'):
                warnings.append("Server missing permission checker")
            
            # Check for tool permissions
            if hasattr(server, 'tool_permissions'):
                if not server.tool_permissions:
                    warnings.append("Server has no tool permissions defined")
            else:
                warnings.append("Server missing tool_permissions attribute")
            
            # Check for authentication integration
            if hasattr(server, '_call_tool_impl'):
                # Server has authentication-aware implementation
                pass
            else:
                warnings.append("Server may not have authentication integration")
            
        except Exception as e:
            errors.append(f"Security test failed: {e}")
        
        return errors, warnings
    
    async def test_server_dependencies(self, server_name: str) -> Tuple[List[str], List[str]]:
        """Test server dependencies and requirements."""
        errors = []
        warnings = []
        
        try:
            server = self.registry.get(server_name)
            if not server:
                return ["Server not found"], []
            
            # Test specific server dependencies
            if server_name == "docker":
                # Test Docker availability
                try:
                    import subprocess
                    result = subprocess.run(['docker', '--version'], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode != 0:
                        warnings.append("Docker not available on system")
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    warnings.append("Docker not found or not responding")
                except Exception as e:
                    warnings.append(f"Docker check failed: {e}")
            
            elif server_name == "kubernetes":
                # Test kubectl availability
                try:
                    import subprocess
                    result = subprocess.run(['kubectl', 'version', '--client'], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode != 0:
                        warnings.append("kubectl not available on system")
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    warnings.append("kubectl not found or not responding")
                except Exception as e:
                    warnings.append(f"kubectl check failed: {e}")
            
            elif server_name == "prometheus-monitoring":
                # Test if aiohttp is available
                try:
                    import aiohttp
                except ImportError:
                    errors.append("aiohttp required for Prometheus server")
            
            elif server_name == "brave":
                # Test if required environment variables are documented
                if not hasattr(server, 'api_key') or not server.api_key:
                    warnings.append("Brave API key not configured (BRAVE_API_KEY)")
            
        except Exception as e:
            errors.append(f"Dependency test failed: {e}")
        
        return errors, warnings
    
    async def test_single_server(self, server_name: str) -> ServerTestResult:
        """Test a single MCP server comprehensively."""
        logger.info(f"Testing MCP server: {server_name}")
        start_time = time.time()
        
        all_errors = []
        all_warnings = []
        tests_run = 0
        tests_passed = 0
        
        # Test infrastructure
        try:
            tests_run += 1
            errors, warnings = await self.test_server_infrastructure(server_name)
            all_errors.extend(errors)
            all_warnings.extend(warnings)
            if not errors:
                tests_passed += 1
                logger.debug(f"  ✓ {server_name} infrastructure tests passed")
            else:
                logger.warning(f"  ! {server_name} infrastructure tests failed")
        except Exception as e:
            all_errors.append(f"Infrastructure test exception: {e}")
        
        # Test security
        try:
            tests_run += 1
            errors, warnings = await self.test_server_security(server_name)
            all_errors.extend(errors)
            all_warnings.extend(warnings)
            if not errors:
                tests_passed += 1
                logger.debug(f"  ✓ {server_name} security tests passed")
            else:
                logger.warning(f"  ! {server_name} security tests failed")
        except Exception as e:
            all_errors.append(f"Security test exception: {e}")
        
        # Test dependencies
        try:
            tests_run += 1
            errors, warnings = await self.test_server_dependencies(server_name)
            all_errors.extend(errors)
            all_warnings.extend(warnings)
            if not errors:
                tests_passed += 1
                logger.debug(f"  ✓ {server_name} dependency tests passed")
            else:
                logger.warning(f"  ! {server_name} dependency tests failed")
        except Exception as e:
            all_errors.append(f"Dependency test exception: {e}")
        
        duration = time.time() - start_time
        success = len(all_errors) == 0
        
        result = ServerTestResult(
            server_name=server_name,
            success=success,
            tests_run=tests_run,
            tests_passed=tests_passed,
            duration=duration,
            errors=all_errors,
            warnings=all_warnings
        )
        
        if success:
            logger.info(f"  ✓ {server_name} all tests passed ({tests_passed}/{tests_run}) in {duration:.2f}s")
        else:
            logger.error(f"  ✗ {server_name} tests failed ({tests_passed}/{tests_run}) in {duration:.2f}s")
            for error in all_errors:
                logger.error(f"    - {error}")
        
        if all_warnings:
            for warning in all_warnings:
                logger.warning(f"    ⚠ {warning}")
        
        return result
    
    async def test_all_servers(self):
        """Test all registered MCP servers."""
        logger.info("🧪 Starting comprehensive MCP server testing")
        
        try:
            await self.initialize()
            
            # Get all server names
            server_names = self.registry.list_servers()
            logger.info(f"Found {len(server_names)} servers to test: {', '.join(server_names)}")
            
            # Test each server
            for server_name in server_names:
                try:
                    result = await self.test_single_server(server_name)
                    self.test_results.append(result)
                except Exception as e:
                    logger.error(f"Failed to test {server_name}: {e}")
                    logger.debug(f"Stack trace: {traceback.format_exc()}")
                    
                    # Create failed result
                    self.test_results.append(ServerTestResult(
                        server_name=server_name,
                        success=False,
                        tests_run=0,
                        tests_passed=0,
                        duration=0.0,
                        errors=[f"Test execution failed: {e}"],
                        warnings=[]
                    ))
            
            # Generate summary
            self.print_test_summary()
            
        except Exception as e:
            logger.error(f"💥 Testing framework failed: {e}")
            logger.debug(f"Stack trace: {traceback.format_exc()}")
            raise
    
    def print_test_summary(self):
        """Print comprehensive test summary."""
        successful_tests = [r for r in self.test_results if r.success]
        failed_tests = [r for r in self.test_results if not r.success]
        
        total_duration = sum(r.duration for r in self.test_results)
        total_tests_run = sum(r.tests_run for r in self.test_results)
        total_tests_passed = sum(r.tests_passed for r in self.test_results)
        
        logger.info("")
        logger.info("📊 MCP Server Testing Summary")
        logger.info("=" * 50)
        logger.info(f"Total Servers: {len(self.test_results)}")
        logger.info(f"Successful: {len(successful_tests)}")
        logger.info(f"Failed: {len(failed_tests)}")
        logger.info(f"Success Rate: {len(successful_tests)/len(self.test_results)*100:.1f}%")
        logger.info(f"Total Duration: {total_duration:.2f}s")
        logger.info(f"Total Tests: {total_tests_passed}/{total_tests_run} passed")
        logger.info("")
        
        if successful_tests:
            logger.info("✅ Successful Servers:")
            for result in successful_tests:
                logger.info(f"  - {result.server_name}: {result.tests_passed}/{result.tests_run} tests passed")
        
        if failed_tests:
            logger.info("")
            logger.info("❌ Failed Servers:")
            for result in failed_tests:
                logger.info(f"  - {result.server_name}: {len(result.errors)} errors")
                for error in result.errors[:3]:  # Show first 3 errors
                    logger.info(f"    • {error}")
                if len(result.errors) > 3:
                    logger.info(f"    • ... and {len(result.errors) - 3} more errors")
        
        # Overall assessment
        logger.info("")
        if len(failed_tests) == 0:
            logger.info("🎉 All MCP servers passed testing!")
        elif len(failed_tests) < len(self.test_results) / 2:
            logger.info("⚠️  Most servers passed - review failed servers")
        else:
            logger.info("💥 Many servers failed - significant issues detected")


async def main():
    """Main testing entry point."""
    tester = MCPServerTester()
    
    try:
        await tester.test_all_servers()
        
        # Exit with appropriate code
        failed_count = len([r for r in tester.test_results if not r.success])
        if failed_count > 0:
            logger.warning(f"Testing completed with {failed_count} failures")
            sys.exit(1)
        else:
            logger.info("🎉 All servers passed testing!")
            sys.exit(0)
            
    except Exception as e:
        logger.error(f"💥 Testing framework failed: {e}")
        sys.exit(2)


if __name__ == "__main__":
    # Run the tests
    asyncio.run(main())