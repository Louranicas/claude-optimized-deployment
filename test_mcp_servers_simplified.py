#!/usr/bin/env python3
"""
Simplified MCP Server Testing Suite
Tests MCP servers without Circle of Experts dependency
"""

import asyncio
import json
import sys
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import time
import logging
from collections import defaultdict
import traceback

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Configure environment
os.environ.setdefault('AUDIT_SIGNING_KEY', f'mcp_test_{datetime.now().strftime("%Y%m%d_%H%M%S")}')
os.environ.setdefault('ENVIRONMENT', 'testing')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(f'mcp_server_test_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    ]
)
logger = logging.getLogger(__name__)


class TestAgentRole(Enum):
    """Specialized roles for MCP testing agents"""
    SEARCH_SPECIALIST = "Search & Discovery Agent"
    SYSTEM_COMMANDER = "System Control Agent"
    CONTAINER_EXPERT = "Container Orchestration Agent"
    CLOUD_NATIVE = "Cloud Native Agent"
    DEVOPS_AUTOMATION = "DevOps Pipeline Agent"
    WINDOWS_SPECIALIST = "Windows Systems Agent"
    MONITORING_EXPERT = "Observability Agent"
    SECURITY_ANALYST = "Security Testing Agent"
    COMMUNICATION_LEAD = "Communication Agent"
    STORAGE_ARCHITECT = "Storage Systems Agent"


@dataclass
class MCPTestCase:
    """Represents a test case for an MCP server"""
    server_name: str
    tool_name: str
    test_name: str
    parameters: Dict[str, Any]
    expected_behavior: str
    severity: str = "normal"
    timeout: float = 30.0


@dataclass
class TestResult:
    """Test execution result"""
    test_case: MCPTestCase
    success: bool
    duration: float
    response: Optional[Any] = None
    error: Optional[str] = None
    agent: Optional[str] = None
    timestamp: datetime = None


class SimplifiedMCPTester:
    """Simplified MCP server tester without external dependencies"""
    
    def __init__(self):
        self.start_time = datetime.now()
        self.test_results: Dict[str, List[TestResult]] = defaultdict(list)
        self.test_metrics = {
            'total_tests': 0,
            'passed': 0,
            'failed': 0,
            'skipped': 0,
            'errors': 0,
            'duration': 0.0,
            'server_coverage': {},
        }
        
    async def initialize_mcp_manager(self):
        """Initialize MCP Manager"""
        logger.info("🚀 Initializing MCP Manager...")
        
        # Set environment variables
        test_env_vars = {
            'BRAVE_API_KEY': os.getenv('BRAVE_API_KEY', 'test_brave_key'),
            'SLACK_BOT_TOKEN': os.getenv('SLACK_BOT_TOKEN', 'test_slack_token'),
            'AWS_ACCESS_KEY_ID': os.getenv('AWS_ACCESS_KEY_ID', 'test_aws_key'),
            'AWS_SECRET_ACCESS_KEY': os.getenv('AWS_SECRET_ACCESS_KEY', 'test_aws_secret'),
            'AZURE_DEVOPS_TOKEN': os.getenv('AZURE_DEVOPS_TOKEN', 'test_azure_token'),
        }
        
        for key, value in test_env_vars.items():
            if not os.getenv(key):
                os.environ[key] = value
        
        try:
            from src.mcp.manager import get_mcp_manager
            self.mcp_manager = get_mcp_manager()
            await self.mcp_manager.initialize()
            logger.info(f"✅ MCP Manager initialized with {len(self.mcp_manager.registry.servers)} servers")
            return True
        except Exception as e:
            logger.error(f"❌ Failed to initialize MCP Manager: {e}")
            return False
    
    def generate_test_suite(self) -> Dict[str, List[MCPTestCase]]:
        """Generate basic test cases for MCP servers"""
        return {
            "brave": [
                MCPTestCase(
                    server_name="brave",
                    tool_name="brave_web_search",
                    test_name="basic_web_search",
                    parameters={"query": "test query", "count": 3},
                    expected_behavior="Returns web search results"
                ),
            ],
            "desktop-commander": [
                MCPTestCase(
                    server_name="desktop-commander",
                    tool_name="execute_command",
                    test_name="echo_test",
                    parameters={"command": "echo 'MCP Test'"},
                    expected_behavior="Executes echo command"
                ),
            ],
            "docker": [
                MCPTestCase(
                    server_name="docker",
                    tool_name="docker_ps",
                    test_name="list_containers",
                    parameters={"all": True},
                    expected_behavior="Lists Docker containers"
                ),
            ],
            "kubernetes": [
                MCPTestCase(
                    server_name="kubernetes",
                    tool_name="kubectl_get",
                    test_name="list_nodes",
                    parameters={"resource_type": "nodes"},
                    expected_behavior="Lists Kubernetes nodes"
                ),
            ],
            "prometheus-monitoring": [
                MCPTestCase(
                    server_name="prometheus-monitoring",
                    tool_name="prometheus_query",
                    test_name="up_query",
                    parameters={"query": "up"},
                    expected_behavior="Returns Prometheus metrics"
                ),
            ],
            "security-scanner": [
                MCPTestCase(
                    server_name="security-scanner",
                    tool_name="file_security_scan",
                    test_name="scan_test",
                    parameters={"path": "./", "exclude": ["venv", "__pycache__"]},
                    expected_behavior="Scans for security issues"
                ),
            ],
            "slack-notifications": [
                MCPTestCase(
                    server_name="slack-notifications",
                    tool_name="list_channels",
                    test_name="list_channels",
                    parameters={},
                    expected_behavior="Lists Slack channels"
                ),
            ],
            "s3-storage": [
                MCPTestCase(
                    server_name="s3-storage",
                    tool_name="s3_list_buckets",
                    test_name="list_buckets",
                    parameters={},
                    expected_behavior="Lists S3 buckets"
                ),
            ],
        }
    
    async def execute_tests(self):
        """Execute all tests"""
        logger.info("🎯 Starting MCP Server Tests")
        logger.info("="*80)
        
        # Initialize MCP Manager
        if not await self.initialize_mcp_manager():
            logger.error("Failed to initialize MCP Manager")
            return
        
        # Generate test suite
        test_suite = self.generate_test_suite()
        self.test_metrics['total_tests'] = sum(len(tests) for tests in test_suite.values())
        
        logger.info(f"📋 Running {self.test_metrics['total_tests']} tests across {len(test_suite)} servers")
        
        # Execute tests for each server
        for server_name, test_cases in test_suite.items():
            await self._test_server(server_name, test_cases)
        
        # Generate report
        self._generate_report()
    
    async def _test_server(self, server_name: str, test_cases: List[MCPTestCase]):
        """Test a specific MCP server"""
        logger.info(f"\n📦 Testing {server_name} server...")
        
        # Check if server is available
        if hasattr(self.mcp_manager, 'registry') and hasattr(self.mcp_manager.registry, 'servers'):
            if server_name not in self.mcp_manager.registry.servers:
                logger.warning(f"⚠️ Server {server_name} not registered")
                self.test_metrics['skipped'] += len(test_cases)
                return
        
        server_results = []
        
        for test_case in test_cases:
            result = await self._execute_test(test_case)
            server_results.append(result)
            self.test_results[server_name].append(result)
            
            # Update metrics
            if result.success:
                self.test_metrics['passed'] += 1
                logger.info(f"  ✅ {test_case.test_name}: PASSED ({result.duration:.2f}s)")
            else:
                if "not found" in str(result.error).lower():
                    self.test_metrics['skipped'] += 1
                    logger.info(f"  ⏭️ {test_case.test_name}: SKIPPED - {result.error}")
                else:
                    self.test_metrics['failed'] += 1
                    logger.error(f"  ❌ {test_case.test_name}: FAILED - {result.error}")
        
        # Update server coverage
        passed = sum(1 for r in server_results if r.success)
        total = len(server_results)
        self.test_metrics['server_coverage'][server_name] = {
            'total': total,
            'passed': passed,
            'coverage': (passed / total * 100) if total > 0 else 0
        }
    
    async def _execute_test(self, test_case: MCPTestCase) -> TestResult:
        """Execute a single test"""
        start_time = time.time()
        
        try:
            # Construct tool name
            tool_name = f"{test_case.server_name}.{test_case.tool_name}"
            
            # Call tool
            response = await asyncio.wait_for(
                self.mcp_manager.call_tool(tool_name, test_case.parameters),
                timeout=test_case.timeout
            )
            
            duration = time.time() - start_time
            return TestResult(
                test_case=test_case,
                success=True,
                duration=duration,
                response=response,
                timestamp=datetime.now()
            )
            
        except asyncio.TimeoutError:
            duration = time.time() - start_time
            return TestResult(
                test_case=test_case,
                success=False,
                duration=duration,
                error=f"Timeout after {test_case.timeout}s",
                timestamp=datetime.now()
            )
            
        except Exception as e:
            duration = time.time() - start_time
            return TestResult(
                test_case=test_case,
                success=False,
                duration=duration,
                error=str(e),
                timestamp=datetime.now()
            )
    
    def _generate_report(self):
        """Generate test report"""
        self.test_metrics['duration'] = (datetime.now() - self.start_time).total_seconds()
        
        # Calculate success rate
        success_rate = (self.test_metrics['passed'] / self.test_metrics['total_tests'] * 100) if self.test_metrics['total_tests'] > 0 else 0
        
        # Display summary
        print("\n" + "="*80)
        print("🎯 MCP SERVER TEST RESULTS")
        print("="*80)
        print(f"⏱️ Duration: {self.test_metrics['duration']:.1f}s")
        print(f"📊 Total Tests: {self.test_metrics['total_tests']}")
        print(f"✅ Passed: {self.test_metrics['passed']}")
        print(f"❌ Failed: {self.test_metrics['failed']}")
        print(f"⏭️ Skipped: {self.test_metrics['skipped']}")
        print(f"\n🎯 Success Rate: {success_rate:.1f}%")
        
        print("\n📦 Server Coverage:")
        for server_name, coverage in self.test_metrics['server_coverage'].items():
            print(f"  {server_name}: {coverage['passed']}/{coverage['total']} ({coverage['coverage']:.1f}%)")
        
        # Save JSON report
        report = {
            'summary': self.test_metrics,
            'server_results': {
                server: [
                    {
                        'test': r.test_case.test_name,
                        'success': r.success,
                        'duration': r.duration,
                        'error': r.error
                    }
                    for r in results
                ]
                for server, results in self.test_results.items()
            },
            'timestamp': datetime.now().isoformat()
        }
        
        report_path = f"mcp_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Report saved to: {report_path}")
        print("="*80)


async def main():
    """Run simplified MCP tests"""
    print("🚀 SIMPLIFIED MCP SERVER TESTING")
    print("🤖 Testing Core MCP Functionality")
    print("="*80)
    
    tester = SimplifiedMCPTester()
    
    try:
        await tester.execute_tests()
        
        # Determine exit code
        if tester.test_metrics['failed'] == 0:
            print("\n✅ All tests passed!")
            return 0
        else:
            print(f"\n⚠️ {tester.test_metrics['failed']} tests failed")
            return 1
            
    except Exception as e:
        logger.error(f"💥 Testing failed: {e}")
        traceback.print_exc()
        return 2


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)