#!/usr/bin/env python3
"""
Comprehensive MCP Server Testing Suite
Tests all 11 MCP servers with parallel execution using 10 agents
"""

import asyncio
import json
import sys
import os
from pathlib import Path
from datetime import datetime
import time
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
from collections import defaultdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(f'mcp_comprehensive_test_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    ]
)
logger = logging.getLogger(__name__)

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))


class TestAgent(Enum):
    """Testing agents specialized for different MCP servers"""
    SEARCH_AGENT = "Search Testing Agent"
    SYSTEM_AGENT = "System Testing Agent"
    CONTAINER_AGENT = "Container Testing Agent"
    CLOUD_AGENT = "Cloud Testing Agent"
    DEVOPS_AGENT = "DevOps Testing Agent"
    WINDOWS_AGENT = "Windows Testing Agent"
    MONITORING_AGENT = "Monitoring Testing Agent"
    SECURITY_AGENT = "Security Testing Agent"
    COMMUNICATION_AGENT = "Communication Testing Agent"
    STORAGE_AGENT = "Storage Testing Agent"


@dataclass
class TestCase:
    """Test case definition"""
    server: str
    tool: str
    description: str
    params: Dict[str, Any]
    agent: TestAgent
    timeout: float = 30.0


@dataclass
class TestResult:
    """Test execution result"""
    test_case: TestCase
    success: bool
    duration: float
    output: Optional[Any] = None
    error: Optional[str] = None
    timestamp: datetime = None


class ComprehensiveMCPTester:
    """Comprehensive MCP testing orchestrator"""
    
    def __init__(self):
        self.start_time = datetime.now()
        self.results: Dict[str, List[TestResult]] = defaultdict(list)
        self.metrics = {
            'total_tests': 0,
            'passed': 0,
            'failed': 0,
            'errors': 0,
            'skipped': 0,
            'servers_tested': set(),
            'tools_tested': set(),
            'duration': 0.0
        }
        self.mcp_manager = None
        
    async def initialize_environment(self):
        """Initialize testing environment"""
        logger.info("🚀 Initializing MCP testing environment...")
        
        # Set environment variables for all services
        env_vars = {
            'ENVIRONMENT': 'testing',
            'AUDIT_SIGNING_KEY': f'test_{datetime.now().strftime("%Y%m%d_%H%M%S")}',
            'BRAVE_API_KEY': os.getenv('BRAVE_API_KEY', 'test_brave_key'),
            'SLACK_BOT_TOKEN': os.getenv('SLACK_BOT_TOKEN', 'test_slack_token'),
            'AWS_ACCESS_KEY_ID': os.getenv('AWS_ACCESS_KEY_ID', 'test_aws_key'),
            'AWS_SECRET_ACCESS_KEY': os.getenv('AWS_SECRET_ACCESS_KEY', 'test_aws_secret'),
            'AZURE_DEVOPS_TOKEN': os.getenv('AZURE_DEVOPS_TOKEN', 'test_azure_token'),
            'PROMETHEUS_URL': os.getenv('PROMETHEUS_URL', 'http://localhost:9090'),
        }
        
        for key, value in env_vars.items():
            os.environ[key] = value
        
        # Initialize MCP Manager
        try:
            from src.mcp.manager import get_mcp_manager
            self.mcp_manager = get_mcp_manager()
            await self.mcp_manager.initialize()
            
            # Get registered servers
            if hasattr(self.mcp_manager, 'registry') and hasattr(self.mcp_manager.registry, 'servers'):
                server_count = len(self.mcp_manager.registry.servers)
                logger.info(f"✅ MCP Manager initialized with {server_count} servers:")
                for server_name in self.mcp_manager.registry.servers:
                    logger.info(f"   📦 {server_name}")
            else:
                logger.warning("⚠️ MCP Manager initialized but no servers found")
                
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize MCP Manager: {e}")
            return False
    
    def create_test_suite(self) -> List[TestCase]:
        """Create comprehensive test suite for all MCP servers"""
        test_suite = []
        
        # Brave Search Server Tests
        test_suite.extend([
            TestCase(
                server="brave",
                tool="brave_web_search",
                description="Web search functionality",
                params={"query": "MCP testing framework", "count": 5},
                agent=TestAgent.SEARCH_AGENT
            ),
            TestCase(
                server="brave",
                tool="brave_news_search",
                description="News search functionality",
                params={"query": "technology news", "freshness": "pd"},
                agent=TestAgent.SEARCH_AGENT
            ),
            TestCase(
                server="brave",
                tool="brave_image_search",
                description="Image search functionality",
                params={"query": "kubernetes architecture"},
                agent=TestAgent.SEARCH_AGENT
            ),
        ])
        
        # Desktop Commander Server Tests
        test_suite.extend([
            TestCase(
                server="desktop-commander",
                tool="execute_command",
                description="Command execution",
                params={"command": "echo 'MCP Test Suite'"},
                agent=TestAgent.SYSTEM_AGENT
            ),
            TestCase(
                server="desktop-commander",
                tool="get_environment_info",
                description="Environment information",
                params={},
                agent=TestAgent.SYSTEM_AGENT
            ),
        ])
        
        # Docker Server Tests
        test_suite.extend([
            TestCase(
                server="docker",
                tool="docker_ps",
                description="List containers",
                params={"all": True},
                agent=TestAgent.CONTAINER_AGENT
            ),
            TestCase(
                server="docker",
                tool="docker_images",
                description="List images",
                params={},
                agent=TestAgent.CONTAINER_AGENT
            ),
            TestCase(
                server="docker",
                tool="docker_system_info",
                description="System information",
                params={},
                agent=TestAgent.CONTAINER_AGENT
            ),
        ])
        
        # Kubernetes Server Tests
        test_suite.extend([
            TestCase(
                server="kubernetes",
                tool="kubectl_get",
                description="List nodes",
                params={"resource_type": "nodes"},
                agent=TestAgent.CLOUD_AGENT
            ),
            TestCase(
                server="kubernetes",
                tool="kubectl_get",
                description="List pods",
                params={"resource_type": "pods", "namespace": "default"},
                agent=TestAgent.CLOUD_AGENT
            ),
            TestCase(
                server="kubernetes",
                tool="kubectl_describe",
                description="Describe service",
                params={"resource_type": "service", "name": "kubernetes"},
                agent=TestAgent.CLOUD_AGENT
            ),
        ])
        
        # Azure DevOps Server Tests
        test_suite.extend([
            TestCase(
                server="azure-devops",
                tool="list_projects",
                description="List projects",
                params={},
                agent=TestAgent.DEVOPS_AGENT
            ),
            TestCase(
                server="azure-devops",
                tool="list_pipelines",
                description="List pipelines",
                params={"project": "TestProject"},
                agent=TestAgent.DEVOPS_AGENT
            ),
        ])
        
        # Windows System Server Tests
        test_suite.extend([
            TestCase(
                server="windows-system",
                tool="system_info",
                description="System information",
                params={},
                agent=TestAgent.WINDOWS_AGENT
            ),
            TestCase(
                server="windows-system",
                tool="process_list",
                description="List processes",
                params={},
                agent=TestAgent.WINDOWS_AGENT
            ),
        ])
        
        # Prometheus Monitoring Server Tests
        test_suite.extend([
            TestCase(
                server="prometheus-monitoring",
                tool="prometheus_query",
                description="Execute query",
                params={"query": "up"},
                agent=TestAgent.MONITORING_AGENT
            ),
            TestCase(
                server="prometheus-monitoring",
                tool="prometheus_targets",
                description="List targets",
                params={"state": "active"},
                agent=TestAgent.MONITORING_AGENT
            ),
            TestCase(
                server="prometheus-monitoring",
                tool="prometheus_alerts",
                description="List alerts",
                params={},
                agent=TestAgent.MONITORING_AGENT
            ),
        ])
        
        # Security Scanner Server Tests
        test_suite.extend([
            TestCase(
                server="security-scanner",
                tool="file_security_scan",
                description="Security scan",
                params={"path": "./src", "exclude": ["__pycache__", "venv"]},
                agent=TestAgent.SECURITY_AGENT,
                timeout=60.0
            ),
            TestCase(
                server="security-scanner",
                tool="dependency_check",
                description="Dependency check",
                params={"file": "requirements.txt"},
                agent=TestAgent.SECURITY_AGENT
            ),
        ])
        
        # Slack Notifications Server Tests
        test_suite.extend([
            TestCase(
                server="slack-notifications",
                tool="list_channels",
                description="List channels",
                params={},
                agent=TestAgent.COMMUNICATION_AGENT
            ),
            TestCase(
                server="slack-notifications",
                tool="send_message",
                description="Send message",
                params={"channel": "#test", "text": "MCP Test Message"},
                agent=TestAgent.COMMUNICATION_AGENT
            ),
        ])
        
        # S3 Storage Server Tests
        test_suite.extend([
            TestCase(
                server="s3-storage",
                tool="s3_list_buckets",
                description="List buckets",
                params={},
                agent=TestAgent.STORAGE_AGENT
            ),
            TestCase(
                server="s3-storage",
                tool="s3_list_objects",
                description="List objects",
                params={"bucket": "test-bucket", "prefix": "mcp/"},
                agent=TestAgent.STORAGE_AGENT
            ),
        ])
        
        # Cloud Storage Server Tests
        test_suite.extend([
            TestCase(
                server="cloud-storage",
                tool="list_storage_accounts",
                description="List accounts",
                params={"provider": "aws"},
                agent=TestAgent.STORAGE_AGENT
            ),
            TestCase(
                server="cloud-storage",
                tool="list_containers",
                description="List containers",
                params={"provider": "azure", "account": "test"},
                agent=TestAgent.STORAGE_AGENT
            ),
        ])
        
        self.metrics['total_tests'] = len(test_suite)
        return test_suite
    
    async def execute_test(self, test_case: TestCase) -> TestResult:
        """Execute a single test case"""
        start_time = time.time()
        
        try:
            # Build tool name
            tool_name = f"{test_case.server}.{test_case.tool}"
            
            # Log test execution
            logger.info(f"🧪 [{test_case.agent.value}] Testing {tool_name}: {test_case.description}")
            
            # Execute tool
            result = await asyncio.wait_for(
                self.mcp_manager.call_tool(tool_name, test_case.params),
                timeout=test_case.timeout
            )
            
            duration = time.time() - start_time
            
            # Success
            logger.info(f"   ✅ PASSED ({duration:.2f}s)")
            
            return TestResult(
                test_case=test_case,
                success=True,
                duration=duration,
                output=result,
                timestamp=datetime.now()
            )
            
        except asyncio.TimeoutError:
            duration = time.time() - start_time
            error = f"Timeout after {test_case.timeout}s"
            logger.error(f"   ⏱️ TIMEOUT ({duration:.2f}s)")
            
            return TestResult(
                test_case=test_case,
                success=False,
                duration=duration,
                error=error,
                timestamp=datetime.now()
            )
            
        except Exception as e:
            duration = time.time() - start_time
            error = str(e)
            
            # Check if it's a "not found" error
            if "not found" in error.lower() or "not registered" in error.lower():
                logger.warning(f"   ⏭️ SKIPPED: {error}")
                self.metrics['skipped'] += 1
            else:
                logger.error(f"   ❌ FAILED: {error}")
                
            return TestResult(
                test_case=test_case,
                success=False,
                duration=duration,
                error=error,
                timestamp=datetime.now()
            )
    
    async def execute_parallel_tests(self, test_suite: List[TestCase]):
        """Execute tests in parallel grouped by agent"""
        logger.info(f"\n🚀 Executing {len(test_suite)} tests across {len(TestAgent)} agents...")
        
        # Group tests by agent
        tests_by_agent = defaultdict(list)
        for test in test_suite:
            tests_by_agent[test.agent].append(test)
        
        # Execute tests for each agent in parallel
        tasks = []
        for agent, tests in tests_by_agent.items():
            logger.info(f"\n🤖 {agent.value} - {len(tests)} tests")
            for test in tests:
                tasks.append(self.execute_test(test))
        
        # Execute all tests
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for result in results:
            if isinstance(result, TestResult):
                # Store result
                self.results[result.test_case.server].append(result)
                
                # Update metrics
                self.metrics['servers_tested'].add(result.test_case.server)
                self.metrics['tools_tested'].add(result.test_case.tool)
                
                if result.success:
                    self.metrics['passed'] += 1
                elif result.error and "skip" not in result.error.lower():
                    self.metrics['failed'] += 1
                    
            elif isinstance(result, Exception):
                self.metrics['errors'] += 1
                logger.error(f"Unexpected error: {result}")
    
    def generate_report(self):
        """Generate comprehensive test report"""
        self.metrics['duration'] = (datetime.now() - self.start_time).total_seconds()
        
        # Calculate statistics
        success_rate = (self.metrics['passed'] / self.metrics['total_tests'] * 100) if self.metrics['total_tests'] > 0 else 0
        
        # Display summary
        print("\n" + "="*80)
        print("🎯 MCP COMPREHENSIVE TEST RESULTS")
        print("="*80)
        print(f"⏱️  Duration: {self.metrics['duration']:.1f}s")
        print(f"📊 Total Tests: {self.metrics['total_tests']}")
        print(f"✅ Passed: {self.metrics['passed']}")
        print(f"❌ Failed: {self.metrics['failed']}")
        print(f"💥 Errors: {self.metrics['errors']}")
        print(f"⏭️  Skipped: {self.metrics['skipped']}")
        print(f"\n🎯 Success Rate: {success_rate:.1f}%")
        print(f"📦 Servers Tested: {len(self.metrics['servers_tested'])}")
        print(f"🔧 Tools Tested: {len(self.metrics['tools_tested'])}")
        
        # Server breakdown
        print("\n📦 Server Results:")
        for server, results in self.results.items():
            passed = sum(1 for r in results if r.success)
            total = len(results)
            coverage = (passed / total * 100) if total > 0 else 0
            print(f"  {server}: {passed}/{total} passed ({coverage:.1f}%)")
        
        # Generate detailed JSON report
        report = {
            'summary': {
                'timestamp': datetime.now().isoformat(),
                'duration': self.metrics['duration'],
                'total_tests': self.metrics['total_tests'],
                'passed': self.metrics['passed'],
                'failed': self.metrics['failed'],
                'errors': self.metrics['errors'],
                'skipped': self.metrics['skipped'],
                'success_rate': success_rate,
                'servers_tested': list(self.metrics['servers_tested']),
                'tools_tested': list(self.metrics['tools_tested'])
            },
            'server_results': {}
        }
        
        # Add detailed results
        for server, results in self.results.items():
            report['server_results'][server] = {
                'total': len(results),
                'passed': sum(1 for r in results if r.success),
                'tests': [
                    {
                        'tool': r.test_case.tool,
                        'description': r.test_case.description,
                        'success': r.success,
                        'duration': r.duration,
                        'error': r.error,
                        'agent': r.test_case.agent.value
                    }
                    for r in results
                ]
            }
        
        # Save report
        report_path = f"mcp_comprehensive_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Detailed report saved to: {report_path}")
        
        # Recommendations
        print("\n💡 Recommendations:")
        if success_rate < 50:
            print("  🚨 Critical: Less than 50% tests passing - immediate attention required")
        elif success_rate < 80:
            print("  ⚠️  Warning: Success rate below 80% - review failing tests")
        else:
            print("  ✅ Good: High test success rate")
            
        if self.metrics['skipped'] > 0:
            print(f"  ℹ️  Info: {self.metrics['skipped']} tests skipped - check server availability")
            
        print("="*80)


async def main():
    """Main test execution"""
    print("🚀 MCP COMPREHENSIVE TESTING SUITE")
    print("🤖 Testing with 10 Parallel Agents")
    print("📦 Testing all 11 MCP Servers")
    print("="*80)
    
    tester = ComprehensiveMCPTester()
    
    try:
        # Initialize environment
        if not await tester.initialize_environment():
            print("\n❌ Failed to initialize MCP environment")
            return 1
        
        # Create test suite
        test_suite = tester.create_test_suite()
        
        # Execute tests
        await tester.execute_parallel_tests(test_suite)
        
        # Generate report
        tester.generate_report()
        
        # Return exit code based on results
        if tester.metrics['failed'] == 0 and tester.metrics['errors'] == 0:
            print("\n✨ All tests passed successfully!")
            return 0
        else:
            print(f"\n⚠️ {tester.metrics['failed'] + tester.metrics['errors']} tests failed")
            return 1
            
    except Exception as e:
        logger.error(f"💥 Critical failure: {e}")
        import traceback
        traceback.print_exc()
        return 2


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)