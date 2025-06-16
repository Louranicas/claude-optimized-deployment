#!/usr/bin/env python3
"""
ULTRATHINK MCP Server Testing Suite - Maximum Parallel Execution
Testing all 11 MCP servers at 100% capacity using 10 specialized agents
Leveraging Circle of Experts for intelligent test orchestration
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

# Import core components
from src.core.parallel_executor import ParallelExecutor, Task, TaskType
from src.circle_of_experts.core.enhanced_expert_manager import EnhancedExpertManager
from src.mcp.manager import get_mcp_manager
from src.mcp.servers import MCPServerRegistry


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


class MCPServerTestOrchestrator:
    """
    ULTRATHINK: Orchestrates comprehensive MCP server testing
    using 10 parallel agents and Circle of Experts intelligence
    """
    
    def __init__(self):
        self.start_time = datetime.now()
        self.mcp_manager = None
        self.expert_manager = None
        self.test_results: Dict[str, List[TestResult]] = defaultdict(list)
        self.server_health: Dict[str, Dict[str, Any]] = {}
        self.test_metrics = {
            'total_tests': 0,
            'passed': 0,
            'failed': 0,
            'skipped': 0,
            'errors': 0,
            'duration': 0.0,
            'server_coverage': {},
            'tool_coverage': {},
            'ai_consultations': 0
        }
        
    async def initialize_systems(self):
        """Initialize MCP Manager and Circle of Experts"""
        logger.info("🚀 Initializing MCP testing infrastructure...")
        
        # Set environment variables for all services
        test_env_vars = {
            'BRAVE_API_KEY': os.getenv('BRAVE_API_KEY', 'test_brave_key'),
            'SLACK_BOT_TOKEN': os.getenv('SLACK_BOT_TOKEN', 'test_slack_token'),
            'AWS_ACCESS_KEY_ID': os.getenv('AWS_ACCESS_KEY_ID', 'test_aws_key'),
            'AWS_SECRET_ACCESS_KEY': os.getenv('AWS_SECRET_ACCESS_KEY', 'test_aws_secret'),
            'AZURE_DEVOPS_TOKEN': os.getenv('AZURE_DEVOPS_TOKEN', 'test_azure_token'),
            'ANTHROPIC_API_KEY': os.getenv('ANTHROPIC_API_KEY', 'test_anthropic_key'),
            'OPENAI_API_KEY': os.getenv('OPENAI_API_KEY', 'test_openai_key'),
            'GOOGLE_GEMINI_API_KEY': os.getenv('GOOGLE_GEMINI_API_KEY', 'test_gemini_key'),
            'DEEPSEEK_API_KEY': os.getenv('DEEPSEEK_API_KEY', 'test_deepseek_key'),
            'GROQ_API_KEY': os.getenv('GROQ_API_KEY', 'test_groq_key')
        }
        
        for key, value in test_env_vars.items():
            if not os.getenv(key):
                os.environ[key] = value
        
        # Initialize MCP Manager
        try:
            self.mcp_manager = get_mcp_manager()
            await self.mcp_manager.initialize()
            logger.info(f"✅ MCP Manager initialized with {len(self.mcp_manager.registry.servers)} servers")
        except Exception as e:
            logger.error(f"❌ Failed to initialize MCP Manager: {e}")
            raise
        
        # Initialize Expert Manager
        try:
            self.expert_manager = EnhancedExpertManager()
            logger.info("✅ Circle of Experts initialized")
        except Exception as e:
            logger.warning(f"⚠️ Circle of Experts initialization failed (non-critical): {e}")
            self.expert_manager = None
    
    def generate_comprehensive_test_suite(self) -> Dict[str, List[MCPTestCase]]:
        """Generate comprehensive test cases for all MCP servers"""
        test_suite = {
            "brave": [
                MCPTestCase(
                    server_name="brave",
                    tool_name="brave_web_search",
                    test_name="basic_web_search",
                    parameters={"query": "MCP server testing", "count": 5},
                    expected_behavior="Returns web search results"
                ),
                MCPTestCase(
                    server_name="brave",
                    tool_name="brave_local_search",
                    test_name="local_search",
                    parameters={"query": "coffee shops near me"},
                    expected_behavior="Returns local search results"
                ),
                MCPTestCase(
                    server_name="brave",
                    tool_name="brave_news_search",
                    test_name="news_search",
                    parameters={"query": "AI development", "freshness": "pd"},
                    expected_behavior="Returns recent news articles"
                ),
                MCPTestCase(
                    server_name="brave",
                    tool_name="brave_image_search",
                    test_name="image_search",
                    parameters={"query": "kubernetes architecture", "size": "medium"},
                    expected_behavior="Returns image search results"
                )
            ],
            "desktop-commander": [
                MCPTestCase(
                    server_name="desktop-commander",
                    tool_name="execute_command",
                    test_name="safe_command_execution",
                    parameters={"command": "echo 'MCP Test Suite Active'"},
                    expected_behavior="Executes safe shell command"
                ),
                MCPTestCase(
                    server_name="desktop-commander",
                    tool_name="get_environment_info",
                    test_name="environment_info",
                    parameters={},
                    expected_behavior="Returns system environment information"
                ),
                MCPTestCase(
                    server_name="desktop-commander",
                    tool_name="file_operations",
                    test_name="file_listing",
                    parameters={"operation": "list", "path": "./"},
                    expected_behavior="Lists files in directory"
                )
            ],
            "docker": [
                MCPTestCase(
                    server_name="docker",
                    tool_name="docker_ps",
                    test_name="list_containers",
                    parameters={"all": True},
                    expected_behavior="Lists all Docker containers"
                ),
                MCPTestCase(
                    server_name="docker",
                    tool_name="docker_images",
                    test_name="list_images",
                    parameters={},
                    expected_behavior="Lists Docker images"
                ),
                MCPTestCase(
                    server_name="docker",
                    tool_name="docker_system_info",
                    test_name="system_info",
                    parameters={},
                    expected_behavior="Returns Docker system information"
                ),
                MCPTestCase(
                    server_name="docker",
                    tool_name="docker_logs",
                    test_name="container_logs",
                    parameters={"container": "test_container", "tail": 10},
                    expected_behavior="Returns container logs",
                    severity="low"
                )
            ],
            "kubernetes": [
                MCPTestCase(
                    server_name="kubernetes",
                    tool_name="kubectl_get",
                    test_name="list_pods",
                    parameters={"resource_type": "pods", "namespace": "default"},
                    expected_behavior="Lists Kubernetes pods"
                ),
                MCPTestCase(
                    server_name="kubernetes",
                    tool_name="kubectl_describe",
                    test_name="describe_service",
                    parameters={"resource_type": "service", "name": "kubernetes"},
                    expected_behavior="Describes Kubernetes service"
                ),
                MCPTestCase(
                    server_name="kubernetes",
                    tool_name="kubectl_logs",
                    test_name="pod_logs",
                    parameters={"pod_name": "test-pod", "container": "main"},
                    expected_behavior="Returns pod logs",
                    severity="low"
                ),
                MCPTestCase(
                    server_name="kubernetes",
                    tool_name="kubectl_get",
                    test_name="list_nodes",
                    parameters={"resource_type": "nodes"},
                    expected_behavior="Lists cluster nodes"
                )
            ],
            "azure-devops": [
                MCPTestCase(
                    server_name="azure-devops",
                    tool_name="list_projects",
                    test_name="list_projects",
                    parameters={},
                    expected_behavior="Lists Azure DevOps projects"
                ),
                MCPTestCase(
                    server_name="azure-devops",
                    tool_name="list_pipelines",
                    test_name="list_pipelines",
                    parameters={"project": "TestProject"},
                    expected_behavior="Lists pipelines in project"
                ),
                MCPTestCase(
                    server_name="azure-devops",
                    tool_name="get_build_status",
                    test_name="build_status",
                    parameters={"project": "TestProject", "build_id": "123"},
                    expected_behavior="Returns build status"
                )
            ],
            "windows-system": [
                MCPTestCase(
                    server_name="windows-system",
                    tool_name="system_info",
                    test_name="get_system_info",
                    parameters={},
                    expected_behavior="Returns Windows system information"
                ),
                MCPTestCase(
                    server_name="windows-system",
                    tool_name="process_list",
                    test_name="list_processes",
                    parameters={},
                    expected_behavior="Lists running processes"
                ),
                MCPTestCase(
                    server_name="windows-system",
                    tool_name="service_status",
                    test_name="check_service",
                    parameters={"service_name": "Windows Update"},
                    expected_behavior="Returns service status"
                )
            ],
            "prometheus-monitoring": [
                MCPTestCase(
                    server_name="prometheus-monitoring",
                    tool_name="prometheus_query",
                    test_name="basic_query",
                    parameters={"query": "up"},
                    expected_behavior="Returns Prometheus query results"
                ),
                MCPTestCase(
                    server_name="prometheus-monitoring",
                    tool_name="prometheus_targets",
                    test_name="list_targets",
                    parameters={"state": "active"},
                    expected_behavior="Lists Prometheus targets"
                ),
                MCPTestCase(
                    server_name="prometheus-monitoring",
                    tool_name="prometheus_alerts",
                    test_name="active_alerts",
                    parameters={},
                    expected_behavior="Returns active alerts"
                ),
                MCPTestCase(
                    server_name="prometheus-monitoring",
                    tool_name="prometheus_metrics",
                    test_name="metric_metadata",
                    parameters={"metric": "http_requests_total"},
                    expected_behavior="Returns metric metadata"
                )
            ],
            "security-scanner": [
                MCPTestCase(
                    server_name="security-scanner",
                    tool_name="file_security_scan",
                    test_name="scan_directory",
                    parameters={"path": "./src", "exclude": ["__pycache__"]},
                    expected_behavior="Scans files for security issues",
                    timeout=60.0
                ),
                MCPTestCase(
                    server_name="security-scanner",
                    tool_name="dependency_check",
                    test_name="check_dependencies",
                    parameters={"file": "requirements.txt"},
                    expected_behavior="Checks dependencies for vulnerabilities"
                ),
                MCPTestCase(
                    server_name="security-scanner",
                    tool_name="sast_scan",
                    test_name="static_analysis",
                    parameters={"path": "./src", "language": "python"},
                    expected_behavior="Performs static security analysis",
                    timeout=90.0
                ),
                MCPTestCase(
                    server_name="security-scanner",
                    tool_name="npm_audit",
                    test_name="npm_security",
                    parameters={"package_json_path": "./package.json"},
                    expected_behavior="Audits npm packages"
                )
            ],
            "slack-notifications": [
                MCPTestCase(
                    server_name="slack-notifications",
                    tool_name="send_message",
                    test_name="send_test_message",
                    parameters={
                        "channel": "#mcp-testing",
                        "text": "MCP Server Test Suite Active 🚀"
                    },
                    expected_behavior="Sends message to Slack"
                ),
                MCPTestCase(
                    server_name="slack-notifications",
                    tool_name="list_channels",
                    test_name="list_channels",
                    parameters={},
                    expected_behavior="Lists Slack channels"
                ),
                MCPTestCase(
                    server_name="slack-notifications",
                    tool_name="send_alert",
                    test_name="send_alert",
                    parameters={
                        "channel": "#alerts",
                        "title": "Test Alert",
                        "message": "This is a test alert",
                        "severity": "info"
                    },
                    expected_behavior="Sends formatted alert"
                )
            ],
            "s3-storage": [
                MCPTestCase(
                    server_name="s3-storage",
                    tool_name="s3_list_buckets",
                    test_name="list_buckets",
                    parameters={},
                    expected_behavior="Lists S3 buckets"
                ),
                MCPTestCase(
                    server_name="s3-storage",
                    tool_name="s3_list_objects",
                    test_name="list_objects",
                    parameters={"bucket": "test-bucket", "prefix": "mcp/"},
                    expected_behavior="Lists objects in bucket"
                ),
                MCPTestCase(
                    server_name="s3-storage",
                    tool_name="s3_get_object",
                    test_name="get_object",
                    parameters={"bucket": "test-bucket", "key": "test.txt"},
                    expected_behavior="Retrieves object from S3"
                ),
                MCPTestCase(
                    server_name="s3-storage",
                    tool_name="s3_put_object",
                    test_name="put_object",
                    parameters={
                        "bucket": "test-bucket",
                        "key": "mcp-test.txt",
                        "content": "MCP Test Content"
                    },
                    expected_behavior="Uploads object to S3"
                )
            ],
            "cloud-storage": [
                MCPTestCase(
                    server_name="cloud-storage",
                    tool_name="list_storage_accounts",
                    test_name="list_accounts",
                    parameters={"provider": "aws"},
                    expected_behavior="Lists cloud storage accounts"
                ),
                MCPTestCase(
                    server_name="cloud-storage",
                    tool_name="list_containers",
                    test_name="list_containers",
                    parameters={"provider": "azure", "account": "testaccount"},
                    expected_behavior="Lists storage containers"
                ),
                MCPTestCase(
                    server_name="cloud-storage",
                    tool_name="upload_file",
                    test_name="upload_file",
                    parameters={
                        "provider": "gcp",
                        "container": "test-bucket",
                        "path": "test/mcp.txt",
                        "content": "Test content"
                    },
                    expected_behavior="Uploads file to cloud storage"
                ),
                MCPTestCase(
                    server_name="cloud-storage",
                    tool_name="download_file",
                    test_name="download_file",
                    parameters={
                        "provider": "aws",
                        "container": "test-bucket",
                        "path": "test/mcp.txt"
                    },
                    expected_behavior="Downloads file from cloud storage"
                )
            ]
        }
        
        return test_suite
    
    async def execute_parallel_testing(self):
        """Execute comprehensive MCP server testing with 10 parallel agents"""
        logger.info("🎯 Starting ULTRATHINK MCP Server Testing Suite")
        logger.info("="*80)
        
        try:
            # Phase 1: Initialize systems
            await self.initialize_systems()
            
            # Phase 2: Generate test suite
            test_suite = self.generate_comprehensive_test_suite()
            total_tests = sum(len(tests) for tests in test_suite.values())
            self.test_metrics['total_tests'] = total_tests
            
            logger.info(f"📋 Generated {total_tests} test cases across {len(test_suite)} MCP servers")
            
            # Phase 3: Create parallel test tasks
            test_tasks = await self._create_parallel_test_tasks(test_suite)
            
            # Phase 4: Execute tests in parallel
            async with ParallelExecutor(
                max_workers_thread=10,
                max_workers_process=4,
                max_concurrent_tasks=20,
                memory_limit_mb=4096
            ) as executor:
                logger.info(f"🚀 Executing {len(test_tasks)} test tasks in parallel...")
                
                # Execute all test tasks
                results = await executor.execute_tasks(test_tasks)
                
                # Process results
                await self._process_test_results(results)
                
                # Get execution report
                execution_report = executor.get_execution_report()
                await self._save_execution_report(execution_report)
            
            # Phase 5: AI-powered test analysis
            if self.expert_manager:
                await self._ai_test_analysis()
            
            # Phase 6: Generate comprehensive report
            await self._generate_comprehensive_report()
            
        except Exception as e:
            logger.error(f"💥 Critical testing failure: {e}")
            logger.error(traceback.format_exc())
            raise
    
    async def _create_parallel_test_tasks(self, test_suite: Dict[str, List[MCPTestCase]]) -> List[Task]:
        """Create parallel tasks for test execution"""
        tasks = []
        
        # Assign test agents to server categories
        agent_assignments = {
            TestAgentRole.SEARCH_SPECIALIST: ["brave"],
            TestAgentRole.SYSTEM_COMMANDER: ["desktop-commander"],
            TestAgentRole.CONTAINER_EXPERT: ["docker"],
            TestAgentRole.CLOUD_NATIVE: ["kubernetes"],
            TestAgentRole.DEVOPS_AUTOMATION: ["azure-devops"],
            TestAgentRole.WINDOWS_SPECIALIST: ["windows-system"],
            TestAgentRole.MONITORING_EXPERT: ["prometheus-monitoring"],
            TestAgentRole.SECURITY_ANALYST: ["security-scanner"],
            TestAgentRole.COMMUNICATION_LEAD: ["slack-notifications"],
            TestAgentRole.STORAGE_ARCHITECT: ["s3-storage", "cloud-storage"]
        }
        
        # Create tasks for each agent
        for agent_role, assigned_servers in agent_assignments.items():
            for server_name in assigned_servers:
                if server_name in test_suite:
                    task = Task(
                        name=f"{agent_role.value}_{server_name}_tests",
                        func=self._execute_server_tests,
                        args=(agent_role, server_name, test_suite[server_name]),
                        task_type=TaskType.ASYNC,
                        timeout=300.0
                    )
                    tasks.append(task)
        
        return tasks
    
    async def _execute_server_tests(
        self,
        agent_role: TestAgentRole,
        server_name: str,
        test_cases: List[MCPTestCase]
    ) -> Dict[str, Any]:
        """Execute tests for a specific MCP server"""
        logger.info(f"🤖 {agent_role.value} testing {server_name} server...")
        
        agent_results = {
            'agent': agent_role.value,
            'server': server_name,
            'test_results': [],
            'summary': {
                'total': len(test_cases),
                'passed': 0,
                'failed': 0,
                'errors': 0,
                'skipped': 0
            }
        }
        
        # Check if server is available
        if server_name not in self.mcp_manager.registry.servers:
            logger.warning(f"⚠️ Server {server_name} not registered, skipping tests")
            agent_results['summary']['skipped'] = len(test_cases)
            return agent_results
        
        # Execute each test case
        for test_case in test_cases:
            result = await self._execute_single_test(test_case, agent_role)
            agent_results['test_results'].append(result)
            
            # Update summary
            if result.success:
                agent_results['summary']['passed'] += 1
            elif result.error and "not found" in result.error.lower():
                agent_results['summary']['skipped'] += 1
            elif result.error:
                agent_results['summary']['errors'] += 1
            else:
                agent_results['summary']['failed'] += 1
            
            # Store result
            self.test_results[server_name].append(result)
        
        # Log agent summary
        summary = agent_results['summary']
        logger.info(
            f"✅ {agent_role.value} completed {server_name} tests: "
            f"{summary['passed']}/{summary['total']} passed, "
            f"{summary['failed']} failed, {summary['errors']} errors"
        )
        
        return agent_results
    
    async def _execute_single_test(
        self,
        test_case: MCPTestCase,
        agent_role: TestAgentRole
    ) -> TestResult:
        """Execute a single test case"""
        start_time = time.time()
        
        try:
            # Construct tool name
            tool_name = f"{test_case.server_name}.{test_case.tool_name}"
            
            # Execute test with timeout
            response = await asyncio.wait_for(
                self.mcp_manager.call_tool(tool_name, test_case.parameters),
                timeout=test_case.timeout
            )
            
            # Test passed
            duration = time.time() - start_time
            return TestResult(
                test_case=test_case,
                success=True,
                duration=duration,
                response=response,
                agent=agent_role.value,
                timestamp=datetime.now()
            )
            
        except asyncio.TimeoutError:
            duration = time.time() - start_time
            return TestResult(
                test_case=test_case,
                success=False,
                duration=duration,
                error=f"Test timed out after {test_case.timeout}s",
                agent=agent_role.value,
                timestamp=datetime.now()
            )
            
        except Exception as e:
            duration = time.time() - start_time
            return TestResult(
                test_case=test_case,
                success=False,
                duration=duration,
                error=str(e),
                agent=agent_role.value,
                timestamp=datetime.now()
            )
    
    async def _process_test_results(self, results: Dict[str, Any]):
        """Process and aggregate test results"""
        for task_name, result in results.items():
            if result.success and result.result:
                agent_results = result.result
                server_name = agent_results['server']
                summary = agent_results['summary']
                
                # Update metrics
                self.test_metrics['passed'] += summary['passed']
                self.test_metrics['failed'] += summary['failed']
                self.test_metrics['errors'] += summary['errors']
                self.test_metrics['skipped'] += summary['skipped']
                
                # Update server coverage
                self.test_metrics['server_coverage'][server_name] = {
                    'total': summary['total'],
                    'passed': summary['passed'],
                    'coverage': (summary['passed'] / summary['total'] * 100) if summary['total'] > 0 else 0
                }
    
    async def _ai_test_analysis(self):
        """Use Circle of Experts to analyze test results"""
        logger.info("🧠 Performing AI-powered test analysis...")
        
        try:
            # Prepare analysis query
            analysis_query = f"""
            Analyze the MCP server test results:
            
            Test Summary:
            - Total Tests: {self.test_metrics['total_tests']}
            - Passed: {self.test_metrics['passed']}
            - Failed: {self.test_metrics['failed']}
            - Errors: {self.test_metrics['errors']}
            - Skipped: {self.test_metrics['skipped']}
            
            Server Coverage:
            {json.dumps(self.test_metrics['server_coverage'], indent=2)}
            
            Provide:
            1. Overall health assessment (0-100%)
            2. Critical issues that need immediate attention
            3. Performance optimization recommendations
            4. Security considerations
            5. Reliability improvements
            """
            
            # Consult multiple experts
            ai_analysis = await self.expert_manager.consult_experts_async(
                analysis_query,
                expert_types=["claude-3-opus", "gpt-4", "deepseek-coder"]
            )
            
            self.test_metrics['ai_consultations'] += 1
            self.test_metrics['ai_analysis'] = ai_analysis
            
            logger.info("✅ AI analysis complete")
            
        except Exception as e:
            logger.warning(f"⚠️ AI analysis failed (non-critical): {e}")
    
    async def _save_execution_report(self, execution_report: Dict[str, Any]):
        """Save detailed execution report"""
        report_path = f"mcp_test_execution_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(report_path, 'w') as f:
            json.dump({
                'execution_report': execution_report,
                'test_metrics': self.test_metrics,
                'timestamp': datetime.now().isoformat()
            }, f, indent=2, default=str)
        
        logger.info(f"📝 Execution report saved to: {report_path}")
    
    async def _generate_comprehensive_report(self):
        """Generate comprehensive test report"""
        duration = (datetime.now() - self.start_time).total_seconds()
        self.test_metrics['duration'] = duration
        
        # Calculate overall statistics
        total_tests = self.test_metrics['total_tests']
        passed = self.test_metrics['passed']
        success_rate = (passed / total_tests * 100) if total_tests > 0 else 0
        
        # Generate HTML report
        html_report = self._generate_html_report()
        
        # Save HTML report
        html_path = f"mcp_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(html_path, 'w') as f:
            f.write(html_report)
        
        # Generate JSON report
        json_report = {
            'test_summary': {
                'timestamp': datetime.now().isoformat(),
                'duration_seconds': duration,
                'total_tests': total_tests,
                'passed': passed,
                'failed': self.test_metrics['failed'],
                'errors': self.test_metrics['errors'],
                'skipped': self.test_metrics['skipped'],
                'success_rate': success_rate
            },
            'server_results': {},
            'tool_coverage': self.test_metrics['tool_coverage'],
            'ai_analysis': self.test_metrics.get('ai_analysis', {}),
            'recommendations': self._generate_recommendations()
        }
        
        # Add detailed server results
        for server_name, results in self.test_results.items():
            json_report['server_results'][server_name] = {
                'total_tests': len(results),
                'passed': sum(1 for r in results if r.success),
                'failed': sum(1 for r in results if not r.success and not r.error),
                'errors': sum(1 for r in results if r.error),
                'average_duration': sum(r.duration for r in results) / len(results) if results else 0,
                'test_details': [
                    {
                        'test_name': r.test_case.test_name,
                        'tool_name': r.test_case.tool_name,
                        'success': r.success,
                        'duration': r.duration,
                        'error': r.error,
                        'agent': r.agent
                    }
                    for r in results
                ]
            }
        
        # Save JSON report
        json_path = f"mcp_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_path, 'w') as f:
            json.dump(json_report, f, indent=2, default=str)
        
        # Display summary
        self._display_test_summary()
        
        logger.info(f"📊 Reports saved: {html_path}, {json_path}")
    
    def _generate_html_report(self) -> str:
        """Generate HTML test report"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>MCP Server Test Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #1a1a1a; color: white; padding: 20px; border-radius: 5px; }}
                .summary {{ background-color: #f0f0f0; padding: 15px; margin: 20px 0; border-radius: 5px; }}
                .server-section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                .passed {{ color: #28a745; font-weight: bold; }}
                .failed {{ color: #dc3545; font-weight: bold; }}
                .error {{ color: #ff6b6b; font-weight: bold; }}
                .skipped {{ color: #6c757d; font-weight: bold; }}
                table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
                th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f8f9fa; font-weight: bold; }}
                .progress-bar {{ width: 100%; height: 20px; background-color: #e0e0e0; border-radius: 10px; overflow: hidden; }}
                .progress-fill {{ height: 100%; background-color: #28a745; transition: width 0.3s; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🚀 MCP Server Test Report</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Duration: {self.test_metrics['duration']:.1f} seconds</p>
            </div>
            
            <div class="summary">
                <h2>Test Summary</h2>
                <p>Total Tests: <strong>{self.test_metrics['total_tests']}</strong></p>
                <p>Passed: <span class="passed">{self.test_metrics['passed']}</span></p>
                <p>Failed: <span class="failed">{self.test_metrics['failed']}</span></p>
                <p>Errors: <span class="error">{self.test_metrics['errors']}</span></p>
                <p>Skipped: <span class="skipped">{self.test_metrics['skipped']}</span></p>
                <p>Success Rate: <strong>{(self.test_metrics['passed'] / self.test_metrics['total_tests'] * 100):.1f}%</strong></p>
                
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {(self.test_metrics['passed'] / self.test_metrics['total_tests'] * 100):.1f}%"></div>
                </div>
            </div>
        """
        
        # Add server sections
        for server_name, results in self.test_results.items():
            passed = sum(1 for r in results if r.success)
            failed = sum(1 for r in results if not r.success)
            
            html += f"""
            <div class="server-section">
                <h3>📦 {server_name.upper()} Server</h3>
                <p>Tests: {len(results)} | Passed: <span class="passed">{passed}</span> | Failed: <span class="failed">{failed}</span></p>
                
                <table>
                    <tr>
                        <th>Test Name</th>
                        <th>Tool</th>
                        <th>Status</th>
                        <th>Duration</th>
                        <th>Agent</th>
                        <th>Error</th>
                    </tr>
            """
            
            for result in results:
                status_class = "passed" if result.success else "failed"
                status_text = "✅ PASSED" if result.success else "❌ FAILED"
                
                html += f"""
                    <tr>
                        <td>{result.test_case.test_name}</td>
                        <td>{result.test_case.tool_name}</td>
                        <td class="{status_class}">{status_text}</td>
                        <td>{result.duration:.2f}s</td>
                        <td>{result.agent or 'N/A'}</td>
                        <td>{result.error or '-'}</td>
                    </tr>
                """
            
            html += """
                </table>
            </div>
            """
        
        html += """
        </body>
        </html>
        """
        
        return html
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on test results"""
        recommendations = []
        
        # Calculate success rate
        success_rate = (self.test_metrics['passed'] / self.test_metrics['total_tests'] * 100) if self.test_metrics['total_tests'] > 0 else 0
        
        if success_rate < 50:
            recommendations.append("🚨 CRITICAL: Less than 50% of tests passing. Immediate investigation required.")
        elif success_rate < 80:
            recommendations.append("⚠️ WARNING: Test success rate below 80%. Review failing tests.")
        else:
            recommendations.append("✅ Good test coverage with high success rate.")
        
        # Check for specific server issues
        for server_name, coverage in self.test_metrics['server_coverage'].items():
            if coverage['coverage'] < 50:
                recommendations.append(f"🔍 Investigate {server_name} server - low test success rate ({coverage['coverage']:.1f}%)")
        
        # Performance recommendations
        slow_tests = []
        for server_results in self.test_results.values():
            for result in server_results:
                if result.duration > 10.0:
                    slow_tests.append(f"{result.test_case.server_name}.{result.test_case.tool_name}")
        
        if slow_tests:
            recommendations.append(f"⏱️ Optimize slow tests: {', '.join(set(slow_tests))}")
        
        # Security recommendations
        if 'security-scanner' in self.test_results:
            security_failures = sum(1 for r in self.test_results['security-scanner'] if not r.success)
            if security_failures > 0:
                recommendations.append("🔒 Security scanner tests failing - review security configurations")
        
        return recommendations
    
    def _display_test_summary(self):
        """Display test summary to console"""
        print("\n" + "="*80)
        print("🎯 MCP SERVER TEST RESULTS")
        print("="*80)
        print(f"⏱️ Duration: {self.test_metrics['duration']:.1f}s")
        print(f"📊 Total Tests: {self.test_metrics['total_tests']}")
        print(f"✅ Passed: {self.test_metrics['passed']}")
        print(f"❌ Failed: {self.test_metrics['failed']}")
        print(f"💥 Errors: {self.test_metrics['errors']}")
        print(f"⏭️ Skipped: {self.test_metrics['skipped']}")
        
        success_rate = (self.test_metrics['passed'] / self.test_metrics['total_tests'] * 100) if self.test_metrics['total_tests'] > 0 else 0
        print(f"\n🎯 Success Rate: {success_rate:.1f}%")
        
        print("\n📦 Server Coverage:")
        for server_name, coverage in self.test_metrics['server_coverage'].items():
            print(f"  {server_name}: {coverage['passed']}/{coverage['total']} ({coverage['coverage']:.1f}%)")
        
        print("\n💡 Recommendations:")
        for rec in self._generate_recommendations():
            print(f"  {rec}")
        
        print("="*80)


async def main():
    """Execute comprehensive MCP server testing"""
    print("🚀 ULTRATHINK MCP SERVER TESTING SUITE")
    print("🤖 Testing with 10 Parallel Agents")
    print("🧠 Powered by Circle of Experts")
    print("📊 Testing all 11 MCP Servers at 100% Capacity")
    print("="*80)
    
    orchestrator = MCPServerTestOrchestrator()
    
    try:
        await orchestrator.execute_parallel_testing()
        
        # Determine exit code based on results
        success_rate = (orchestrator.test_metrics['passed'] / orchestrator.test_metrics['total_tests'] * 100) if orchestrator.test_metrics['total_tests'] > 0 else 0
        
        if success_rate >= 95:
            print("\n✨ EXCELLENT: 95%+ tests passing!")
            return 0
        elif success_rate >= 80:
            print("\n✅ GOOD: 80%+ tests passing")
            return 1
        elif success_rate >= 60:
            print("\n⚠️ WARNING: Only 60-80% tests passing")
            return 2
        else:
            print("\n❌ CRITICAL: Less than 60% tests passing")
            return 3
            
    except Exception as e:
        logger.error(f"💥 TESTING CATASTROPHIC FAILURE: {e}")
        import traceback
        traceback.print_exc()
        return 4


if __name__ == "__main__":
    # Execute testing with maximum capacity
    exit_code = asyncio.run(main())
    sys.exit(exit_code)