"""
GitHub Actions Integration - CI/CD integration for GitHub Actions.

This module provides seamless integration with GitHub Actions workflows,
enabling automated test execution, reporting, and deployment gating.
"""

import json
import logging
import os
import time
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import asyncio
import subprocess

import requests
import yaml
from prometheus_client import Counter, Histogram

logger = logging.getLogger(__name__)

# Metrics
github_actions_triggers = Counter('github_actions_triggers_total', 'GitHub Actions triggers', ['event_type'])
workflow_execution_duration = Histogram('workflow_execution_duration_seconds', 'Workflow execution duration')
deployment_gates = Counter('deployment_gates_total', 'Deployment gate decisions', ['decision'])


class WorkflowEvent(Enum):
    """GitHub Actions workflow events."""
    PUSH = "push"
    PULL_REQUEST = "pull_request"
    SCHEDULE = "schedule"
    WORKFLOW_DISPATCH = "workflow_dispatch"
    DEPLOYMENT = "deployment"
    RELEASE = "release"


class JobStatus(Enum):
    """GitHub Actions job status."""
    QUEUED = "queued"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class JobConclusion(Enum):
    """GitHub Actions job conclusion."""
    SUCCESS = "success"
    FAILURE = "failure"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"
    TIMED_OUT = "timed_out"
    ACTION_REQUIRED = "action_required"


@dataclass
class GitHubActionsConfig:
    """GitHub Actions integration configuration."""
    repository: str  # owner/repo format
    token: str
    base_url: str = "https://api.github.com"
    workflow_timeout: int = 3600  # 1 hour default
    max_retries: int = 3
    retry_delay: int = 30
    webhook_secret: Optional[str] = None
    default_branch: str = "main"
    environment: str = "testing"


@dataclass
class WorkflowRun:
    """GitHub Actions workflow run information."""
    id: int
    name: str
    head_branch: str
    head_sha: str
    status: JobStatus
    conclusion: Optional[JobConclusion]
    html_url: str
    run_number: int
    event: WorkflowEvent
    created_at: datetime
    updated_at: datetime
    run_started_at: Optional[datetime] = None
    jobs_url: str = ""
    artifacts_url: str = ""


@dataclass
class TestExecutionRequest:
    """Test execution request from GitHub Actions."""
    repository: str
    ref: str
    sha: str
    event_type: WorkflowEvent
    workflow_id: str
    run_id: int
    environment: str
    test_suites: List[str] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    quality_gates: Dict[str, float] = field(default_factory=dict)


class GitHubActionsIntegration:
    """GitHub Actions CI/CD integration."""
    
    def __init__(self, config: GitHubActionsConfig):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'token {config.token}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'Claude-Test-Automation/1.0'
        })
        
        # Workflow templates
        self.workflow_templates = {
            'stress_testing': self._create_stress_test_workflow(),
            'chaos_testing': self._create_chaos_test_workflow(),
            'performance_testing': self._create_performance_test_workflow(),
            'full_suite': self._create_full_suite_workflow()
        }
        
        logger.info(f"GitHub Actions integration initialized for {config.repository}")
        
    def _create_stress_test_workflow(self) -> Dict[str, Any]:
        """Create stress test workflow configuration."""
        return {
            'name': 'Stress Testing Pipeline',
            'on': {
                'push': {
                    'branches': [self.config.default_branch]
                },
                'pull_request': {
                    'branches': [self.config.default_branch]
                },
                'schedule': [
                    {'cron': '0 2 * * *'}  # Daily at 2 AM
                ],
                'workflow_dispatch': {
                    'inputs': {
                        'test_duration': {
                            'description': 'Test duration in seconds',
                            'required': False,
                            'default': '300'
                        },
                        'load_level': {
                            'description': 'Load level (low/medium/high)',
                            'required': False,
                            'default': 'medium'
                        }
                    }
                }
            },
            'env': {
                'PYTHONPATH': '${{ github.workspace }}/src',
                'TEST_ENVIRONMENT': 'ci'
            },
            'jobs': {
                'stress-tests': {
                    'runs-on': 'ubuntu-latest',
                    'timeout-minutes': 60,
                    'strategy': {
                        'matrix': {
                            'test-type': ['cpu', 'memory', 'io', 'network']
                        },
                        'fail-fast': False
                    },
                    'steps': [
                        {
                            'name': 'Checkout code',
                            'uses': 'actions/checkout@v3'
                        },
                        {
                            'name': 'Set up Python',
                            'uses': 'actions/setup-python@v4',
                            'with': {
                                'python-version': '3.11'
                            }
                        },
                        {
                            'name': 'Install dependencies',
                            'run': '''
                                python -m pip install --upgrade pip
                                pip install -r requirements.txt
                                pip install -r requirements-dev.txt
                            '''
                        },
                        {
                            'name': 'Run stress tests',
                            'run': '''
                                python -m pytest test_environments/automation/pipelines/stress_test_pipeline.py::StressTestPipeline \
                                    --test-type=${{ matrix.test-type }} \
                                    --duration=${{ github.event.inputs.test_duration || '300' }} \
                                    --load-level=${{ github.event.inputs.load_level || 'medium' }} \
                                    --junit-xml=reports/stress-${{ matrix.test-type }}-results.xml \
                                    --html=reports/stress-${{ matrix.test-type }}-report.html \
                                    --self-contained-html
                            '''
                        },
                        {
                            'name': 'Upload test results',
                            'uses': 'actions/upload-artifact@v3',
                            'if': 'always()',
                            'with': {
                                'name': 'stress-test-results-${{ matrix.test-type }}',
                                'path': 'reports/'
                            }
                        },
                        {
                            'name': 'Publish test results',
                            'uses': 'dorny/test-reporter@v1',
                            'if': 'always()',
                            'with': {
                                'name': 'Stress Tests (${{ matrix.test-type }})',
                                'path': 'reports/stress-${{ matrix.test-type }}-results.xml',
                                'reporter': 'java-junit'
                            }
                        }
                    ]
                },
                'quality-gate': {
                    'runs-on': 'ubuntu-latest',
                    'needs': 'stress-tests',
                    'if': 'always()',
                    'steps': [
                        {
                            'name': 'Download test results',
                            'uses': 'actions/download-artifact@v3',
                            'with': {
                                'path': 'all-results'
                            }
                        },
                        {
                            'name': 'Evaluate quality gates',
                            'run': '''
                                python scripts/evaluate_quality_gates.py \
                                    --results-dir=all-results \
                                    --output=quality-gate-results.json
                            '''
                        },
                        {
                            'name': 'Check quality gates',
                            'run': '''
                                if [ "$(jq -r '.passed' quality-gate-results.json)" = "false" ]; then
                                    echo "Quality gates failed!"
                                    jq '.failures' quality-gate-results.json
                                    exit 1
                                fi
                                echo "All quality gates passed!"
                            '''
                        }
                    ]
                }
            }
        }
        
    def _create_chaos_test_workflow(self) -> Dict[str, Any]:
        """Create chaos test workflow configuration."""
        return {
            'name': 'Chaos Engineering Pipeline',
            'on': {
                'schedule': [
                    {'cron': '0 1 * * 1'}  # Weekly on Monday at 1 AM
                ],
                'workflow_dispatch': {
                    'inputs': {
                        'experiment_type': {
                            'description': 'Chaos experiment type',
                            'required': True,
                            'type': 'choice',
                            'options': ['process_killer', 'network_partition', 'full_suite']
                        },
                        'impact_level': {
                            'description': 'Impact level',
                            'required': False,
                            'type': 'choice',
                            'options': ['low', 'medium', 'high'],
                            'default': 'medium'
                        }
                    }
                }
            },
            'jobs': {
                'chaos-experiments': {
                    'runs-on': 'ubuntu-latest',
                    'timeout-minutes': 90,
                    'steps': [
                        {
                            'name': 'Checkout code',
                            'uses': 'actions/checkout@v3'
                        },
                        {
                            'name': 'Set up Python',
                            'uses': 'actions/setup-python@v4',
                            'with': {
                                'python-version': '3.11'
                            }
                        },
                        {
                            'name': 'Install dependencies',
                            'run': '''
                                python -m pip install --upgrade pip
                                pip install -r requirements.txt
                                sudo apt-get update
                                sudo apt-get install -y stress-ng
                            '''
                        },
                        {
                            'name': 'Run chaos experiments',
                            'run': '''
                                python -m test_environments.automation.pipelines.chaos_test_pipeline \
                                    --experiment=${{ github.event.inputs.experiment_type || 'full_suite' }} \
                                    --impact=${{ github.event.inputs.impact_level || 'medium' }} \
                                    --output=chaos-results.json
                            '''
                        },
                        {
                            'name': 'Generate chaos report',
                            'run': '''
                                python scripts/generate_chaos_report.py \
                                    --input=chaos-results.json \
                                    --output=chaos-report.html
                            '''
                        },
                        {
                            'name': 'Upload chaos results',
                            'uses': 'actions/upload-artifact@v3',
                            'if': 'always()',
                            'with': {
                                'name': 'chaos-experiment-results',
                                'path': |
                                    chaos-results.json
                                    chaos-report.html
                            }
                        }
                    ]
                }
            }
        }
        
    def _create_performance_test_workflow(self) -> Dict[str, Any]:
        """Create performance test workflow configuration."""
        return {
            'name': 'Performance Testing Pipeline',
            'on': {
                'push': {
                    'branches': [self.config.default_branch]
                },
                'pull_request': {
                    'branches': [self.config.default_branch]
                }
            },
            'jobs': {
                'performance-tests': {
                    'runs-on': 'ubuntu-latest',
                    'steps': [
                        {
                            'name': 'Checkout code',
                            'uses': 'actions/checkout@v3'
                        },
                        {
                            'name': 'Set up Python',
                            'uses': 'actions/setup-python@v4',
                            'with': {
                                'python-version': '3.11'
                            }
                        },
                        {
                            'name': 'Run performance tests',
                            'run': '''
                                python -m pytest tests/performance/ \
                                    --benchmark-json=performance-results.json \
                                    --benchmark-html=performance-report.html
                            '''
                        },
                        {
                            'name': 'Performance regression check',
                            'run': '''
                                python scripts/check_performance_regression.py \
                                    --current=performance-results.json \
                                    --baseline=baseline-performance.json \
                                    --threshold=0.1
                            '''
                        }
                    ]
                }
            }
        }
        
    def _create_full_suite_workflow(self) -> Dict[str, Any]:
        """Create comprehensive test suite workflow."""
        return {
            'name': 'Full Test Suite Pipeline',
            'on': {
                'schedule': [
                    {'cron': '0 0 * * 0'}  # Weekly on Sunday at midnight
                ],
                'workflow_dispatch': {}
            },
            'jobs': {
                'full-test-suite': {
                    'runs-on': 'ubuntu-latest',
                    'timeout-minutes': 180,
                    'steps': [
                        {
                            'name': 'Checkout code',
                            'uses': 'actions/checkout@v3'
                        },
                        {
                            'name': 'Set up Python',
                            'uses': 'actions/setup-python@v4',
                            'with': {
                                'python-version': '3.11'
                            }
                        },
                        {
                            'name': 'Install dependencies',
                            'run': '''
                                python -m pip install --upgrade pip
                                pip install -r requirements.txt
                                pip install -r requirements-dev.txt
                            '''
                        },
                        {
                            'name': 'Run full test suite',
                            'run': '''
                                python -m test_environments.automation.test_orchestrator \
                                    --suite=comprehensive \
                                    --output-dir=full-suite-results \
                                    --generate-reports
                            '''
                        },
                        {
                            'name': 'Upload comprehensive results',
                            'uses': 'actions/upload-artifact@v3',
                            'if': 'always()',
                            'with': {
                                'name': 'full-suite-results',
                                'path': 'full-suite-results/'
                            }
                        }
                    ]
                }
            }
        }
        
    async def create_workflow_file(self, workflow_type: str, output_path: Optional[str] = None) -> str:
        """Create GitHub Actions workflow file."""
        if workflow_type not in self.workflow_templates:
            raise ValueError(f"Unknown workflow type: {workflow_type}")
            
        workflow = self.workflow_templates[workflow_type]
        
        # Set default output path
        if not output_path:
            output_path = f".github/workflows/{workflow_type.replace('_', '-')}.yml"
            
        # Ensure directory exists
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Write workflow file
        with open(output_path, 'w') as f:
            yaml.dump(workflow, f, default_flow_style=False, sort_keys=False)
            
        logger.info(f"Created workflow file: {output_path}")
        return output_path
        
    async def trigger_workflow(self, workflow_id: str, ref: str = None, 
                             inputs: Optional[Dict[str, str]] = None) -> WorkflowRun:
        """Trigger a GitHub Actions workflow."""
        github_actions_triggers.labels(event_type='manual_trigger').inc()
        
        url = f"{self.config.base_url}/repos/{self.config.repository}/actions/workflows/{workflow_id}/dispatches"
        
        data = {
            'ref': ref or self.config.default_branch
        }
        
        if inputs:
            data['inputs'] = inputs
            
        response = self.session.post(url, json=data)
        response.raise_for_status()
        
        # Get the latest workflow run
        await asyncio.sleep(2)  # Wait for workflow to appear
        return await self.get_latest_workflow_run(workflow_id)
        
    async def get_workflow_run(self, run_id: int) -> WorkflowRun:
        """Get workflow run information."""
        url = f"{self.config.base_url}/repos/{self.config.repository}/actions/runs/{run_id}"
        
        response = self.session.get(url)
        response.raise_for_status()
        
        data = response.json()
        
        return WorkflowRun(
            id=data['id'],
            name=data['name'],
            head_branch=data['head_branch'],
            head_sha=data['head_sha'],
            status=JobStatus(data['status']),
            conclusion=JobConclusion(data['conclusion']) if data['conclusion'] else None,
            html_url=data['html_url'],
            run_number=data['run_number'],
            event=WorkflowEvent(data['event']),
            created_at=datetime.fromisoformat(data['created_at'].replace('Z', '+00:00')),
            updated_at=datetime.fromisoformat(data['updated_at'].replace('Z', '+00:00')),
            run_started_at=datetime.fromisoformat(data['run_started_at'].replace('Z', '+00:00')) 
                          if data.get('run_started_at') else None,
            jobs_url=data['jobs_url'],
            artifacts_url=data['artifacts_url']
        )
        
    async def get_latest_workflow_run(self, workflow_id: str) -> WorkflowRun:
        """Get the latest workflow run."""
        url = f"{self.config.base_url}/repos/{self.config.repository}/actions/workflows/{workflow_id}/runs"
        
        response = self.session.get(url, params={'per_page': 1})
        response.raise_for_status()
        
        data = response.json()
        
        if not data['workflow_runs']:
            raise ValueError(f"No workflow runs found for workflow {workflow_id}")
            
        run_data = data['workflow_runs'][0]
        
        return WorkflowRun(
            id=run_data['id'],
            name=run_data['name'],
            head_branch=run_data['head_branch'],
            head_sha=run_data['head_sha'],
            status=JobStatus(run_data['status']),
            conclusion=JobConclusion(run_data['conclusion']) if run_data['conclusion'] else None,
            html_url=run_data['html_url'],
            run_number=run_data['run_number'],
            event=WorkflowEvent(run_data['event']),
            created_at=datetime.fromisoformat(run_data['created_at'].replace('Z', '+00:00')),
            updated_at=datetime.fromisoformat(run_data['updated_at'].replace('Z', '+00:00')),
            jobs_url=run_data['jobs_url'],
            artifacts_url=run_data['artifacts_url']
        )
        
    async def wait_for_workflow_completion(self, run_id: int, timeout: int = None) -> WorkflowRun:
        """Wait for workflow completion."""
        timeout = timeout or self.config.workflow_timeout
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            workflow_run = await self.get_workflow_run(run_id)
            
            if workflow_run.status == JobStatus.COMPLETED:
                duration = time.time() - start_time
                workflow_execution_duration.observe(duration)
                return workflow_run
                
            await asyncio.sleep(30)  # Check every 30 seconds
            
        raise TimeoutError(f"Workflow {run_id} did not complete within {timeout} seconds")
        
    async def get_workflow_artifacts(self, run_id: int) -> List[Dict[str, Any]]:
        """Get workflow run artifacts."""
        url = f"{self.config.base_url}/repos/{self.config.repository}/actions/runs/{run_id}/artifacts"
        
        response = self.session.get(url)
        response.raise_for_status()
        
        return response.json()['artifacts']
        
    async def download_artifact(self, artifact_id: int, output_path: str) -> None:
        """Download workflow artifact."""
        url = f"{self.config.base_url}/repos/{self.config.repository}/actions/artifacts/{artifact_id}/zip"
        
        response = self.session.get(url)
        response.raise_for_status()
        
        with open(output_path, 'wb') as f:
            f.write(response.content)
            
        logger.info(f"Downloaded artifact to {output_path}")
        
    async def create_deployment_status(self, deployment_id: int, state: str, 
                                     description: str = "", target_url: str = "") -> None:
        """Create deployment status."""
        url = f"{self.config.base_url}/repos/{self.config.repository}/deployments/{deployment_id}/statuses"
        
        data = {
            'state': state,
            'description': description,
            'target_url': target_url,
            'environment': self.config.environment
        }
        
        response = self.session.post(url, json=data)
        response.raise_for_status()
        
    async def evaluate_quality_gates(self, test_results: Dict[str, Any], 
                                   quality_gates: Dict[str, float]) -> Dict[str, Any]:
        """Evaluate quality gates for deployment."""
        results = {
            'passed': True,
            'failures': [],
            'metrics': {},
            'decision': 'proceed'
        }
        
        # Extract metrics from test results
        success_rate = test_results.get('summary', {}).get('execution_summary', {}).get('success_rate', 0)
        quality_score = test_results.get('quality_score', 0)
        anomaly_count = len(test_results.get('anomalies', []))
        
        results['metrics'] = {
            'success_rate': success_rate,
            'quality_score': quality_score,
            'anomaly_count': anomaly_count
        }
        
        # Check quality gates
        min_success_rate = quality_gates.get('min_success_rate', 0.95)
        if success_rate < min_success_rate:
            results['passed'] = False
            results['failures'].append(f"Success rate {success_rate:.1%} below threshold {min_success_rate:.1%}")
            
        min_quality_score = quality_gates.get('min_quality_score', 80.0)
        if quality_score < min_quality_score:
            results['passed'] = False
            results['failures'].append(f"Quality score {quality_score:.1f} below threshold {min_quality_score:.1f}")
            
        max_anomalies = quality_gates.get('max_anomalies', 5)
        if anomaly_count > max_anomalies:
            results['passed'] = False
            results['failures'].append(f"Anomaly count {anomaly_count} exceeds threshold {max_anomalies}")
            
        # Update decision
        if not results['passed']:
            results['decision'] = 'block'
            deployment_gates.labels(decision='block').inc()
        else:
            deployment_gates.labels(decision='proceed').inc()
            
        return results
        
    async def setup_webhooks(self, webhook_url: str, events: List[str]) -> None:
        """Setup GitHub webhooks for test automation."""
        url = f"{self.config.base_url}/repos/{self.config.repository}/hooks"
        
        data = {
            'name': 'web',
            'active': True,
            'events': events,
            'config': {
                'url': webhook_url,
                'content_type': 'json',
                'insecure_ssl': '0'
            }
        }
        
        if self.config.webhook_secret:
            data['config']['secret'] = self.config.webhook_secret
            
        response = self.session.post(url, json=data)
        response.raise_for_status()
        
        logger.info(f"Setup webhook for events: {events}")
        
    def handle_webhook(self, payload: Dict[str, Any], headers: Dict[str, str]) -> Optional[TestExecutionRequest]:
        """Handle incoming webhook payload."""
        event_type = headers.get('X-GitHub-Event')
        
        if event_type == 'push':
            return self._handle_push_event(payload)
        elif event_type == 'pull_request':
            return self._handle_pull_request_event(payload)
        elif event_type == 'workflow_run':
            return self._handle_workflow_run_event(payload)
        else:
            logger.info(f"Unhandled webhook event: {event_type}")
            return None
            
    def _handle_push_event(self, payload: Dict[str, Any]) -> TestExecutionRequest:
        """Handle push event webhook."""
        return TestExecutionRequest(
            repository=payload['repository']['full_name'],
            ref=payload['ref'],
            sha=payload['head_commit']['id'],
            event_type=WorkflowEvent.PUSH,
            workflow_id='push-triggered-tests',
            run_id=0,  # Will be set when workflow is triggered
            environment=self.config.environment,
            test_suites=['unit', 'integration', 'performance'],
            quality_gates={
                'min_success_rate': 0.95,
                'min_quality_score': 80.0,
                'max_anomalies': 3
            }
        )
        
    def _handle_pull_request_event(self, payload: Dict[str, Any]) -> TestExecutionRequest:
        """Handle pull request event webhook."""
        return TestExecutionRequest(
            repository=payload['repository']['full_name'],
            ref=payload['pull_request']['head']['ref'],
            sha=payload['pull_request']['head']['sha'],
            event_type=WorkflowEvent.PULL_REQUEST,
            workflow_id='pr-tests',
            run_id=0,
            environment='staging',
            test_suites=['unit', 'integration'],
            quality_gates={
                'min_success_rate': 0.90,
                'min_quality_score': 75.0,
                'max_anomalies': 5
            }
        )
        
    def _handle_workflow_run_event(self, payload: Dict[str, Any]) -> Optional[TestExecutionRequest]:
        """Handle workflow run event webhook."""
        if payload['action'] == 'completed':
            # Trigger additional tests based on workflow completion
            return None  # Implementation depends on specific requirements
        return None


# Example usage and helper scripts
def create_quality_gate_script() -> str:
    """Create quality gate evaluation script."""
    return '''#!/usr/bin/env python3
"""
Quality Gate Evaluation Script for GitHub Actions.
"""

import argparse
import json
import sys
from pathlib import Path


def evaluate_quality_gates(results_dir: str, output_file: str) -> None:
    """Evaluate quality gates from test results."""
    results_path = Path(results_dir)
    
    # Aggregate results from all test artifacts
    total_tests = 0
    passed_tests = 0
    quality_scores = []
    anomaly_counts = []
    
    # Process all result files
    for result_file in results_path.rglob("*.json"):
        try:
            with open(result_file) as f:
                data = json.load(f)
                
            # Extract metrics based on file structure
            if 'summary' in data:
                summary = data['summary']['execution_summary']
                total_tests += summary['total_tests']
                passed_tests += summary['passed_tests']
                
            if 'quality_score' in data:
                quality_scores.append(data['quality_score'])
                
            if 'anomalies' in data:
                anomaly_counts.append(len(data['anomalies']))
                
        except Exception as e:
            print(f"Error processing {result_file}: {e}")
            
    # Calculate overall metrics
    success_rate = passed_tests / total_tests if total_tests > 0 else 0
    avg_quality_score = sum(quality_scores) / len(quality_scores) if quality_scores else 0
    total_anomalies = sum(anomaly_counts)
    
    # Evaluate gates
    quality_gates = {
        'min_success_rate': 0.95,
        'min_quality_score': 80.0,
        'max_anomalies': 5
    }
    
    result = {
        'passed': True,
        'failures': [],
        'metrics': {
            'success_rate': success_rate,
            'quality_score': avg_quality_score,
            'total_anomalies': total_anomalies
        }
    }
    
    # Check each gate
    if success_rate < quality_gates['min_success_rate']:
        result['passed'] = False
        result['failures'].append(f"Success rate {success_rate:.1%} below {quality_gates['min_success_rate']:.1%}")
        
    if avg_quality_score < quality_gates['min_quality_score']:
        result['passed'] = False
        result['failures'].append(f"Quality score {avg_quality_score:.1f} below {quality_gates['min_quality_score']}")
        
    if total_anomalies > quality_gates['max_anomalies']:
        result['passed'] = False
        result['failures'].append(f"Anomalies {total_anomalies} exceed {quality_gates['max_anomalies']}")
        
    # Write result
    with open(output_file, 'w') as f:
        json.dump(result, f, indent=2)
        
    print(f"Quality gate evaluation: {'PASSED' if result['passed'] else 'FAILED'}")
    if result['failures']:
        for failure in result['failures']:
            print(f"  - {failure}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate quality gates")
    parser.add_argument("--results-dir", required=True, help="Results directory")
    parser.add_argument("--output", required=True, help="Output file")
    
    args = parser.parse_args()
    evaluate_quality_gates(args.results_dir, args.output)
'''


# Example usage
if __name__ == "__main__":
    import asyncio
    
    async def main():
        # Configuration (would normally come from environment variables)
        config = GitHubActionsConfig(
            repository="owner/repo",
            token="github_token_here",
            environment="testing"
        )
        
        integration = GitHubActionsIntegration(config)
        
        # Create workflow files
        await integration.create_workflow_file('stress_testing')
        await integration.create_workflow_file('chaos_testing')
        await integration.create_workflow_file('performance_testing')
        await integration.create_workflow_file('full_suite')
        
        print("GitHub Actions workflow files created successfully!")
        
        # Create quality gate script
        script_content = create_quality_gate_script()
        with open('scripts/evaluate_quality_gates.py', 'w') as f:
            f.write(script_content)
            
        print("Quality gate evaluation script created!")
        
    asyncio.run(main())