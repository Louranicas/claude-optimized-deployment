#!/usr/bin/env python3
"""
Pipeline Automation Tools
Comprehensive tools for managing CI/CD pipeline automation.
"""

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import argparse
import yaml
import requests
from dataclasses import dataclass


@dataclass
class PipelineConfig:
    """Pipeline configuration settings"""
    github_token: str
    repository: str
    environments: List[str]
    notification_webhook: Optional[str] = None
    slack_webhook: Optional[str] = None
    monitoring_enabled: bool = True


class PipelineAutomation:
    """Main pipeline automation class"""
    
    def __init__(self, config: PipelineConfig):
        self.config = config
        self.headers = {
            'Authorization': f'token {config.github_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        self.base_url = f'https://api.github.com/repos/{config.repository}'
    
    def trigger_workflow(self, workflow_name: str, inputs: Dict[str, Any] = None) -> Dict[str, Any]:
        """Trigger a GitHub Actions workflow"""
        url = f"{self.base_url}/actions/workflows/{workflow_name}/dispatches"
        
        payload = {
            'ref': 'main',
            'inputs': inputs or {}
        }
        
        response = requests.post(url, headers=self.headers, json=payload)
        
        if response.status_code == 204:
            print(f"✅ Successfully triggered workflow: {workflow_name}")
            return {'status': 'success', 'workflow': workflow_name}
        else:
            print(f"❌ Failed to trigger workflow: {workflow_name}")
            print(f"Status: {response.status_code}, Response: {response.text}")
            return {'status': 'error', 'message': response.text}
    
    def get_workflow_runs(self, workflow_name: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent workflow runs"""
        url = f"{self.base_url}/actions/workflows/{workflow_name}/runs"
        params = {'per_page': limit}
        
        response = requests.get(url, headers=self.headers, params=params)
        
        if response.status_code == 200:
            return response.json().get('workflow_runs', [])
        else:
            print(f"❌ Failed to get workflow runs: {response.status_code}")
            return []
    
    def wait_for_workflow(self, run_id: int, timeout: int = 1800) -> Dict[str, Any]:
        """Wait for a workflow run to complete"""
        url = f"{self.base_url}/actions/runs/{run_id}"
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                run_data = response.json()
                status = run_data.get('status')
                conclusion = run_data.get('conclusion')
                
                if status == 'completed':
                    return {
                        'status': 'completed',
                        'conclusion': conclusion,
                        'run_data': run_data
                    }
                
                print(f"⏳ Workflow {run_id} status: {status}")
                time.sleep(30)
            else:
                print(f"❌ Error checking workflow status: {response.status_code}")
                break
        
        return {'status': 'timeout', 'message': f'Workflow did not complete within {timeout} seconds'}
    
    def deploy_to_environment(self, environment: str, version: str = None, strategy: str = 'rolling') -> Dict[str, Any]:
        """Deploy to a specific environment"""
        inputs = {
            'environment': environment,
            'strategy': strategy
        }
        
        if version:
            inputs['version'] = version
        
        print(f"🚀 Deploying to {environment} with {strategy} strategy")
        
        # Trigger deployment workflow
        result = self.trigger_workflow('deployment.yml', inputs)
        
        if result['status'] == 'success':
            # Wait for deployment to complete
            runs = self.get_workflow_runs('deployment.yml', 1)
            if runs:
                run_id = runs[0]['id']
                completion_result = self.wait_for_workflow(run_id)
                
                if completion_result['status'] == 'completed':
                    if completion_result['conclusion'] == 'success':
                        print(f"✅ Deployment to {environment} completed successfully")
                        
                        # Send notification
                        self.send_notification(
                            f"✅ Deployment Success",
                            f"Successfully deployed to {environment} using {strategy} strategy"
                        )
                        
                        return {'status': 'success', 'environment': environment}
                    else:
                        print(f"❌ Deployment to {environment} failed")
                        
                        # Send failure notification
                        self.send_notification(
                            f"❌ Deployment Failed",
                            f"Deployment to {environment} failed with conclusion: {completion_result['conclusion']}"
                        )
                        
                        return {'status': 'failed', 'conclusion': completion_result['conclusion']}
                else:
                    return completion_result
        
        return result
    
    def rollback_deployment(self, environment: str, version: str = None) -> Dict[str, Any]:
        """Rollback deployment in an environment"""
        inputs = {
            'environment': environment,
            'rollback': True
        }
        
        if version:
            inputs['version'] = version
        
        print(f"🔄 Rolling back deployment in {environment}")
        
        # Trigger rollback
        result = self.trigger_workflow('deployment.yml', inputs)
        
        if result['status'] == 'success':
            self.send_notification(
                f"🔄 Rollback Initiated",
                f"Rollback initiated for {environment} environment"
            )
        
        return result
    
    def run_security_scan(self) -> Dict[str, Any]:
        """Run comprehensive security scan"""
        print("🔒 Running security scan...")
        
        result = self.trigger_workflow('security-audit.yml')
        
        if result['status'] == 'success':
            # Wait for scan to complete
            runs = self.get_workflow_runs('security-audit.yml', 1)
            if runs:
                run_id = runs[0]['id']
                completion_result = self.wait_for_workflow(run_id, 900)  # 15 minute timeout
                
                if completion_result['status'] == 'completed':
                    # Download and analyze security reports
                    artifacts = self.get_workflow_artifacts(run_id)
                    security_summary = self.analyze_security_artifacts(artifacts)
                    
                    return {
                        'status': 'completed',
                        'security_summary': security_summary,
                        'artifacts': artifacts
                    }
        
        return result
    
    def get_workflow_artifacts(self, run_id: int) -> List[Dict[str, Any]]:
        """Get artifacts from a workflow run"""
        url = f"{self.base_url}/actions/runs/{run_id}/artifacts"
        
        response = requests.get(url, headers=self.headers)
        
        if response.status_code == 200:
            return response.json().get('artifacts', [])
        else:
            print(f"❌ Failed to get artifacts: {response.status_code}")
            return []
    
    def analyze_security_artifacts(self, artifacts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze security scan artifacts"""
        summary = {
            'vulnerabilities_found': 0,
            'high_severity': 0,
            'medium_severity': 0,
            'low_severity': 0,
            'recommendations': []
        }
        
        # This would analyze actual security reports
        # For now, return placeholder data
        summary['recommendations'] = [
            "Update dependencies with known vulnerabilities",
            "Review and fix any high-severity security issues",
            "Implement additional security headers"
        ]
        
        return summary
    
    def send_notification(self, title: str, message: str) -> None:
        """Send notification via configured channels"""
        if self.config.slack_webhook:
            self._send_slack_notification(title, message)
        
        if self.config.notification_webhook:
            self._send_webhook_notification(title, message)
    
    def _send_slack_notification(self, title: str, message: str) -> None:
        """Send Slack notification"""
        payload = {
            'text': f"{title}\\n{message}",
            'username': 'CI/CD Pipeline',
            'icon_emoji': ':robot_face:'
        }
        
        try:
            response = requests.post(self.config.slack_webhook, json=payload)
            if response.status_code == 200:
                print("📱 Slack notification sent")
            else:
                print(f"❌ Failed to send Slack notification: {response.status_code}")
        except Exception as e:
            print(f"❌ Error sending Slack notification: {e}")
    
    def _send_webhook_notification(self, title: str, message: str) -> None:
        """Send generic webhook notification"""
        payload = {
            'title': title,
            'message': message,
            'timestamp': datetime.now().isoformat(),
            'repository': self.config.repository
        }
        
        try:
            response = requests.post(self.config.notification_webhook, json=payload)
            if response.status_code == 200:
                print("📧 Webhook notification sent")
            else:
                print(f"❌ Failed to send webhook notification: {response.status_code}")
        except Exception as e:
            print(f"❌ Error sending webhook notification: {e}")


class PipelineMetrics:
    """Pipeline metrics collection and analysis"""
    
    def __init__(self, config: PipelineConfig):
        self.config = config
        self.headers = {
            'Authorization': f'token {config.github_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        self.base_url = f'https://api.github.com/repos/{config.repository}'
    
    def collect_pipeline_metrics(self, days: int = 30) -> Dict[str, Any]:
        """Collect comprehensive pipeline metrics"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # Get workflow runs
        runs = self._get_workflow_runs_in_period(start_date, end_date)
        
        # Calculate metrics
        metrics = self._calculate_metrics(runs)
        
        # Add system metrics
        metrics['system_info'] = self._get_system_metrics()
        
        # Add quality metrics
        metrics['quality_metrics'] = self._get_quality_metrics()
        
        return metrics
    
    def _get_workflow_runs_in_period(self, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """Get workflow runs within a specific period"""
        url = f"{self.base_url}/actions/runs"
        params = {
            'per_page': 100,
            'created': f">{start_date.isoformat()}"
        }
        
        all_runs = []
        page = 1
        
        while page <= 10:  # Limit to 10 pages to avoid rate limits
            params['page'] = page
            response = requests.get(url, headers=self.headers, params=params)
            
            if response.status_code == 200:
                data = response.json()
                runs = data.get('workflow_runs', [])
                
                if not runs:
                    break
                
                # Filter runs by date
                for run in runs:
                    created_at = datetime.fromisoformat(run['created_at'].replace('Z', '+00:00'))
                    if start_date <= created_at <= end_date:
                        all_runs.append(run)
                
                page += 1
            else:
                print(f"❌ Error fetching workflow runs: {response.status_code}")
                break
        
        return all_runs
    
    def _calculate_metrics(self, runs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate pipeline metrics from runs"""
        total_runs = len(runs)
        successful_runs = len([r for r in runs if r.get('conclusion') == 'success'])
        failed_runs = len([r for r in runs if r.get('conclusion') == 'failure'])
        cancelled_runs = len([r for r in runs if r.get('conclusion') == 'cancelled'])
        
        # Calculate durations
        durations = []
        for run in runs:
            if run.get('conclusion') in ['success', 'failure']:
                created = datetime.fromisoformat(run['created_at'].replace('Z', '+00:00'))
                updated = datetime.fromisoformat(run['updated_at'].replace('Z', '+00:00'))
                duration = (updated - created).total_seconds()
                durations.append(duration)
        
        avg_duration = sum(durations) / len(durations) if durations else 0
        
        # Calculate success rate
        success_rate = (successful_runs / total_runs * 100) if total_runs > 0 else 0
        
        # Calculate MTTR (Mean Time To Recovery) - time between failure and next success
        mttr = self._calculate_mttr(runs)
        
        # Calculate deployment frequency
        deployment_frequency = self._calculate_deployment_frequency(runs)
        
        return {
            'total_runs': total_runs,
            'successful_runs': successful_runs,
            'failed_runs': failed_runs,
            'cancelled_runs': cancelled_runs,
            'success_rate': round(success_rate, 2),
            'average_duration_seconds': round(avg_duration, 2),
            'average_duration_minutes': round(avg_duration / 60, 2),
            'mttr_hours': round(mttr, 2),
            'deployment_frequency_per_day': round(deployment_frequency, 2),
            'quality_score': self._calculate_quality_score(success_rate, avg_duration, mttr)
        }
    
    def _calculate_mttr(self, runs: List[Dict[str, Any]]) -> float:
        """Calculate Mean Time To Recovery"""
        failures = [r for r in runs if r.get('conclusion') == 'failure']
        
        if not failures:
            return 0
        
        recovery_times = []
        
        for failure in failures:
            failure_time = datetime.fromisoformat(failure['updated_at'].replace('Z', '+00:00'))
            
            # Find next successful run after this failure
            next_success = None
            for run in runs:
                if run.get('conclusion') == 'success':
                    run_time = datetime.fromisoformat(run['created_at'].replace('Z', '+00:00'))
                    if run_time > failure_time:
                        if not next_success or run_time < datetime.fromisoformat(next_success['created_at'].replace('Z', '+00:00')):
                            next_success = run
            
            if next_success:
                recovery_time = datetime.fromisoformat(next_success['created_at'].replace('Z', '+00:00'))
                recovery_duration = (recovery_time - failure_time).total_seconds() / 3600  # Convert to hours
                recovery_times.append(recovery_duration)
        
        return sum(recovery_times) / len(recovery_times) if recovery_times else 0
    
    def _calculate_deployment_frequency(self, runs: List[Dict[str, Any]]) -> float:
        """Calculate deployment frequency per day"""
        deployment_runs = [r for r in runs if 'deploy' in r.get('name', '').lower()]
        
        if not deployment_runs:
            return 0
        
        # Get date range
        dates = [datetime.fromisoformat(r['created_at'].replace('Z', '+00:00')).date() for r in deployment_runs]
        if not dates:
            return 0
        
        date_range = (max(dates) - min(dates)).days
        if date_range == 0:
            date_range = 1
        
        return len(deployment_runs) / date_range
    
    def _calculate_quality_score(self, success_rate: float, avg_duration: float, mttr: float) -> float:
        """Calculate overall pipeline quality score (0-100)"""
        # Normalize metrics
        success_score = success_rate  # Already 0-100
        
        # Duration score (penalize long build times)
        duration_score = max(0, 100 - (avg_duration / 60))  # Penalty after 1 minute
        
        # MTTR score (penalize long recovery times)
        mttr_score = max(0, 100 - mttr)  # Penalty after 1 hour
        
        # Weighted average
        quality_score = (success_score * 0.5) + (duration_score * 0.3) + (mttr_score * 0.2)
        
        return round(quality_score, 2)
    
    def _get_system_metrics(self) -> Dict[str, Any]:
        """Get system-level metrics"""
        try:
            import psutil
            
            return {
                'cpu_count': psutil.cpu_count(),
                'memory_total_gb': round(psutil.virtual_memory().total / (1024**3), 2),
                'disk_total_gb': round(psutil.disk_usage('/').total / (1024**3), 2),
                'python_version': sys.version,
                'platform': sys.platform
            }
        except ImportError:
            return {'status': 'psutil not available'}
    
    def _get_quality_metrics(self) -> Dict[str, Any]:
        """Get code quality metrics"""
        quality_metrics = {
            'test_coverage': 0,
            'lines_of_code': 0,
            'files_count': 0,
            'last_analysis': datetime.now().isoformat()
        }
        
        # Try to get coverage from coverage.xml
        coverage_file = Path('coverage.xml')
        if coverage_file.exists():
            try:
                import xml.etree.ElementTree as ET
                tree = ET.parse(coverage_file)
                root = tree.getroot()
                line_rate = root.get('line-rate')
                if line_rate:
                    quality_metrics['test_coverage'] = round(float(line_rate) * 100, 2)
            except Exception as e:
                print(f"Warning: Could not parse coverage.xml: {e}")
        
        # Count lines of code
        try:
            for ext in ['*.py', '*.rs', '*.js', '*.ts']:
                files = list(Path('.').rglob(ext))
                quality_metrics['files_count'] += len(files)
                
                for file in files:
                    try:
                        with open(file, 'r', encoding='utf-8') as f:
                            quality_metrics['lines_of_code'] += len(f.readlines())
                    except:
                        pass
        except Exception as e:
            print(f"Warning: Could not count lines of code: {e}")
        
        return quality_metrics


class PipelineCLI:
    """Command-line interface for pipeline automation"""
    
    def __init__(self):
        self.config = self._load_config()
        self.automation = PipelineAutomation(self.config)
        self.metrics = PipelineMetrics(self.config)
    
    def _load_config(self) -> PipelineConfig:
        """Load configuration from environment and files"""
        github_token = os.getenv('GITHUB_TOKEN')
        if not github_token:
            raise ValueError("GITHUB_TOKEN environment variable is required")
        
        repository = os.getenv('GITHUB_REPOSITORY', 'your-org/claude-optimized-deployment')
        
        environments = os.getenv('PIPELINE_ENVIRONMENTS', 'development,staging,production').split(',')
        
        return PipelineConfig(
            github_token=github_token,
            repository=repository,
            environments=environments,
            notification_webhook=os.getenv('NOTIFICATION_WEBHOOK'),
            slack_webhook=os.getenv('SLACK_WEBHOOK'),
            monitoring_enabled=os.getenv('MONITORING_ENABLED', 'true').lower() == 'true'
        )
    
    def run(self):
        """Main CLI entry point"""
        parser = argparse.ArgumentParser(description='Pipeline Automation Tools')
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # Deploy command
        deploy_parser = subparsers.add_parser('deploy', help='Deploy to environment')
        deploy_parser.add_argument('environment', choices=self.config.environments)
        deploy_parser.add_argument('--version', help='Version to deploy')
        deploy_parser.add_argument('--strategy', choices=['rolling', 'blue-green', 'canary'], default='rolling')
        
        # Rollback command
        rollback_parser = subparsers.add_parser('rollback', help='Rollback deployment')
        rollback_parser.add_argument('environment', choices=self.config.environments)
        rollback_parser.add_argument('--version', help='Version to rollback to')
        
        # Security scan command
        subparsers.add_parser('security-scan', help='Run security scan')
        
        # Metrics command
        metrics_parser = subparsers.add_parser('metrics', help='Collect pipeline metrics')
        metrics_parser.add_argument('--days', type=int, default=30, help='Number of days to analyze')
        metrics_parser.add_argument('--output', help='Output file for metrics')
        
        # Trigger workflow command
        trigger_parser = subparsers.add_parser('trigger', help='Trigger workflow')
        trigger_parser.add_argument('workflow', help='Workflow file name')
        trigger_parser.add_argument('--inputs', help='JSON string of inputs')
        
        args = parser.parse_args()
        
        if not args.command:
            parser.print_help()
            return
        
        try:
            if args.command == 'deploy':
                result = self.automation.deploy_to_environment(
                    args.environment, 
                    args.version, 
                    args.strategy
                )
                print(json.dumps(result, indent=2))
            
            elif args.command == 'rollback':
                result = self.automation.rollback_deployment(
                    args.environment, 
                    args.version
                )
                print(json.dumps(result, indent=2))
            
            elif args.command == 'security-scan':
                result = self.automation.run_security_scan()
                print(json.dumps(result, indent=2))
            
            elif args.command == 'metrics':
                metrics_data = self.metrics.collect_pipeline_metrics(args.days)
                
                if args.output:
                    with open(args.output, 'w') as f:
                        json.dump(metrics_data, f, indent=2)
                    print(f"Metrics saved to {args.output}")
                else:
                    print(json.dumps(metrics_data, indent=2))
            
            elif args.command == 'trigger':
                inputs = {}
                if args.inputs:
                    inputs = json.loads(args.inputs)
                
                result = self.automation.trigger_workflow(args.workflow, inputs)
                print(json.dumps(result, indent=2))
        
        except Exception as e:
            print(f"❌ Error: {e}")
            sys.exit(1)


if __name__ == '__main__':
    cli = PipelineCLI()
    cli.run()