#!/usr/bin/env python3
"""
Pipeline Setup and Configuration Script
Comprehensive setup for the CI/CD pipeline infrastructure.
"""

import os
import sys
import json
import subprocess
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
import argparse
import shutil
import stat


class PipelineSetup:
    """Complete pipeline setup and configuration"""
    
    def __init__(self, project_root: Path = None):
        self.project_root = project_root or Path.cwd()
        self.github_dir = self.project_root / '.github'
        self.workflows_dir = self.github_dir / 'workflows'
        self.scripts_dir = self.project_root / 'scripts'
        
    def setup_complete_pipeline(self) -> None:
        """Set up the complete CI/CD pipeline"""
        print("🚀 Setting up CI/CD Pipeline Infrastructure...")
        
        # Ensure directories exist
        self._create_directories()
        
        # Validate existing workflows
        self._validate_workflows()
        
        # Setup pipeline tools
        self._setup_pipeline_tools()
        
        # Configure environment
        self._setup_environment()
        
        # Setup monitoring
        self._setup_monitoring()
        
        # Create documentation
        self._create_documentation()
        
        # Validate configuration
        self._validate_configuration()
        
        print("✅ Pipeline setup completed successfully!")
        self._print_next_steps()
    
    def _create_directories(self) -> None:
        """Create necessary directories"""
        directories = [
            self.github_dir,
            self.workflows_dir,
            self.github_dir / 'ISSUE_TEMPLATE',
            self.scripts_dir,
            self.project_root / 'docs',
            self.project_root / 'deploy' / 'environments' / 'development',
            self.project_root / 'deploy' / 'environments' / 'staging',
            self.project_root / 'deploy' / 'environments' / 'production',
            self.project_root / 'monitoring',
            self.project_root / 'k8s'
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            print(f"📁 Created directory: {directory}")
    
    def _validate_workflows(self) -> None:
        """Validate existing workflow files"""
        required_workflows = [
            'ci-enhanced.yml',
            'deployment.yml',
            'monitoring.yml',
            'container-optimization.yml'
        ]
        
        print("🔍 Validating workflow files...")
        
        for workflow in required_workflows:
            workflow_path = self.workflows_dir / workflow
            if workflow_path.exists():
                print(f"✅ Found workflow: {workflow}")
                
                # Validate YAML syntax
                try:
                    with open(workflow_path, 'r') as f:
                        yaml.safe_load(f)
                    print(f"   ✅ Valid YAML syntax")
                except yaml.YAMLError as e:
                    print(f"   ❌ Invalid YAML: {e}")
            else:
                print(f"❌ Missing workflow: {workflow}")
    
    def _setup_pipeline_tools(self) -> None:
        """Set up pipeline automation tools"""
        print("🛠️ Setting up pipeline tools...")
        
        # Make pipeline tools executable
        pipeline_tools = self.scripts_dir / 'pipeline_tools.py'
        if pipeline_tools.exists():
            pipeline_tools.chmod(pipeline_tools.stat().st_mode | stat.S_IEXEC)
            print(f"✅ Made executable: {pipeline_tools}")
        
        # Create pipeline CLI wrapper
        cli_wrapper = self.scripts_dir / 'pipeline'
        with open(cli_wrapper, 'w') as f:
            f.write(f"""#!/bin/bash
# Pipeline CLI Wrapper
SCRIPT_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
python3 "$SCRIPT_DIR/pipeline_tools.py" "$@"
""")
        cli_wrapper.chmod(cli_wrapper.stat().st_mode | stat.S_IEXEC)
        print(f"✅ Created CLI wrapper: {cli_wrapper}")
        
        # Install required Python packages
        self._install_python_dependencies()
    
    def _install_python_dependencies(self) -> None:
        """Install required Python dependencies for pipeline tools"""
        required_packages = [
            'requests>=2.31.0',
            'pyyaml>=6.0',
            'psutil>=5.9.0',
            'click>=8.1.0',
            'rich>=13.0.0'
        ]
        
        print("📦 Installing pipeline dependencies...")
        
        for package in required_packages:
            try:
                subprocess.run([
                    sys.executable, '-m', 'pip', 'install', package
                ], check=True, capture_output=True)
                print(f"   ✅ Installed: {package}")
            except subprocess.CalledProcessError as e:
                print(f"   ⚠️ Failed to install: {package} - {e}")
    
    def _setup_environment(self) -> None:
        """Set up environment configuration"""
        print("🔧 Setting up environment configuration...")
        
        # Create .env.example file
        env_example = self.project_root / '.env.example'
        with open(env_example, 'w') as f:
            f.write("""# Pipeline Environment Configuration

# Required: GitHub configuration
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
GITHUB_REPOSITORY=your-org/claude-optimized-deployment

# Optional: Notification webhooks
SLACK_WEBHOOK=https://hooks.slack.com/services/xxx/xxx/xxx
NOTIFICATION_WEBHOOK=https://api.yourcompany.com/notifications

# Optional: Pipeline configuration
PIPELINE_ENVIRONMENTS=development,staging,production
MONITORING_ENABLED=true

# Optional: Security scanning
SNYK_TOKEN=your-snyk-token
FOSSA_API_KEY=your-fossa-api-key

# Optional: Cloud configuration
AWS_REGION=us-west-2
AWS_PROFILE=default

# Optional: Container registry
CONTAINER_REGISTRY=ghcr.io
CONTAINER_NAMESPACE=your-org
""")
        print(f"✅ Created: {env_example}")
        
        # Create pipeline configuration file
        pipeline_config = self.project_root / 'pipeline.yml'
        config_data = {
            'pipeline': {
                'name': 'claude-optimized-deployment',
                'version': '1.0.0',
                'environments': ['development', 'staging', 'production'],
                'default_strategy': 'rolling'
            },
            'build': {
                'parallel_jobs': 16,
                'timeout_minutes': 30,
                'cache_enabled': True,
                'optimization_level': 'standard'
            },
            'testing': {
                'parallel_workers': 16,
                'coverage_threshold': 80,
                'timeout_minutes': 20,
                'benchmark_enabled': True
            },
            'security': {
                'scanners': ['trivy', 'grype', 'snyk'],
                'critical_threshold': 0,
                'high_threshold': 5,
                'fail_on_critical': True
            },
            'deployment': {
                'strategies': {
                    'development': 'rolling',
                    'staging': 'blue-green',
                    'production': 'canary'
                },
                'rollback_enabled': True,
                'health_checks': True
            },
            'monitoring': {
                'metrics_enabled': True,
                'alerting_enabled': True,
                'retention_days': 30,
                'dashboard_enabled': True
            }
        }
        
        with open(pipeline_config, 'w') as f:
            yaml.dump(config_data, f, default_flow_style=False, indent=2)
        print(f"✅ Created: {pipeline_config}")
    
    def _setup_monitoring(self) -> None:
        """Set up monitoring configuration"""
        print("📊 Setting up monitoring configuration...")
        
        # Create Prometheus configuration
        prometheus_config = self.project_root / 'monitoring' / 'prometheus.yml'
        prometheus_data = {
            'global': {
                'scrape_interval': '15s',
                'evaluation_interval': '15s'
            },
            'rule_files': [
                'alert_rules.yml',
                'recording_rules.yml'
            ],
            'scrape_configs': [
                {
                    'job_name': 'claude-deployment',
                    'static_configs': [
                        {'targets': ['localhost:8000']}
                    ],
                    'metrics_path': '/metrics',
                    'scrape_interval': '30s'
                },
                {
                    'job_name': 'github-actions',
                    'static_configs': [
                        {'targets': ['api.github.com:443']}
                    ],
                    'scheme': 'https'
                }
            ],
            'alerting': {
                'alertmanagers': [
                    {
                        'static_configs': [
                            {'targets': ['localhost:9093']}
                        ]
                    }
                ]
            }
        }
        
        with open(prometheus_config, 'w') as f:
            yaml.dump(prometheus_data, f, default_flow_style=False, indent=2)
        print(f"✅ Created: {prometheus_config}")
        
        # Create alert rules
        alert_rules = self.project_root / 'monitoring' / 'alert_rules.yml'
        alert_data = {
            'groups': [
                {
                    'name': 'pipeline_alerts',
                    'rules': [
                        {
                            'alert': 'PipelineFailureRate',
                            'expr': 'rate(github_actions_workflow_failure_total[5m]) > 0.1',
                            'for': '5m',
                            'labels': {'severity': 'warning'},
                            'annotations': {
                                'summary': 'High pipeline failure rate detected',
                                'description': 'Pipeline failure rate is {{ $value }} failures per second'
                            }
                        },
                        {
                            'alert': 'DeploymentFailure',
                            'expr': 'increase(github_actions_deployment_failure_total[1h]) > 0',
                            'for': '0m',
                            'labels': {'severity': 'critical'},
                            'annotations': {
                                'summary': 'Deployment failure detected',
                                'description': 'A deployment has failed in the last hour'
                            }
                        },
                        {
                            'alert': 'SecurityVulnerabilities',
                            'expr': 'security_scan_critical_vulnerabilities > 0',
                            'for': '0m',
                            'labels': {'severity': 'critical'},
                            'annotations': {
                                'summary': 'Critical security vulnerabilities found',
                                'description': '{{ $value }} critical vulnerabilities detected'
                            }
                        }
                    ]
                }
            ]
        }
        
        with open(alert_rules, 'w') as f:
            yaml.dump(alert_data, f, default_flow_style=False, indent=2)
        print(f"✅ Created: {alert_rules}")
        
        # Create Grafana dashboard configuration
        self._create_grafana_dashboards()
    
    def _create_grafana_dashboards(self) -> None:
        """Create Grafana dashboard configurations"""
        dashboards_dir = self.project_root / 'monitoring' / 'dashboards'
        dashboards_dir.mkdir(exist_ok=True)
        
        # Pipeline overview dashboard
        pipeline_dashboard = {
            "dashboard": {
                "id": None,
                "title": "CI/CD Pipeline Overview",
                "tags": ["pipeline", "cicd"],
                "timezone": "browser",
                "panels": [
                    {
                        "id": 1,
                        "title": "Build Success Rate",
                        "type": "stat",
                        "targets": [
                            {
                                "expr": "rate(github_actions_workflow_success_total[24h]) / rate(github_actions_workflow_total[24h]) * 100",
                                "legendFormat": "Success Rate %"
                            }
                        ],
                        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0}
                    },
                    {
                        "id": 2,
                        "title": "Average Build Time",
                        "type": "stat",
                        "targets": [
                            {
                                "expr": "avg(github_actions_workflow_duration_seconds)",
                                "legendFormat": "Avg Duration"
                            }
                        ],
                        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0}
                    },
                    {
                        "id": 3,
                        "title": "Deployment Frequency",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "rate(github_actions_deployment_total[1h])",
                                "legendFormat": "Deployments/hour"
                            }
                        ],
                        "gridPos": {"h": 8, "w": 24, "x": 0, "y": 8}
                    }
                ],
                "time": {"from": "now-24h", "to": "now"},
                "refresh": "5m"
            }
        }
        
        dashboard_file = dashboards_dir / 'pipeline-overview.json'
        with open(dashboard_file, 'w') as f:
            json.dump(pipeline_dashboard, f, indent=2)
        print(f"✅ Created dashboard: {dashboard_file}")
    
    def _create_documentation(self) -> None:
        """Create additional documentation files"""
        print("📚 Creating documentation...")
        
        # Create README for CI/CD
        cicd_readme = self.project_root / 'docs' / 'CICD_README.md'
        with open(cicd_readme, 'w') as f:
            f.write("""# CI/CD Pipeline

## Quick Start

1. **Set up environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements-dev.txt
   ```

3. **Run pipeline tools:**
   ```bash
   # Check pipeline status
   ./scripts/pipeline metrics
   
   # Deploy to development
   ./scripts/pipeline deploy development
   
   # Run security scan
   ./scripts/pipeline security-scan
   ```

## Workflows

- **CI/CD Enhanced** - Main build and test pipeline
- **Deployment** - Multi-strategy deployment pipeline
- **Container Optimization** - Docker optimization and security
- **Monitoring** - Metrics collection and reporting

## Configuration

See `pipeline.yml` for complete configuration options.

## Troubleshooting

See [CI/CD Best Practices](CICD_BEST_PRACTICES.md) for detailed troubleshooting guide.
""")
        print(f"✅ Created: {cicd_readme}")
        
        # Create deployment environment configurations
        for env in ['development', 'staging', 'production']:
            self._create_environment_config(env)
    
    def _create_environment_config(self, environment: str) -> None:
        """Create configuration for a specific environment"""
        env_dir = self.project_root / 'deploy' / 'environments' / environment
        
        # Kustomization file
        kustomization = env_dir / 'kustomization.yaml'
        kustomization_data = {
            'apiVersion': 'kustomize.config.k8s.io/v1beta1',
            'kind': 'Kustomization',
            'resources': [
                '../../base'
            ],
            'namePrefix': f'{environment}-',
            'namespace': environment,
            'commonLabels': {
                'environment': environment,
                'app': 'claude-optimized-deployment'
            },
            'images': [
                {
                    'name': 'app',
                    'newName': 'ghcr.io/your-org/claude-optimized-deployment',
                    'newTag': 'latest'
                }
            ]
        }
        
        # Environment-specific configuration
        if environment == 'production':
            kustomization_data['replicas'] = [
                {'name': 'app', 'count': 3}
            ]
            kustomization_data['patchesStrategicMerge'] = [
                'production-patches.yaml'
            ]
        elif environment == 'staging':
            kustomization_data['replicas'] = [
                {'name': 'app', 'count': 2}
            ]
        else:  # development
            kustomization_data['replicas'] = [
                {'name': 'app', 'count': 1}
            ]
        
        with open(kustomization, 'w') as f:
            yaml.dump(kustomization_data, f, default_flow_style=False, indent=2)
        
        # Environment configuration file
        config_file = env_dir / 'config.yaml'
        config_data = {
            'environment': environment,
            'deployment': {
                'strategy': 'rolling' if environment == 'development' else 'blue-green',
                'replicas': 1 if environment == 'development' else 2 if environment == 'staging' else 3,
                'resources': {
                    'requests': {
                        'cpu': '100m' if environment == 'development' else '200m',
                        'memory': '256Mi' if environment == 'development' else '512Mi'
                    },
                    'limits': {
                        'cpu': '500m' if environment == 'development' else '1000m',
                        'memory': '512Mi' if environment == 'development' else '1Gi'
                    }
                }
            },
            'security': {
                'scan_level': 'basic' if environment == 'development' else 'comprehensive',
                'vulnerability_threshold': {
                    'critical': 0,
                    'high': 5 if environment == 'development' else 2 if environment == 'staging' else 0
                }
            },
            'monitoring': {
                'enabled': True,
                'retention_days': 7 if environment == 'development' else 30,
                'alerting': environment == 'production'
            }
        }
        
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f, default_flow_style=False, indent=2)
        
        print(f"✅ Created environment config: {environment}")
    
    def _validate_configuration(self) -> None:
        """Validate the complete pipeline configuration"""
        print("🔍 Validating pipeline configuration...")
        
        # Check required files
        required_files = [
            '.env.example',
            'pipeline.yml',
            'docs/CICD_BEST_PRACTICES.md',
            'scripts/pipeline_tools.py',
            'monitoring/prometheus.yml'
        ]
        
        for file_path in required_files:
            full_path = self.project_root / file_path
            if full_path.exists():
                print(f"   ✅ {file_path}")
            else:
                print(f"   ❌ {file_path}")
        
        # Validate workflow syntax
        for workflow_file in self.workflows_dir.glob('*.yml'):
            try:
                with open(workflow_file, 'r') as f:
                    yaml.safe_load(f)
                print(f"   ✅ {workflow_file.name} (valid YAML)")
            except yaml.YAMLError as e:
                print(f"   ❌ {workflow_file.name} (invalid YAML): {e}")
        
        # Check Python dependencies
        try:
            import requests, yaml, psutil
            print("   ✅ Python dependencies installed")
        except ImportError as e:
            print(f"   ⚠️ Missing Python dependency: {e}")
        
        print("✅ Configuration validation completed")
    
    def _print_next_steps(self) -> None:
        """Print next steps for the user"""
        print("""
🎉 CI/CD Pipeline Setup Complete!

Next Steps:
===========

1. 📝 Configure Environment Variables:
   cp .env.example .env
   # Edit .env with your GitHub token and other settings

2. 🔧 Set up GitHub Secrets:
   - GITHUB_TOKEN (for API access)
   - SLACK_WEBHOOK (optional, for notifications)
   - CONTAINER_REGISTRY_TOKEN (for pushing images)

3. 🧪 Test the Pipeline:
   # Check pipeline status
   ./scripts/pipeline metrics --days 7
   
   # Trigger a test build
   gh workflow run ci-enhanced.yml

4. 🚀 Deploy to Development:
   ./scripts/pipeline deploy development

5. 📊 Set up Monitoring:
   # Review monitoring configuration
   cat monitoring/prometheus.yml
   
   # Deploy monitoring stack (if using Kubernetes)
   kubectl apply -f monitoring/

6. 📚 Read the Documentation:
   # Complete guide
   cat docs/CICD_BEST_PRACTICES.md
   
   # Quick reference
   cat docs/CICD_README.md

Useful Commands:
===============

# Pipeline management
./scripts/pipeline --help
./scripts/pipeline deploy --help
./scripts/pipeline metrics --help

# GitHub CLI (if installed)
gh workflow list
gh run list
gh run watch

# Docker commands
docker buildx build --tag myapp:test .
docker run --rm myapp:test

Need Help?
==========

- 📖 Documentation: docs/CICD_BEST_PRACTICES.md
- 🐛 Issues: Check workflow logs in GitHub Actions
- 🔧 Tools: ./scripts/pipeline --help

Happy deploying! 🚀
        """)


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(description='CI/CD Pipeline Setup Tool')
    parser.add_argument(
        '--project-root',
        type=Path,
        default=Path.cwd(),
        help='Project root directory'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be done without making changes'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Setup command
    setup_parser = subparsers.add_parser('setup', help='Set up complete pipeline')
    setup_parser.add_argument(
        '--force',
        action='store_true',
        help='Overwrite existing files'
    )
    
    # Validate command
    validate_parser = subparsers.add_parser('validate', help='Validate pipeline configuration')
    
    # Update command
    update_parser = subparsers.add_parser('update', help='Update pipeline configuration')
    update_parser.add_argument(
        '--component',
        choices=['workflows', 'monitoring', 'docs', 'all'],
        default='all',
        help='Component to update'
    )
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    setup = PipelineSetup(args.project_root)
    
    try:
        if args.command == 'setup':
            if args.dry_run:
                print("🔍 Dry run mode - showing what would be done:")
                print("- Create directory structure")
                print("- Validate existing workflows")
                print("- Set up pipeline tools")
                print("- Configure environment")
                print("- Create documentation")
            else:
                setup.setup_complete_pipeline()
        
        elif args.command == 'validate':
            setup._validate_configuration()
        
        elif args.command == 'update':
            print(f"🔄 Updating {args.component} component(s)...")
            if args.component in ['workflows', 'all']:
                setup._validate_workflows()
            if args.component in ['monitoring', 'all']:
                setup._setup_monitoring()
            if args.component in ['docs', 'all']:
                setup._create_documentation()
            print("✅ Update completed")
    
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()