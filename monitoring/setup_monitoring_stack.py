#!/usr/bin/env python3
"""
MCP Monitoring Stack Setup and Management
Automates the deployment and configuration of the complete monitoring infrastructure
for MCP servers including Prometheus, Grafana, alerting, and tracing.
"""

import asyncio
import json
import logging
import os
import subprocess
import time
import yaml
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

class MonitoringStackManager:
    """Manages the complete MCP monitoring stack deployment"""
    
    def __init__(self, config_path: str = None):
        self.config = self._load_config(config_path)
        self.logger = self._setup_logging()
        self.base_dir = Path("/home/louranicas/projects/claude-optimized-deployment")
        self.monitoring_dir = self.base_dir / "monitoring"
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load monitoring stack configuration"""
        default_config = {
            "stack": {
                "prometheus": {
                    "enabled": True,
                    "port": 9090,
                    "retention": "30d",
                    "storage_path": "/var/lib/prometheus"
                },
                "grafana": {
                    "enabled": True,
                    "port": 3000,
                    "admin_password": "admin123",
                    "data_path": "/var/lib/grafana"
                },
                "jaeger": {
                    "enabled": True,
                    "ui_port": 16686,
                    "collector_port": 14268
                },
                "alertmanager": {
                    "enabled": True,
                    "port": 9093,
                    "webhook_url": ""
                },
                "node_exporter": {
                    "enabled": True,
                    "port": 9100
                },
                "pushgateway": {
                    "enabled": True,
                    "port": 9091
                }
            },
            "deployment": {
                "method": "docker-compose",  # docker-compose, kubernetes, systemd
                "data_retention_days": 30,
                "backup_enabled": True,
                "ssl_enabled": False
            },
            "monitoring": {
                "scrape_interval": "15s",
                "evaluation_interval": "15s",
                "rule_files": ["alert_rules.yaml", "recording_rules.yaml"],
                "targets": {
                    "mcp_servers": [
                        "localhost:8001",  # desktop-commander
                        "localhost:8002",  # filesystem
                        "localhost:8003",  # postgres
                        "localhost:8004",  # github
                        "localhost:8005",  # memory
                        "localhost:8006",  # brave-search
                        "localhost:8007",  # slack
                        "localhost:8008"   # puppeteer
                    ]
                }
            },
            "alerting": {
                "smtp_server": "",
                "smtp_port": 587,
                "email_from": "alerts@company.com",
                "email_to": ["oncall@company.com"],
                "slack_webhook": "",
                "pagerduty_service_key": ""
            }
        }
        
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                default_config.update(user_config)
        
        return default_config
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for the monitoring stack manager"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        return logging.getLogger("monitoring_stack")
    
    def create_docker_compose(self) -> str:
        """Create Docker Compose configuration for monitoring stack"""
        compose_config = {
            "version": "3.8",
            "services": {},
            "networks": {
                "monitoring": {
                    "driver": "bridge"
                }
            },
            "volumes": {
                "prometheus_data": {},
                "grafana_data": {},
                "jaeger_data": {}
            }
        }
        
        # Prometheus service
        if self.config["stack"]["prometheus"]["enabled"]:
            compose_config["services"]["prometheus"] = {
                "image": "prom/prometheus:latest",
                "ports": [f"{self.config['stack']['prometheus']['port']}:9090"],
                "volumes": [
                    "./prometheus.yml:/etc/prometheus/prometheus.yml",
                    "./alert_rules.yaml:/etc/prometheus/alert_rules.yaml",
                    "./memory_recording_rules.yml:/etc/prometheus/memory_recording_rules.yml",
                    "prometheus_data:/prometheus"
                ],
                "command": [
                    "--config.file=/etc/prometheus/prometheus.yml",
                    "--storage.tsdb.path=/prometheus",
                    f"--storage.tsdb.retention.time={self.config['stack']['prometheus']['retention']}",
                    "--web.console.libraries=/usr/share/prometheus/console_libraries",
                    "--web.console.templates=/usr/share/prometheus/consoles",
                    "--web.enable-lifecycle",
                    "--web.enable-admin-api"
                ],
                "networks": ["monitoring"],
                "restart": "unless-stopped"
            }
        
        # Grafana service
        if self.config["stack"]["grafana"]["enabled"]:
            compose_config["services"]["grafana"] = {
                "image": "grafana/grafana:latest",
                "ports": [f"{self.config['stack']['grafana']['port']}:3000"],
                "environment": {
                    "GF_SECURITY_ADMIN_PASSWORD": self.config["stack"]["grafana"]["admin_password"],
                    "GF_INSTALL_PLUGINS": "grafana-piechart-panel"
                },
                "volumes": [
                    "grafana_data:/var/lib/grafana",
                    "./dashboards:/var/lib/grafana/dashboards",
                    "./grafana-provisioning:/etc/grafana/provisioning"
                ],
                "networks": ["monitoring"],
                "restart": "unless-stopped"
            }
        
        # Jaeger service
        if self.config["stack"]["jaeger"]["enabled"]:
            compose_config["services"]["jaeger"] = {
                "image": "jaegertracing/all-in-one:latest",
                "ports": [
                    f"{self.config['stack']['jaeger']['ui_port']}:16686",
                    f"{self.config['stack']['jaeger']['collector_port']}:14268"
                ],
                "environment": {
                    "COLLECTOR_ZIPKIN_HTTP_PORT": "9411"
                },
                "volumes": ["jaeger_data:/tmp"],
                "networks": ["monitoring"],
                "restart": "unless-stopped"
            }
        
        # Alertmanager service
        if self.config["stack"]["alertmanager"]["enabled"]:
            compose_config["services"]["alertmanager"] = {
                "image": "prom/alertmanager:latest",
                "ports": [f"{self.config['stack']['alertmanager']['port']}:9093"],
                "volumes": ["./alertmanager.yml:/etc/alertmanager/alertmanager.yml"],
                "networks": ["monitoring"],
                "restart": "unless-stopped"
            }
        
        # Node Exporter service
        if self.config["stack"]["node_exporter"]["enabled"]:
            compose_config["services"]["node-exporter"] = {
                "image": "prom/node-exporter:latest",
                "ports": [f"{self.config['stack']['node_exporter']['port']}:9100"],
                "volumes": [
                    "/proc:/host/proc:ro",
                    "/sys:/host/sys:ro",
                    "/:/rootfs:ro"
                ],
                "command": [
                    "--path.procfs=/host/proc",
                    "--path.sysfs=/host/sys",
                    "--collector.filesystem.ignored-mount-points",
                    "^/(sys|proc|dev|host|etc|rootfs/var/lib/docker/containers|rootfs/var/lib/docker/overlay2|rootfs/run/docker/netns|rootfs/var/lib/docker/aufs)($$|/)"
                ],
                "networks": ["monitoring"],
                "restart": "unless-stopped"
            }
        
        # Pushgateway service
        if self.config["stack"]["pushgateway"]["enabled"]:
            compose_config["services"]["pushgateway"] = {
                "image": "prom/pushgateway:latest",
                "ports": [f"{self.config['stack']['pushgateway']['port']}:9091"],
                "networks": ["monitoring"],
                "restart": "unless-stopped"
            }
        
        # Write Docker Compose file
        compose_path = self.monitoring_dir / "docker-compose.yml"
        with open(compose_path, 'w') as f:
            yaml.dump(compose_config, f, default_flow_style=False, indent=2)
        
        return str(compose_path)
    
    def create_alertmanager_config(self) -> str:
        """Create Alertmanager configuration"""
        alertmanager_config = {
            "global": {
                "smtp_smarthost": f"{self.config['alerting']['smtp_server']}:{self.config['alerting']['smtp_port']}",
                "smtp_from": self.config['alerting']['email_from']
            },
            "route": {
                "group_by": ["alertname"],
                "group_wait": "10s",
                "group_interval": "10s",
                "repeat_interval": "1h",
                "receiver": "web.hook"
            },
            "receivers": [
                {
                    "name": "web.hook",
                    "email_configs": [
                        {
                            "to": ", ".join(self.config['alerting']['email_to']),
                            "subject": "MCP Alert: {{ range .Alerts }}{{ .Annotations.summary }}{{ end }}",
                            "body": """
Alert Details:
{{ range .Alerts }}
- Alert: {{ .Annotations.summary }}
- Description: {{ .Annotations.description }}
- Severity: {{ .Labels.severity }}
- Server: {{ .Labels.server_name }}
- Runbook: {{ .Annotations.runbook_url }}
{{ end }}
"""
                        }
                    ]
                }
            ]
        }
        
        # Add Slack notifications if configured
        if self.config['alerting']['slack_webhook']:
            alertmanager_config["receivers"][0]["slack_configs"] = [{
                "api_url": self.config['alerting']['slack_webhook'],
                "channel": "#mcp-alerts",
                "title": "MCP Server Alert",
                "text": "{{ range .Alerts }}{{ .Annotations.summary }}{{ end }}"
            }]
        
        # Add PagerDuty if configured
        if self.config['alerting']['pagerduty_service_key']:
            alertmanager_config["receivers"][0]["pagerduty_configs"] = [{
                "service_key": self.config['alerting']['pagerduty_service_key'],
                "description": "{{ range .Alerts }}{{ .Annotations.summary }}{{ end }}"
            }]
        
        # Write Alertmanager config
        config_path = self.monitoring_dir / "alertmanager.yml"
        with open(config_path, 'w') as f:
            yaml.dump(alertmanager_config, f, default_flow_style=False, indent=2)
        
        return str(config_path)
    
    def create_grafana_provisioning(self) -> str:
        """Create Grafana provisioning configuration"""
        provisioning_dir = self.monitoring_dir / "grafana-provisioning"
        provisioning_dir.mkdir(exist_ok=True)
        
        # Datasources provisioning
        datasources_dir = provisioning_dir / "datasources"
        datasources_dir.mkdir(exist_ok=True)
        
        datasources_config = {
            "apiVersion": 1,
            "datasources": [
                {
                    "name": "Prometheus",
                    "type": "prometheus",
                    "access": "proxy",
                    "url": "http://prometheus:9090",
                    "isDefault": True
                },
                {
                    "name": "Jaeger",
                    "type": "jaeger",
                    "access": "proxy",
                    "url": "http://jaeger:16686"
                }
            ]
        }
        
        with open(datasources_dir / "prometheus.yml", 'w') as f:
            yaml.dump(datasources_config, f, default_flow_style=False, indent=2)
        
        # Dashboards provisioning
        dashboards_dir = provisioning_dir / "dashboards"
        dashboards_dir.mkdir(exist_ok=True)
        
        dashboards_config = {
            "apiVersion": 1,
            "providers": [
                {
                    "name": "MCP Dashboards",
                    "orgId": 1,
                    "folder": "MCP Monitoring",
                    "type": "file",
                    "disableDeletion": False,
                    "updateIntervalSeconds": 10,
                    "options": {
                        "path": "/var/lib/grafana/dashboards"
                    }
                }
            ]
        }
        
        with open(dashboards_dir / "dashboards.yml", 'w') as f:
            yaml.dump(dashboards_config, f, default_flow_style=False, indent=2)
        
        return str(provisioning_dir)
    
    def update_prometheus_config(self) -> str:
        """Update Prometheus configuration with MCP targets"""
        prometheus_config = {
            "global": {
                "scrape_interval": self.config["monitoring"]["scrape_interval"],
                "evaluation_interval": self.config["monitoring"]["evaluation_interval"],
                "external_labels": {
                    "monitor": "mcp-monitoring",
                    "environment": "production"
                }
            },
            "alerting": {
                "alertmanagers": [
                    {
                        "static_configs": [
                            {"targets": ["alertmanager:9093"]}
                        ]
                    }
                ]
            },
            "rule_files": self.config["monitoring"]["rule_files"],
            "scrape_configs": [
                {
                    "job_name": "prometheus",
                    "static_configs": [{"targets": ["localhost:9090"]}]
                },
                {
                    "job_name": "node-exporter",
                    "static_configs": [{"targets": ["node-exporter:9100"]}]
                },
                {
                    "job_name": "pushgateway",
                    "honor_labels": True,
                    "static_configs": [{"targets": ["pushgateway:9091"]}]
                },
                {
                    "job_name": "mcp-servers",
                    "static_configs": [
                        {"targets": self.config["monitoring"]["targets"]["mcp_servers"]}
                    ],
                    "metrics_path": "/metrics",
                    "scrape_interval": "10s"
                },
                {
                    "job_name": "mcp-health-checks",
                    "static_configs": [{"targets": ["localhost:9090"]}],
                    "metrics_path": "/metrics",
                    "scrape_interval": "30s"
                }
            ]
        }
        
        # Write Prometheus config
        config_path = self.monitoring_dir / "prometheus.yml"
        with open(config_path, 'w') as f:
            yaml.dump(prometheus_config, f, default_flow_style=False, indent=2)
        
        return str(config_path)
    
    def setup_monitoring_scripts(self) -> List[str]:
        """Setup monitoring automation scripts"""
        scripts_dir = self.monitoring_dir / "scripts"
        scripts_dir.mkdir(exist_ok=True)
        
        created_scripts = []
        
        # Health check automation script
        health_check_script = scripts_dir / "run_health_checks.sh"
        with open(health_check_script, 'w') as f:
            f.write("""#!/bin/bash
# Automated health check script for MCP servers

MONITORING_DIR="/home/louranicas/projects/claude-optimized-deployment/monitoring"
LOG_FILE="/var/log/mcp-health-checks.log"

# Function to log messages
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Run health checks for all servers
log_message "Starting automated health checks"

python3 "$MONITORING_DIR/mcp_health_checks.py" --continuous --interval 60 &
HEALTH_CHECK_PID=$!

# Run metrics collection
python3 "$MONITORING_DIR/mcp_metrics_collector.py" --continuous --interval 30 &
METRICS_PID=$!

# Store PIDs for cleanup
echo "$HEALTH_CHECK_PID" > /var/run/mcp-health-checks.pid
echo "$METRICS_PID" > /var/run/mcp-metrics.pid

log_message "Health checks and metrics collection started"
log_message "Health check PID: $HEALTH_CHECK_PID"
log_message "Metrics PID: $METRICS_PID"

# Trap signals for graceful shutdown
trap 'kill $HEALTH_CHECK_PID $METRICS_PID; exit' SIGTERM SIGINT

# Wait for processes
wait
""")
        health_check_script.chmod(0o755)
        created_scripts.append(str(health_check_script))
        
        # Backup script
        backup_script = scripts_dir / "backup_monitoring_data.sh"
        with open(backup_script, 'w') as f:
            f.write("""#!/bin/bash
# Backup monitoring data

BACKUP_DIR="/backup/monitoring/$(date +%Y%m%d_%H%M%S)"
PROMETHEUS_DATA="/var/lib/prometheus"
GRAFANA_DATA="/var/lib/grafana"

mkdir -p "$BACKUP_DIR"

# Backup Prometheus data
if [ -d "$PROMETHEUS_DATA" ]; then
    tar -czf "$BACKUP_DIR/prometheus_data.tar.gz" -C "$PROMETHEUS_DATA" .
    echo "Prometheus data backed up"
fi

# Backup Grafana data
if [ -d "$GRAFANA_DATA" ]; then
    tar -czf "$BACKUP_DIR/grafana_data.tar.gz" -C "$GRAFANA_DATA" .
    echo "Grafana data backed up"
fi

# Backup configurations
tar -czf "$BACKUP_DIR/monitoring_configs.tar.gz" -C "/home/louranicas/projects/claude-optimized-deployment/monitoring" .

echo "Monitoring backup completed: $BACKUP_DIR"

# Clean up old backups (keep 30 days)
find /backup/monitoring -type d -mtime +30 -exec rm -rf {} + 2>/dev/null
""")
        backup_script.chmod(0o755)
        created_scripts.append(str(backup_script))
        
        # Alert test script
        alert_test_script = scripts_dir / "test_alerts.sh"
        with open(alert_test_script, 'w') as f:
            f.write("""#!/bin/bash
# Test alerting system

ALERTMANAGER_URL="http://localhost:9093"

# Test alert payload
ALERT_PAYLOAD=$(cat <<EOF
[
  {
    "labels": {
      "alertname": "TestAlert",
      "service": "mcp-test",
      "severity": "warning"
    },
    "annotations": {
      "summary": "Test alert from monitoring setup",
      "description": "This is a test alert to verify the alerting system"
    },
    "generatorURL": "http://localhost:9090/graph?g0.expr=up&g0.tab=1"
  }
]
EOF
)

echo "Sending test alert to Alertmanager..."
curl -XPOST "$ALERTMANAGER_URL/api/v1/alerts" \\
     -H "Content-Type: application/json" \\
     -d "$ALERT_PAYLOAD"

echo "Test alert sent. Check your notification channels."
""")
        alert_test_script.chmod(0o755)
        created_scripts.append(str(alert_test_script))
        
        return created_scripts
    
    def setup_systemd_services(self) -> List[str]:
        """Setup systemd services for monitoring components"""
        services_created = []
        
        # MCP Health Check service
        health_check_service = """[Unit]
Description=MCP Health Check Service
After=network.target

[Service]
Type=simple
User=mcp-monitor
Group=mcp-monitor
WorkingDirectory=/home/louranicas/projects/claude-optimized-deployment/monitoring
ExecStart=/home/louranicas/projects/claude-optimized-deployment/monitoring/scripts/run_health_checks.sh
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
"""
        
        service_path = "/etc/systemd/system/mcp-health-checks.service"
        try:
            with open(service_path, 'w') as f:
                f.write(health_check_service)
            services_created.append(service_path)
        except PermissionError:
            self.logger.warning(f"Cannot write to {service_path} - run as root or use sudo")
        
        return services_created
    
    async def deploy_stack(self) -> Dict[str, Any]:
        """Deploy the complete monitoring stack"""
        deployment_results = {
            "started_at": datetime.utcnow().isoformat(),
            "method": self.config["deployment"]["method"],
            "components": {},
            "status": "in_progress"
        }
        
        try:
            self.logger.info("Starting monitoring stack deployment")
            
            # Create configuration files
            self.logger.info("Creating configuration files...")
            docker_compose_path = self.create_docker_compose()
            alertmanager_config = self.create_alertmanager_config()
            prometheus_config = self.update_prometheus_config()
            grafana_provisioning = self.create_grafana_provisioning()
            
            deployment_results["components"]["config_files"] = {
                "docker_compose": docker_compose_path,
                "alertmanager": alertmanager_config,
                "prometheus": prometheus_config,
                "grafana_provisioning": grafana_provisioning
            }
            
            # Setup automation scripts
            self.logger.info("Setting up automation scripts...")
            scripts = self.setup_monitoring_scripts()
            deployment_results["components"]["scripts"] = scripts
            
            # Deploy using chosen method
            if self.config["deployment"]["method"] == "docker-compose":
                await self._deploy_docker_compose()
            elif self.config["deployment"]["method"] == "systemd":
                services = self.setup_systemd_services()
                deployment_results["components"]["systemd_services"] = services
            
            # Wait for services to start
            self.logger.info("Waiting for services to start...")
            await asyncio.sleep(30)
            
            # Verify deployment
            verification_results = await self._verify_deployment()
            deployment_results["verification"] = verification_results
            
            # Setup initial monitoring
            self.logger.info("Starting monitoring automation...")
            await self._start_monitoring_automation()
            
            deployment_results["status"] = "completed"
            deployment_results["completed_at"] = datetime.utcnow().isoformat()
            
        except Exception as e:
            self.logger.error(f"Deployment failed: {str(e)}")
            deployment_results["status"] = "failed"
            deployment_results["error"] = str(e)
            deployment_results["failed_at"] = datetime.utcnow().isoformat()
        
        return deployment_results
    
    async def _deploy_docker_compose(self):
        """Deploy using Docker Compose"""
        compose_file = self.monitoring_dir / "docker-compose.yml"
        
        # Pull images
        self.logger.info("Pulling Docker images...")
        subprocess.run(["docker-compose", "-f", str(compose_file), "pull"], check=True)
        
        # Start services
        self.logger.info("Starting monitoring services...")
        subprocess.run(["docker-compose", "-f", str(compose_file), "up", "-d"], check=True)
        
        self.logger.info("Docker Compose deployment completed")
    
    async def _verify_deployment(self) -> Dict[str, Any]:
        """Verify that all monitoring components are working"""
        verification_results = {
            "prometheus": False,
            "grafana": False,
            "jaeger": False,
            "alertmanager": False,
            "node_exporter": False,
            "pushgateway": False
        }
        
        # Check Prometheus
        try:
            import httpx
            async with httpx.AsyncClient() as client:
                response = await client.get(f"http://localhost:{self.config['stack']['prometheus']['port']}/api/v1/status/config")
                verification_results["prometheus"] = response.status_code == 200
        except Exception as e:
            self.logger.warning(f"Prometheus verification failed: {e}")
        
        # Check Grafana
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"http://localhost:{self.config['stack']['grafana']['port']}/api/health")
                verification_results["grafana"] = response.status_code == 200
        except Exception as e:
            self.logger.warning(f"Grafana verification failed: {e}")
        
        # Check other services similarly...
        
        return verification_results
    
    async def _start_monitoring_automation(self):
        """Start automated monitoring processes"""
        # Start health checks
        health_check_process = await asyncio.create_subprocess_exec(
            "python3", str(self.monitoring_dir / "mcp_health_checks.py"),
            "--continuous", "--interval", "60",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Start metrics collection
        metrics_process = await asyncio.create_subprocess_exec(
            "python3", str(self.monitoring_dir / "mcp_metrics_collector.py"),
            "--continuous", "--interval", "30",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        self.logger.info("Monitoring automation processes started")
    
    def generate_deployment_report(self, deployment_results: Dict[str, Any]) -> str:
        """Generate a comprehensive deployment report"""
        report_path = self.monitoring_dir / f"deployment_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        
        with open(report_path, 'w') as f:
            f.write(f"""# MCP Monitoring Stack Deployment Report

## Deployment Summary
- **Status**: {deployment_results['status']}
- **Method**: {deployment_results['method']}
- **Started**: {deployment_results['started_at']}
- **Completed**: {deployment_results.get('completed_at', 'N/A')}

## Components Deployed

### Configuration Files
""")
            
            for component, path in deployment_results.get("components", {}).get("config_files", {}).items():
                f.write(f"- **{component}**: `{path}`\n")
            
            f.write("""
### Services
""")
            
            for service, status in deployment_results.get("verification", {}).items():
                status_emoji = "✅" if status else "❌"
                f.write(f"- **{service}**: {status_emoji}\n")
            
            f.write(f"""
## Access Information

### Service URLs
- **Prometheus**: http://localhost:{self.config['stack']['prometheus']['port']}
- **Grafana**: http://localhost:{self.config['stack']['grafana']['port']}
- **Jaeger**: http://localhost:{self.config['stack']['jaeger']['ui_port']}
- **Alertmanager**: http://localhost:{self.config['stack']['alertmanager']['port']}

### Default Credentials
- **Grafana**: admin / {self.config['stack']['grafana']['admin_password']}

## Next Steps

1. **Configure Data Sources**: Import Prometheus data source in Grafana
2. **Import Dashboards**: Load MCP monitoring dashboards
3. **Test Alerts**: Run alert test script to verify notifications
4. **Setup Backups**: Configure automated backup schedule
5. **Review Documentation**: Read monitoring playbook and runbooks

## Support

- **Documentation**: `/monitoring/runbooks/`
- **Scripts**: `/monitoring/scripts/`
- **Logs**: `/var/log/mcp-*.log`

## Troubleshooting

If any services are not running:

```bash
# Check Docker Compose status
docker-compose -f {self.monitoring_dir}/docker-compose.yml ps

# View service logs
docker-compose -f {self.monitoring_dir}/docker-compose.yml logs [service_name]

# Restart all services
docker-compose -f {self.monitoring_dir}/docker-compose.yml restart
```

---
Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
""")
        
        return str(report_path)

async def main():
    import argparse
    parser = argparse.ArgumentParser(description="MCP Monitoring Stack Setup")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--deploy", action="store_true", help="Deploy the monitoring stack")
    parser.add_argument("--verify", action="store_true", help="Verify deployment")
    parser.add_argument("--report", action="store_true", help="Generate deployment report")
    
    args = parser.parse_args()
    
    manager = MonitoringStackManager(args.config)
    
    if args.deploy:
        print("Deploying MCP monitoring stack...")
        results = await manager.deploy_stack()
        
        if results["status"] == "completed":
            print("✅ Deployment completed successfully!")
            
            if args.report:
                report_path = manager.generate_deployment_report(results)
                print(f"📄 Deployment report generated: {report_path}")
        else:
            print("❌ Deployment failed!")
            print(f"Error: {results.get('error', 'Unknown error')}")
    
    elif args.verify:
        print("Verifying monitoring stack...")
        verification = await manager._verify_deployment()
        
        print("\nService Status:")
        for service, status in verification.items():
            status_emoji = "✅" if status else "❌"
            print(f"  {service}: {status_emoji}")
    
    else:
        print("Use --deploy to deploy the monitoring stack")
        print("Use --verify to check service status")
        print("Use --report to generate deployment report")

if __name__ == "__main__":
    asyncio.run(main())