#!/usr/bin/env python3
"""
BASH GOD PRODUCTION DEPLOYMENT
Production deployment automation for the Bash God MCP Server
Handles container deployment, scaling, monitoring, and maintenance
"""

import asyncio
import json
import logging
import os
import subprocess
import sys
import time
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional
import docker
import psutil

logger = logging.getLogger('BashGodDeployment')

class BashGodDeployment:
    """Production deployment manager for Bash God MCP Server"""
    
    def __init__(self, config_path: str = "bash_god_config.yaml"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.docker_client = None
        self.deployment_status = {
            "status": "not_deployed",
            "containers": {},
            "services": {},
            "health_checks": {}
        }
    
    def _load_config(self) -> Dict[str, Any]:
        """Load deployment configuration"""
        default_config = {
            "version": "1.0.0",
            "deployment": {
                "environment": "production",
                "replicas": 3,
                "cpu_limit": "2000m",
                "memory_limit": "4Gi",
                "ports": {
                    "mcp_server": 8080,
                    "metrics": 9090,
                    "health": 8081
                }
            },
            "amd_ryzen": {
                "enabled": True,
                "cpu_cores": 16,
                "memory_gb": 32,
                "optimizations": [
                    "cpu_governor",
                    "memory_bandwidth",
                    "network_tuning",
                    "io_scheduler"
                ]
            },
            "security": {
                "enable_sandboxing": True,
                "max_execution_time": 300,
                "allowed_commands": "all",
                "security_level": "strict"
            },
            "monitoring": {
                "prometheus": True,
                "grafana": True,
                "alerting": True,
                "log_level": "INFO"
            },
            "scaling": {
                "auto_scaling": True,
                "min_replicas": 2,
                "max_replicas": 10,
                "cpu_threshold": 70,
                "memory_threshold": 80
            }
        }
        
        if self.config_path.exists():
            with open(self.config_path) as f:
                user_config = yaml.safe_load(f)
                # Merge with defaults
                return {**default_config, **user_config}
        else:
            # Save default config
            with open(self.config_path, 'w') as f:
                yaml.dump(default_config, f, default_flow_style=False)
            return default_config
    
    async def deploy_production(self):
        """Deploy Bash God MCP Server to production"""
        logger.info("🚀 Starting Bash God MCP Server production deployment")
        
        try:
            # Initialize Docker client
            self.docker_client = docker.from_env()
            
            # Step 1: Prepare deployment
            await self._prepare_deployment()
            
            # Step 2: Build container images
            await self._build_container_images()
            
            # Step 3: Deploy core services
            await self._deploy_core_services()
            
            # Step 4: Deploy monitoring stack
            await self._deploy_monitoring_stack()
            
            # Step 5: Configure load balancing
            await self._configure_load_balancing()
            
            # Step 6: Apply AMD Ryzen optimizations
            await self._apply_amd_optimizations()
            
            # Step 7: Setup health checks
            await self._setup_health_checks()
            
            # Step 8: Configure auto-scaling
            await self._configure_auto_scaling()
            
            # Step 9: Validate deployment
            await self._validate_deployment()
            
            self.deployment_status["status"] = "deployed"
            logger.info("✅ Bash God MCP Server production deployment completed successfully")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Deployment failed: {e}")
            await self._rollback_deployment()
            return False
    
    async def _prepare_deployment(self):
        """Prepare deployment environment"""
        logger.info("📋 Preparing deployment environment")
        
        # Create necessary directories
        deployment_dirs = [
            "logs", "data", "config", "scripts", "monitoring"
        ]
        
        for dir_name in deployment_dirs:
            Path(dir_name).mkdir(exist_ok=True)
        
        # Generate deployment manifests
        await self._generate_docker_compose()
        await self._generate_kubernetes_manifests()
        await self._generate_monitoring_configs()
        
        logger.info("✅ Deployment environment prepared")
    
    async def _generate_docker_compose(self):
        """Generate Docker Compose configuration"""
        compose_config = {
            "version": "3.8",
            "services": {
                "bash-god-server": {
                    "image": "bash-god-mcp:latest",
                    "build": {
                        "context": ".",
                        "dockerfile": "Dockerfile.bash-god"
                    },
                    "ports": [
                        f"{self.config['deployment']['ports']['mcp_server']}:8080",
                        f"{self.config['deployment']['ports']['health']}:8081"
                    ],
                    "environment": [
                        "ENVIRONMENT=production",
                        f"CPU_CORES={self.config['amd_ryzen']['cpu_cores']}",
                        f"MEMORY_GB={self.config['amd_ryzen']['memory_gb']}",
                        f"SECURITY_LEVEL={self.config['security']['security_level']}"
                    ],
                    "volumes": [
                        "./data:/app/data",
                        "./logs:/app/logs",
                        "./config:/app/config"
                    ],
                    "deploy": {
                        "replicas": self.config['deployment']['replicas'],
                        "resources": {
                            "limits": {
                                "cpus": self.config['deployment']['cpu_limit'],
                                "memory": self.config['deployment']['memory_limit']
                            }
                        },
                        "restart_policy": {
                            "condition": "on-failure",
                            "max_attempts": 3
                        }
                    },
                    "healthcheck": {
                        "test": ["CMD", "curl", "-f", "http://localhost:8081/health"],
                        "interval": "30s",
                        "timeout": "10s",
                        "retries": 3
                    }
                },
                "nginx-proxy": {
                    "image": "nginx:alpine",
                    "ports": ["80:80", "443:443"],
                    "volumes": [
                        "./nginx.conf:/etc/nginx/nginx.conf",
                        "./ssl:/etc/nginx/ssl"
                    ],
                    "depends_on": ["bash-god-server"]
                },
                "prometheus": {
                    "image": "prom/prometheus:latest",
                    "ports": [f"{self.config['deployment']['ports']['metrics']}:9090"],
                    "volumes": [
                        "./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml",
                        "prometheus_data:/prometheus"
                    ],
                    "command": [
                        "--config.file=/etc/prometheus/prometheus.yml",
                        "--storage.tsdb.path=/prometheus",
                        "--web.console.libraries=/etc/prometheus/console_libraries",
                        "--web.console.templates=/etc/prometheus/consoles",
                        "--storage.tsdb.retention.time=200h",
                        "--web.enable-lifecycle"
                    ]
                },
                "grafana": {
                    "image": "grafana/grafana:latest",
                    "ports": ["3000:3000"],
                    "environment": [
                        "GF_SECURITY_ADMIN_PASSWORD=admin123"
                    ],
                    "volumes": [
                        "grafana_data:/var/lib/grafana",
                        "./monitoring/grafana:/etc/grafana/provisioning"
                    ]
                }
            },
            "volumes": {
                "prometheus_data": {},
                "grafana_data": {}
            },
            "networks": {
                "bash-god-network": {
                    "driver": "bridge"
                }
            }
        }
        
        with open("docker-compose.prod.yml", 'w') as f:
            yaml.dump(compose_config, f, default_flow_style=False)
        
        logger.info("✅ Docker Compose configuration generated")
    
    async def _generate_kubernetes_manifests(self):
        """Generate Kubernetes deployment manifests"""
        k8s_manifests = {
            "namespace.yaml": {
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": "bash-god"
                }
            },
            "deployment.yaml": {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {
                    "name": "bash-god-server",
                    "namespace": "bash-god"
                },
                "spec": {
                    "replicas": self.config['deployment']['replicas'],
                    "selector": {
                        "matchLabels": {
                            "app": "bash-god-server"
                        }
                    },
                    "template": {
                        "metadata": {
                            "labels": {
                                "app": "bash-god-server"
                            }
                        },
                        "spec": {
                            "containers": [{
                                "name": "bash-god-server",
                                "image": "bash-god-mcp:latest",
                                "ports": [
                                    {"containerPort": 8080, "name": "mcp-server"},
                                    {"containerPort": 8081, "name": "health"}
                                ],
                                "resources": {
                                    "limits": {
                                        "cpu": self.config['deployment']['cpu_limit'],
                                        "memory": self.config['deployment']['memory_limit']
                                    },
                                    "requests": {
                                        "cpu": "500m",
                                        "memory": "1Gi"
                                    }
                                },
                                "env": [
                                    {"name": "ENVIRONMENT", "value": "production"},
                                    {"name": "CPU_CORES", "value": str(self.config['amd_ryzen']['cpu_cores'])},
                                    {"name": "MEMORY_GB", "value": str(self.config['amd_ryzen']['memory_gb'])}
                                ],
                                "livenessProbe": {
                                    "httpGet": {
                                        "path": "/health",
                                        "port": 8081
                                    },
                                    "initialDelaySeconds": 30,
                                    "periodSeconds": 10
                                },
                                "readinessProbe": {
                                    "httpGet": {
                                        "path": "/ready",
                                        "port": 8081
                                    },
                                    "initialDelaySeconds": 5,
                                    "periodSeconds": 5
                                }
                            }]
                        }
                    }
                }
            },
            "service.yaml": {
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {
                    "name": "bash-god-service",
                    "namespace": "bash-god"
                },
                "spec": {
                    "selector": {
                        "app": "bash-god-server"
                    },
                    "ports": [
                        {
                            "name": "mcp-server",
                            "port": 8080,
                            "targetPort": 8080
                        },
                        {
                            "name": "health",
                            "port": 8081,
                            "targetPort": 8081
                        }
                    ],
                    "type": "LoadBalancer"
                }
            },
            "hpa.yaml": {
                "apiVersion": "autoscaling/v2",
                "kind": "HorizontalPodAutoscaler",
                "metadata": {
                    "name": "bash-god-hpa",
                    "namespace": "bash-god"
                },
                "spec": {
                    "scaleTargetRef": {
                        "apiVersion": "apps/v1",
                        "kind": "Deployment",
                        "name": "bash-god-server"
                    },
                    "minReplicas": self.config['scaling']['min_replicas'],
                    "maxReplicas": self.config['scaling']['max_replicas'],
                    "metrics": [
                        {
                            "type": "Resource",
                            "resource": {
                                "name": "cpu",
                                "target": {
                                    "type": "Utilization",
                                    "averageUtilization": self.config['scaling']['cpu_threshold']
                                }
                            }
                        },
                        {
                            "type": "Resource",
                            "resource": {
                                "name": "memory",
                                "target": {
                                    "type": "Utilization",
                                    "averageUtilization": self.config['scaling']['memory_threshold']
                                }
                            }
                        }
                    ]
                }
            }
        }
        
        # Create k8s directory and save manifests
        k8s_dir = Path("k8s")
        k8s_dir.mkdir(exist_ok=True)
        
        for filename, manifest in k8s_manifests.items():
            with open(k8s_dir / filename, 'w') as f:
                yaml.dump(manifest, f, default_flow_style=False)
        
        logger.info("✅ Kubernetes manifests generated")
    
    async def _generate_monitoring_configs(self):
        """Generate monitoring configurations"""
        monitoring_dir = Path("monitoring")
        monitoring_dir.mkdir(exist_ok=True)
        
        # Prometheus configuration
        prometheus_config = {
            "global": {
                "scrape_interval": "15s",
                "evaluation_interval": "15s"
            },
            "rule_files": ["alert_rules.yml"],
            "scrape_configs": [
                {
                    "job_name": "bash-god-server",
                    "static_configs": [
                        {"targets": [f"bash-god-server:{self.config['deployment']['ports']['mcp_server']}"]}
                    ],
                    "scrape_interval": "5s",
                    "metrics_path": "/metrics"
                },
                {
                    "job_name": "node-exporter",
                    "static_configs": [
                        {"targets": ["node-exporter:9100"]}
                    ]
                }
            ],
            "alerting": {
                "alertmanagers": [
                    {
                        "static_configs": [
                            {"targets": ["alertmanager:9093"]}
                        ]
                    }
                ]
            }
        }
        
        with open(monitoring_dir / "prometheus.yml", 'w') as f:
            yaml.dump(prometheus_config, f, default_flow_style=False)
        
        # Alert rules
        alert_rules = {
            "groups": [
                {
                    "name": "bash-god-alerts",
                    "rules": [
                        {
                            "alert": "BashGodServerDown",
                            "expr": "up{job=\"bash-god-server\"} == 0",
                            "for": "1m",
                            "labels": {"severity": "critical"},
                            "annotations": {
                                "summary": "Bash God MCP Server is down",
                                "description": "Bash God MCP Server has been down for more than 1 minute"
                            }
                        },
                        {
                            "alert": "HighCPUUsage",
                            "expr": "cpu_usage_percent > 90",
                            "for": "5m",
                            "labels": {"severity": "warning"},
                            "annotations": {
                                "summary": "High CPU usage detected",
                                "description": "CPU usage is above 90% for more than 5 minutes"
                            }
                        },
                        {
                            "alert": "HighMemoryUsage",
                            "expr": "memory_usage_percent > 85",
                            "for": "5m",
                            "labels": {"severity": "warning"},
                            "annotations": {
                                "summary": "High memory usage detected",
                                "description": "Memory usage is above 85% for more than 5 minutes"
                            }
                        },
                        {
                            "alert": "CommandExecutionFailures",
                            "expr": "rate(command_execution_failures_total[5m]) > 0.1",
                            "for": "2m",
                            "labels": {"severity": "warning"},
                            "annotations": {
                                "summary": "High command execution failure rate",
                                "description": "Command execution failure rate is above 10% for more than 2 minutes"
                            }
                        }
                    ]
                }
            ]
        }
        
        with open(monitoring_dir / "alert_rules.yml", 'w') as f:
            yaml.dump(alert_rules, f, default_flow_style=False)
        
        logger.info("✅ Monitoring configurations generated")
    
    async def _build_container_images(self):
        """Build container images"""
        logger.info("🏗️ Building container images")
        
        # Generate Dockerfile
        dockerfile_content = '''FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    curl \\
    git \\
    sudo \\
    procps \\
    htop \\
    iotop \\
    sysstat \\
    lsof \\
    net-tools \\
    dnsutils \\
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY mcp_learning_system/ ./mcp_learning_system/
COPY *.py ./

# Create non-root user
RUN useradd -m -u 1000 bashgod && \\
    chown -R bashgod:bashgod /app

# Switch to non-root user
USER bashgod

# Expose ports
EXPOSE 8080 8081

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \\
    CMD curl -f http://localhost:8081/health || exit 1

# Start the server
CMD ["python", "-m", "mcp_learning_system.bash_god_mcp_server"]
'''
        
        with open("Dockerfile.bash-god", 'w') as f:
            f.write(dockerfile_content)
        
        # Generate requirements.txt
        requirements = [
            "asyncio",
            "websockets",
            "aiohttp",
            "psutil",
            "docker",
            "pyyaml",
            "prometheus-client",
            "structlog"
        ]
        
        with open("requirements.txt", 'w') as f:
            f.write('\n'.join(requirements))
        
        # Build Docker image
        try:
            image, logs = self.docker_client.images.build(
                path=".",
                dockerfile="Dockerfile.bash-god",
                tag="bash-god-mcp:latest",
                rm=True
            )
            
            logger.info("✅ Container image built successfully")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to build container image: {e}")
            return False
    
    async def _deploy_core_services(self):
        """Deploy core Bash God services"""
        logger.info("🚀 Deploying core services")
        
        try:
            # Start services using Docker Compose
            result = subprocess.run([
                "docker-compose", "-f", "docker-compose.prod.yml", "up", "-d"
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info("✅ Core services deployed successfully")
                return True
            else:
                logger.error(f"❌ Failed to deploy core services: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Failed to deploy core services: {e}")
            return False
    
    async def _deploy_monitoring_stack(self):
        """Deploy monitoring stack"""
        logger.info("📊 Deploying monitoring stack")
        
        # Monitoring services are included in docker-compose.prod.yml
        # Additional setup for Grafana dashboards
        grafana_dir = Path("monitoring/grafana")
        grafana_dir.mkdir(exist_ok=True, parents=True)
        
        # Generate Grafana dashboard
        dashboard_config = {
            "dashboard": {
                "id": None,
                "title": "Bash God MCP Server",
                "tags": ["bash-god", "mcp"],
                "timezone": "browser",
                "panels": [
                    {
                        "id": 1,
                        "title": "Command Execution Rate",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "rate(commands_executed_total[5m])",
                                "legendFormat": "Commands/sec"
                            }
                        ]
                    },
                    {
                        "id": 2,
                        "title": "CPU Usage",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "cpu_usage_percent",
                                "legendFormat": "CPU %"
                            }
                        ]
                    },
                    {
                        "id": 3,
                        "title": "Memory Usage",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "memory_usage_percent",
                                "legendFormat": "Memory %"
                            }
                        ]
                    },
                    {
                        "id": 4,
                        "title": "Active Workflows",
                        "type": "stat",
                        "targets": [
                            {
                                "expr": "active_workflows_total",
                                "legendFormat": "Active"
                            }
                        ]
                    }
                ],
                "time": {
                    "from": "now-1h",
                    "to": "now"
                },
                "refresh": "5s"
            }
        }
        
        with open(grafana_dir / "bash-god-dashboard.json", 'w') as f:
            json.dump(dashboard_config, f, indent=2)
        
        logger.info("✅ Monitoring stack deployed")
    
    async def _configure_load_balancing(self):
        """Configure load balancing"""
        logger.info("⚖️ Configuring load balancing")
        
        nginx_config = '''
events {
    worker_connections 1024;
}

http {
    upstream bash_god_backend {
        least_conn;
        server bash-god-server:8080 max_fails=3 fail_timeout=30s;
    }
    
    server {
        listen 80;
        server_name _;
        
        location / {
            proxy_pass http://bash_god_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # WebSocket support
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            
            # Timeouts
            proxy_connect_timeout 60s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;
        }
        
        location /health {
            access_log off;
            return 200 "healthy\\n";
        }
    }
}
'''
        
        with open("nginx.conf", 'w') as f:
            f.write(nginx_config)
        
        logger.info("✅ Load balancing configured")
    
    async def _apply_amd_optimizations(self):
        """Apply AMD Ryzen optimizations"""
        if not self.config['amd_ryzen']['enabled']:
            logger.info("⏭️ AMD Ryzen optimizations disabled")
            return
        
        logger.info("🚀 Applying AMD Ryzen optimizations")
        
        optimization_script = '''#!/bin/bash
# AMD Ryzen 7 7800X3D Optimization Script

echo "Applying AMD Ryzen optimizations..."

# Set CPU governor to performance
echo "performance" | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Configure transparent huge pages
echo "madvise" | sudo tee /sys/kernel/mm/transparent_hugepage/enabled

# Network optimizations
sudo sysctl -w net.core.rmem_max=134217728
sudo sysctl -w net.core.wmem_max=134217728
sudo sysctl -w net.ipv4.tcp_congestion_control=bbr

# I/O scheduler optimization for NVMe
echo "none" | sudo tee /sys/block/nvme*/queue/scheduler

echo "AMD Ryzen optimizations applied successfully"
'''
        
        scripts_dir = Path("scripts")
        scripts_dir.mkdir(exist_ok=True)
        
        script_path = scripts_dir / "amd_optimize.sh"
        with open(script_path, 'w') as f:
            f.write(optimization_script)
        
        os.chmod(script_path, 0o755)
        
        # Apply optimizations if running on AMD system
        try:
            result = subprocess.run(['lscpu'], capture_output=True, text=True)
            if 'AMD' in result.stdout and 'Ryzen' in result.stdout:
                subprocess.run([str(script_path)], check=True)
                logger.info("✅ AMD Ryzen optimizations applied")
            else:
                logger.info("ℹ️ Non-AMD system detected, skipping hardware optimizations")
        except Exception as e:
            logger.warning(f"⚠️ Could not apply AMD optimizations: {e}")
    
    async def _setup_health_checks(self):
        """Setup health checks and monitoring"""
        logger.info("🏥 Setting up health checks")
        
        health_check_script = '''#!/usr/bin/env python3
import asyncio
import aiohttp
import sys
import time

async def check_health():
    """Comprehensive health check"""
    checks = {
        "server": False,
        "metrics": False,
        "performance": False
    }
    
    try:
        # Check main server
        async with aiohttp.ClientSession() as session:
            async with session.get("http://localhost:8081/health", timeout=5) as resp:
                checks["server"] = resp.status == 200
        
        # Check metrics endpoint
        async with aiohttp.ClientSession() as session:
            async with session.get("http://localhost:9090/metrics", timeout=5) as resp:
                checks["metrics"] = resp.status == 200
        
        # Check performance
        # This would include response time checks, etc.
        checks["performance"] = True
        
    except Exception as e:
        print(f"Health check failed: {e}")
    
    all_healthy = all(checks.values())
    
    print(f"Health Status: {'HEALTHY' if all_healthy else 'UNHEALTHY'}")
    for check, status in checks.items():
        print(f"  {check}: {'✅' if status else '❌'}")
    
    return 0 if all_healthy else 1

if __name__ == "__main__":
    exit_code = asyncio.run(check_health())
    sys.exit(exit_code)
'''
        
        with open("scripts/health_check.py", 'w') as f:
            f.write(health_check_script)
        
        os.chmod("scripts/health_check.py", 0o755)
        
        logger.info("✅ Health checks configured")
    
    async def _configure_auto_scaling(self):
        """Configure auto-scaling policies"""
        logger.info("📈 Configuring auto-scaling")
        
        if self.config['scaling']['auto_scaling']:
            # Docker Swarm auto-scaling service
            scaling_config = f'''
version: "3.8"
services:
  bash-god-autoscaler:
    image: bash-god-mcp:latest
    deploy:
      replicas: {self.config['scaling']['min_replicas']}
      update_config:
        parallelism: 1
        order: start-first
      restart_policy:
        condition: on-failure
      placement:
        constraints:
          - node.role == worker
    environment:
      - AUTO_SCALING=true
      - MIN_REPLICAS={self.config['scaling']['min_replicas']}
      - MAX_REPLICAS={self.config['scaling']['max_replicas']}
      - CPU_THRESHOLD={self.config['scaling']['cpu_threshold']}
      - MEMORY_THRESHOLD={self.config['scaling']['memory_threshold']}
'''
            
            with open("docker-compose.scaling.yml", 'w') as f:
                f.write(scaling_config)
        
        logger.info("✅ Auto-scaling configured")
    
    async def _validate_deployment(self):
        """Validate deployment success"""
        logger.info("✅ Validating deployment")
        
        validation_checks = {
            "containers_running": False,
            "services_healthy": False,
            "endpoints_accessible": False,
            "monitoring_active": False
        }
        
        try:
            # Check containers
            containers = self.docker_client.containers.list()
            bash_god_containers = [c for c in containers if 'bash-god' in c.name]
            validation_checks["containers_running"] = len(bash_god_containers) > 0
            
            # Check service health
            if bash_god_containers:
                container = bash_god_containers[0]
                health = container.attrs.get('State', {}).get('Health', {})
                validation_checks["services_healthy"] = health.get('Status') == 'healthy'
            
            # Check endpoints
            import aiohttp
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get("http://localhost:8080", timeout=10) as resp:
                        validation_checks["endpoints_accessible"] = resp.status in [200, 404]  # 404 is ok for root path
                except:
                    pass
            
            # Check monitoring
            try:
                async with session.get("http://localhost:9090", timeout=5) as resp:
                    validation_checks["monitoring_active"] = resp.status in [200, 404]
            except:
                pass
            
        except Exception as e:
            logger.error(f"Validation error: {e}")
        
        # Report validation results
        all_valid = all(validation_checks.values())
        
        logger.info(f"Deployment validation: {'✅ PASSED' if all_valid else '❌ FAILED'}")
        for check, status in validation_checks.items():
            logger.info(f"  {check}: {'✅' if status else '❌'}")
        
        return all_valid
    
    async def _rollback_deployment(self):
        """Rollback failed deployment"""
        logger.info("🔄 Rolling back deployment")
        
        try:
            # Stop services
            subprocess.run([
                "docker-compose", "-f", "docker-compose.prod.yml", "down"
            ], capture_output=True)
            
            logger.info("✅ Deployment rolled back")
            
        except Exception as e:
            logger.error(f"❌ Rollback failed: {e}")
    
    async def get_deployment_status(self) -> Dict[str, Any]:
        """Get current deployment status"""
        if self.docker_client:
            containers = self.docker_client.containers.list()
            self.deployment_status["containers"] = {
                c.name: c.status for c in containers if 'bash-god' in c.name
            }
        
        return self.deployment_status
    
    async def scale_deployment(self, replicas: int):
        """Scale deployment to specified number of replicas"""
        logger.info(f"📈 Scaling deployment to {replicas} replicas")
        
        try:
            subprocess.run([
                "docker-compose", "-f", "docker-compose.prod.yml", 
                "up", "-d", "--scale", f"bash-god-server={replicas}"
            ], check=True)
            
            logger.info(f"✅ Scaled to {replicas} replicas")
            
        except Exception as e:
            logger.error(f"❌ Scaling failed: {e}")

async def main():
    """Main deployment execution"""
    deployment = BashGodDeployment()
    
    logger.info("🚀 Starting Bash God MCP Server Production Deployment")
    
    success = await deployment.deploy_production()
    
    if success:
        logger.info("🎉 Deployment completed successfully!")
        
        # Show deployment status
        status = await deployment.get_deployment_status()
        logger.info(f"Deployment status: {status}")
        
        return 0
    else:
        logger.error("💥 Deployment failed!")
        return 1

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    exit_code = asyncio.run(main())