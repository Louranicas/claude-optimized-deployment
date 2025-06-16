# Learning MCP System Deployment Guide

## Overview

The Learning MCP System is a sophisticated ecosystem of 4 interconnected MCP servers with advanced learning capabilities, designed for seamless integration with CODE terminal and high-performance operations.

## System Requirements

### Hardware Requirements
- **Memory**: Minimum 12GB RAM available
- **CPU**: 4+ cores recommended
- **Storage**: 50GB free space
- **Network**: Low-latency network for cross-instance communication

### Software Requirements
- **Operating System**: Linux (Ubuntu 20.04+, Linux Mint 21+)
- **Python**: 3.8 or higher
- **Rust**: 1.70 or higher
- **Docker**: 20.10+ (optional for containerized deployment)
- **Node.js**: 18+ (for CODE integration)

## Architecture

### MCP Servers

1. **Learning Core Server** (Port 5100)
   - Pattern recognition engine
   - Adaptive learning algorithms
   - Prediction models
   - Memory allocation: 4GB

2. **Learning Analytics Server** (Port 5101)
   - Data analysis and processing
   - Performance tracking
   - Optimization algorithms
   - Memory allocation: 3GB

3. **Learning Orchestrator Server** (Port 5102)
   - Workflow management
   - Resource allocation
   - Cross-instance coordination
   - Memory allocation: 3GB

4. **Learning Interface Server** (Port 5103)
   - CODE terminal integration
   - API gateway
   - User interface
   - Memory allocation: 2GB

## Deployment Steps

### 1. Pre-deployment Checklist

```bash
# Verify system requirements
python3 --version  # Should be 3.8+
rustc --version    # Should be 1.70+
free -h           # Check available memory

# Install dependencies
pip install -r requirements.txt
cargo build --release
```

### 2. Configuration

Create configuration files for each server:

```bash
mkdir -p mcp_learning_system/deployment/configs
```

Example configuration (`learning_core_config.json`):

```json
{
  "name": "learning_core",
  "port": 5100,
  "memory_limit": "4G",
  "features": ["pattern_recognition", "adaptive_learning", "prediction"],
  "learning": {
    "enabled": true,
    "model_path": "/models/learning_core",
    "update_interval": 300,
    "batch_size": 32
  },
  "rust_acceleration": true,
  "monitoring": {
    "enabled": true,
    "metrics_port": 6100
  }
}
```

### 3. Automated Deployment

Run the deployment script:

```bash
cd mcp_learning_system/deployment/scripts
python deploy_learning_mcp.py
```

This script will:
- Verify system requirements
- Deploy all 4 MCP servers
- Configure monitoring
- Validate deployment
- Generate deployment report

### 4. Manual Deployment (Alternative)

If you prefer manual deployment:

```bash
# Start Learning Core Server
export MCP_CONFIG=configs/learning_core_config.json
python -m mcp_learning_system.servers.learning_core &

# Start Learning Analytics Server
export MCP_CONFIG=configs/learning_analytics_config.json
python -m mcp_learning_system.servers.learning_analytics &

# Start Learning Orchestrator Server
export MCP_CONFIG=configs/learning_orchestrator_config.json
python -m mcp_learning_system.servers.learning_orchestrator &

# Start Learning Interface Server
export MCP_CONFIG=configs/learning_interface_config.json
python -m mcp_learning_system.servers.learning_interface &
```

### 5. Systemd Service Installation

For production deployment, install as systemd services:

```bash
# Copy service files
sudo cp services/mcp_*.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable services
sudo systemctl enable mcp_learning_core
sudo systemctl enable mcp_learning_analytics
sudo systemctl enable mcp_learning_orchestrator
sudo systemctl enable mcp_learning_interface

# Start services
sudo systemctl start mcp_learning_core
sudo systemctl start mcp_learning_analytics
sudo systemctl start mcp_learning_orchestrator
sudo systemctl start mcp_learning_interface
```

## Validation

### Running Validation Suite

```bash
cd mcp_learning_system/deployment/validation
python validate_learning_system.py
```

The validation suite performs:
- Phase 1: Deployment validation (15 min)
- Phase 2: Learning validation (20 min)
- Phase 3: Performance validation (25 min)
- Phase 4: Integration testing (20 min)
- Phase 5: Production readiness (20 min)

### Health Checks

Check server health:

```bash
# Check individual servers
curl http://localhost:5100/health
curl http://localhost:5101/health
curl http://localhost:5102/health
curl http://localhost:5103/health

# Check metrics
curl http://localhost:6100/metrics
```

## CODE Terminal Integration

### Setup CODE Integration

1. Install CODE extension:
```bash
npm install -g @anthropic/claude-code
```

2. Configure CODE connection:
```json
{
  "mcp_servers": {
    "learning_interface": {
      "url": "http://localhost:5103",
      "auth": "your-auth-token"
    }
  }
}
```

3. Test connection:
```bash
claude-code test-mcp
```

### Using CODE with Learning MCP

```bash
# Connect to Learning MCP
claude-code connect --mcp learning

# Execute commands with learning assistance
claude-code run "analyze codebase patterns"
claude-code predict "next development steps"
```

## Monitoring

### Prometheus Metrics

Access Prometheus at: http://localhost:9090

Key metrics:
- `mcp_request_duration_seconds` - Request latency
- `mcp_requests_total` - Total requests
- `mcp_learning_accuracy` - Learning accuracy
- `mcp_memory_usage_bytes` - Memory usage

### Grafana Dashboards

Access Grafana at: http://localhost:3000

Dashboards:
- Learning MCP Overview
- Performance Metrics
- Learning Analytics
- Resource Utilization

### Alerting

Configure alerts in `monitoring/alertmanager.yml`:

```yaml
route:
  receiver: 'team-notifications'
  
receivers:
  - name: 'team-notifications'
    email_configs:
      - to: 'team@example.com'
    slack_configs:
      - api_url: 'YOUR_SLACK_WEBHOOK'
```

## Troubleshooting

### Common Issues

1. **Server won't start**
   - Check port availability: `netstat -tulpn | grep 510`
   - Verify memory availability: `free -h`
   - Check logs: `journalctl -u mcp_learning_core`

2. **Learning accuracy low**
   - Check model files exist
   - Verify training data quality
   - Review learning parameters

3. **Performance issues**
   - Monitor CPU usage: `top`
   - Check memory usage: `htop`
   - Review Rust compilation: `cargo build --release`

4. **CODE integration fails**
   - Verify interface server running
   - Check authentication token
   - Test network connectivity

### Debug Mode

Enable debug logging:

```bash
export MCP_LOG_LEVEL=DEBUG
export RUST_LOG=debug
```

### Support

For issues:
1. Check logs in `/var/log/mcp/`
2. Run validation suite
3. Review monitoring dashboards
4. Consult troubleshooting guide

## Backup and Recovery

### Backup Procedures

1. **Model Backup**
```bash
# Backup learning models
tar -czf models_backup_$(date +%Y%m%d).tar.gz /models/
```

2. **Configuration Backup**
```bash
# Backup configurations
cp -r configs/ configs_backup_$(date +%Y%m%d)/
```

3. **Database Backup**
```bash
# Backup learning database
pg_dump learning_mcp > learning_mcp_$(date +%Y%m%d).sql
```

### Recovery Procedures

1. **Restore Models**
```bash
tar -xzf models_backup_20240606.tar.gz -C /
```

2. **Restore Configuration**
```bash
cp -r configs_backup_20240606/* configs/
```

3. **Restart Services**
```bash
sudo systemctl restart mcp_learning_*
```

## Security

### Authentication

Configure authentication in each server config:

```json
{
  "auth": {
    "enabled": true,
    "type": "jwt",
    "secret": "your-secret-key",
    "expiry": 3600
  }
}
```

### TLS/SSL

Enable HTTPS:

```json
{
  "tls": {
    "enabled": true,
    "cert_file": "/path/to/cert.pem",
    "key_file": "/path/to/key.pem"
  }
}
```

### Network Security

Configure firewall rules:

```bash
# Allow MCP ports
sudo ufw allow 5100:5103/tcp
sudo ufw allow 6100:6103/tcp
```

## Performance Tuning

### Memory Optimization

```bash
# Set memory limits
export MCP_MEMORY_LIMIT=12G
export RUST_MIN_STACK=8388608
```

### CPU Optimization

```bash
# Set CPU affinity
taskset -c 0-3 python -m mcp_learning_system.servers.learning_core
```

### Network Optimization

```bash
# Increase network buffers
sudo sysctl -w net.core.rmem_max=134217728
sudo sysctl -w net.core.wmem_max=134217728
```

## Maintenance

### Regular Tasks

1. **Daily**
   - Check server health
   - Review error logs
   - Monitor resource usage

2. **Weekly**
   - Backup models
   - Update learning parameters
   - Review performance metrics

3. **Monthly**
   - Security updates
   - Performance optimization
   - Capacity planning

### Updates

```bash
# Update system
git pull origin main
pip install -r requirements.txt --upgrade
cargo update
cargo build --release

# Restart services
sudo systemctl restart mcp_learning_*
```

## Appendix

### Environment Variables

- `MCP_CONFIG` - Configuration file path
- `MCP_LOG_LEVEL` - Logging level (DEBUG, INFO, WARNING, ERROR)
- `MCP_MEMORY_LIMIT` - Memory limit for all servers
- `RUST_LOG` - Rust logging level
- `PYTHONPATH` - Python module path

### Port Reference

| Server | Main Port | Metrics Port |
|--------|-----------|--------------|
| Learning Core | 5100 | 6100 |
| Learning Analytics | 5101 | 6101 |
| Learning Orchestrator | 5102 | 6102 |
| Learning Interface | 5103 | 6103 |

### API Endpoints

- `/health` - Health check
- `/metrics` - Prometheus metrics
- `/api/v1/learn` - Learning endpoint
- `/api/v1/predict` - Prediction endpoint
- `/api/v1/analyze` - Analysis endpoint