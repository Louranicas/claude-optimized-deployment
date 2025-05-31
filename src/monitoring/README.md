# Comprehensive Monitoring & Metrics Implementation

This module provides enterprise-grade monitoring and observability for the Claude Deployment Engine, following SRE best practices with proper metric naming, SLA tracking, and distributed tracing.

## Features

### 🔍 **Comprehensive Metrics Collection**
- **HTTP/API Metrics**: Request rates, latency percentiles, error rates
- **System Metrics**: CPU, memory, disk usage, file descriptors
- **Business Metrics**: User activity, operation success rates, queue sizes
- **AI/ML Metrics**: Model requests, token usage, costs, provider performance
- **MCP Metrics**: Tool call rates, latency, success rates per server
- **SLA Metrics**: Compliance tracking, error budget consumption

### 🏥 **Health Check System**
- **Kubernetes Probes**: Liveness and readiness endpoints
- **Component Health**: Database, AI providers, MCP servers
- **System Health**: Resource usage, process status
- **Custom Checks**: Extensible health check framework

### 📊 **SLA Tracking & Reporting**
- **Availability SLAs**: 99.9% uptime targets
- **Latency SLAs**: P95/P99 response time tracking
- **Error Rate SLAs**: Error budget management
- **Business SLAs**: Deployment success rates, AI cost efficiency
- **Error Budget**: Burn rate calculation and exhaustion prediction

### 🚨 **Advanced Alerting**
- **Multi-tier Alerts**: Critical, high, medium, low severity levels
- **Smart Routing**: Severity-based notification channels
- **Alert Inhibition**: Prevent alert storms
- **Multiple Channels**: Slack, email, webhooks
- **Prometheus Rules**: Industry-standard alert definitions

### 🔗 **Distributed Tracing**
- **OpenTelemetry**: Industry-standard tracing
- **Jaeger Integration**: Distributed trace visualization
- **Context Propagation**: Cross-service trace correlation
- **Auto-instrumentation**: Automatic HTTP, database, Redis tracing

### 📈 **Rich Dashboards**
- **Grafana Dashboards**: Pre-built comprehensive dashboards
- **SLA Dashboard**: Real-time compliance monitoring
- **Business Dashboard**: Key performance indicators
- **System Dashboard**: Infrastructure monitoring

## Quick Start

### 1. **Automated Setup**
```bash
# Run the comprehensive setup script
python src/monitoring/setup_monitoring.py
```

This will:
- ✅ Check and install dependencies
- ✅ Initialize monitoring components
- ✅ Start Docker monitoring stack
- ✅ Configure health checks and SLA objectives
- ✅ Validate all endpoints

### 2. **Manual Setup**

#### Install Dependencies
```bash
pip install prometheus-client psutil opentelemetry-api opentelemetry-sdk
pip install opentelemetry-instrumentation-fastapi opentelemetry-exporter-jaeger
pip install fastapi uvicorn requests pyyaml
```

#### Start Monitoring Stack
```bash
cd src/monitoring
docker-compose -f docker-compose.monitoring.yml up -d
```

#### Initialize in Your Application
```python
from monitoring import (
    init_tracing,
    get_metrics_collector,
    monitoring_router,
    health_check_middleware
)

# Initialize tracing
init_tracing(
    service_name="claude-deployment-engine",
    environment="production",
    sample_rate=0.1,
    exporter_type="jaeger"
)

# Add monitoring endpoints to FastAPI
app.include_router(monitoring_router)
app.middleware("http")(health_check_middleware)
```

## Usage Examples

### **Metrics Collection**
```python
from monitoring import record_request, record_business_metric, metrics_decorator

# Record HTTP requests automatically
record_request("GET", "/api/users", 200, 0.05)

# Record business operations
record_business_metric("user_registration", "success", 1.2)

# Use decorators for automatic tracking
@metrics_decorator(operation="data_processing")
async def process_data():
    # Your business logic here
    pass
```

### **Health Checks**
```python
from monitoring import register_health_check, health_check

# Register custom health checks
@health_check("external_service")
async def check_external_service():
    try:
        # Check your service
        return True
    except Exception:
        return False

# Check health programmatically
checker = get_health_checker()
report = await checker.check_health_async()
print(f"System health: {report.status}")
```

### **SLA Tracking**
```python
from monitoring import add_sla_objective, check_sla_compliance
from monitoring.sla import SLAObjective, SLAType

# Define custom SLA
add_sla_objective(SLAObjective(
    name="api_latency_p95",
    type=SLAType.LATENCY,
    target=95.0,  # 95% under threshold
    latency_threshold_ms=1000,
    description="95% of API requests under 1 second"
))

# Check compliance
reports = await check_sla_compliance()
for name, report in reports.items():
    print(f"{name}: {report.compliance_percent}% compliant")
```

### **Distributed Tracing**
```python
from monitoring import trace_span, trace_async, set_span_attribute

# Trace functions
@trace_span("user_authentication")
def authenticate_user(user_id):
    set_span_attribute("user.id", user_id)
    # Authentication logic
    return user

# Trace async functions
@trace_async("ai_model_request")
async def call_ai_model(prompt):
    set_span_attribute("ai.model", "claude-3")
    set_span_attribute("ai.prompt_length", len(prompt))
    # AI call logic
    return response
```

### **Custom Alerts**
```python
from monitoring import get_alert_manager, register_alert_handler
from monitoring.alerts import AlertRule, AlertSeverity

# Create custom alert rule
custom_rule = AlertRule(
    name="HighDatabaseConnections",
    expression="database_connections_active > 80",
    duration=timedelta(minutes=5),
    severity=AlertSeverity.HIGH,
    annotations={
        "summary": "Database connection pool nearly exhausted",
        "description": "Active database connections: {{ $value }}"
    }
)

# Register custom alert handler
def custom_alert_handler(alert):
    # Send to your notification system
    send_to_pagerduty(alert)

register_alert_handler(custom_alert_handler)
```

## Monitoring Stack Components

### **Core Services**
- **Prometheus** (`:9090`): Metrics collection and alerting
- **Grafana** (`:3000`): Dashboards and visualization
- **Jaeger** (`:16686`): Distributed tracing
- **AlertManager** (`:9093`): Alert routing and notifications

### **Supporting Services**
- **Node Exporter** (`:9100`): System metrics
- **cAdvisor** (`:8080`): Container metrics
- **Redis** (`:6379`): Caching and session storage
- **PostgreSQL** (`:5432`): Metrics persistence
- **Loki** (`:3100`): Log aggregation

## API Endpoints

### **Health & Status**
- `GET /monitoring/health` - Comprehensive health check
- `GET /monitoring/health/live` - Kubernetes liveness probe
- `GET /monitoring/health/ready` - Kubernetes readiness probe
- `GET /monitoring/metrics` - Prometheus metrics endpoint

### **SLA Management**
- `GET /monitoring/sla` - SLA compliance report
- `GET /monitoring/sla/objectives` - List SLA objectives
- `POST /monitoring/sla/objectives` - Add SLA objective
- `GET /monitoring/sla/error-budget/{objective}` - Error budget status

### **Alert Management**
- `GET /monitoring/alerts` - List active alerts
- `GET /monitoring/alerts/rules` - List alert rules
- `POST /monitoring/alerts/rules/{name}/enable` - Enable alert rule
- `GET /monitoring/alerts/prometheus-rules` - Export Prometheus rules

## Dashboards

### **Pre-built Dashboards**
1. **Overview Dashboard** (`claude_deployment_engine.json`)
   - Request rates and error rates
   - API latency percentiles
   - System resource usage
   - AI provider metrics

2. **Comprehensive SLA Dashboard** (`claude_deployment_engine_comprehensive.json`)
   - SLA compliance gauges
   - Error budget tracking
   - Business metrics
   - Cost monitoring

### **Dashboard Features**
- **Real-time Updates** (5-second refresh)
- **Interactive Filters** (endpoint, AI provider)
- **Alerting Integration** (visual alert indicators)
- **Mobile Responsive** (works on all devices)

## Alert Rules

### **Critical Alerts**
- **Service Down**: Main service unavailable
- **SLA Violation**: Compliance below 99.9%
- **API Unavailable**: API availability below 99.95%
- **Resource Exhaustion**: CPU/Memory above 95%

### **High Priority Alerts**
- **High Error Rate**: API errors above 5%
- **High Latency**: P95 latency above 2 seconds
- **AI Provider Errors**: AI error rate above 10%
- **MCP Tool Failures**: MCP error rate above 10%

### **Warning Alerts**
- **Resource Usage**: CPU/Memory above 85%
- **High AI Costs**: AI costs above $10/hour
- **Queue Backlog**: Queue size above 100 items

## Configuration

### **Environment Variables**
```bash
# Tracing
JAEGER_ENDPOINT=localhost:6831
ENVIRONMENT=production

# Alerting
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
ALERT_EMAIL=oncall@yourcompany.com

# Monitoring
PROMETHEUS_URL=http://localhost:9090
GRAFANA_URL=http://localhost:3000

# Database
POSTGRES_URL=postgresql://user:pass@localhost:5432/monitoring
REDIS_URL=redis://localhost:6379
```

### **Custom Configuration**
```python
# Custom metrics collector
collector = MetricsCollector(registry=custom_registry)

# Custom health checker with different cache TTL
checker = HealthChecker()
checker._cache_ttl = timedelta(seconds=30)

# Custom SLA tracker with different objectives
tracker = SLATracker()
tracker.add_objective(your_custom_sla)
```

## Deployment Considerations

### **Production Setup**
- **Resource Limits**: Set appropriate CPU/memory limits
- **Data Retention**: Configure Prometheus retention (default: 30 days)
- **High Availability**: Deploy multiple Prometheus instances
- **Security**: Enable authentication for Grafana and other UIs

### **Scaling**
- **Prometheus Federation**: For multi-cluster deployments
- **Remote Storage**: For long-term metrics storage
- **Alert Routing**: Configure PagerDuty/OpsGenie integration
- **Log Aggregation**: Scale Loki for high-volume logging

### **Best Practices**
- **Metric Naming**: Follow Prometheus naming conventions
- **Label Management**: Keep cardinality reasonable
- **SLA Definition**: Align with business requirements
- **Alert Tuning**: Minimize false positives
- **Dashboard Design**: Focus on actionable metrics

## Troubleshooting

### **Common Issues**
1. **Metrics Not Appearing**
   - Check Prometheus targets: http://localhost:9090/targets
   - Verify metrics endpoint accessibility
   - Check firewall/network connectivity

2. **High Memory Usage**
   - Review metric cardinality
   - Adjust Prometheus retention settings
   - Optimize query patterns

3. **Alert Fatigue**
   - Tune alert thresholds
   - Implement alert inhibition rules
   - Review alert severity levels

4. **Tracing Issues**
   - Verify Jaeger connectivity
   - Check sampling configuration
   - Review instrumentation setup

### **Debug Commands**
```bash
# Check monitoring stack status
docker-compose -f docker-compose.monitoring.yml ps

# View logs
docker-compose -f docker-compose.monitoring.yml logs prometheus
docker-compose -f docker-compose.monitoring.yml logs grafana

# Test metrics endpoint
curl http://localhost:8000/monitoring/metrics

# Validate Prometheus config
docker exec claude-prometheus promtool check config /etc/prometheus/prometheus.yml
```

## Integration Examples

### **FastAPI Integration**
```python
from fastapi import FastAPI
from monitoring import monitoring_router, health_check_middleware

app = FastAPI()

# Add monitoring middleware
app.middleware("http")(health_check_middleware)

# Include monitoring routes
app.include_router(monitoring_router)

@app.on_event("startup")
async def startup():
    init_tracing(service_name="my-api")
```

### **Background Task Monitoring**
```python
from monitoring import metrics_decorator, trace_async

@metrics_decorator(operation="background_task")
@trace_async("data_processing")
async def process_background_data():
    # Your background task logic
    pass
```

### **Custom Business Metrics**
```python
from monitoring import get_metrics_collector
from prometheus_client import Counter, Histogram

collector = get_metrics_collector()

# Custom business counter
user_actions = Counter(
    'user_actions_total',
    'Total user actions',
    ['action_type', 'user_tier']
)

user_actions.labels(action_type='login', user_tier='premium').inc()
```

This monitoring implementation provides enterprise-grade observability with comprehensive metrics, SLA tracking, distributed tracing, and intelligent alerting - essential for production deployment of the Claude Deployment Engine.