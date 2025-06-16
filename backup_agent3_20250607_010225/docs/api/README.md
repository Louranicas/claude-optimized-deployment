# CODE API Documentation

[![Documentation Status](https://img.shields.io/badge/docs-latest-brightgreen.svg)](https://code-engine.io/docs/)
[![API Version](https://img.shields.io/badge/API-v1.0.0-blue.svg)](./openapi.yaml)
[![Python Client](https://img.shields.io/badge/client-Python-green.svg)](./clients/python-client.py)
[![JavaScript Client](https://img.shields.io/badge/client-JavaScript-yellow.svg)](./clients/javascript-client.js)

Complete API documentation for the Claude-Optimized Deployment Engine (CODE) - a hybrid Python/Rust infrastructure management system with AI-powered consultation capabilities.

## 📚 Documentation Contents

### 🚀 Getting Started
- **[Developer Quickstart](./quickstart.md)** - Get up and running in minutes
- **[OpenAPI Specification](./openapi.yaml)** - Complete API specification
- **[Postman Collection](./postman-collection.json)** - Ready-to-use API testing

### 🔧 API Reference
- **[Circuit Breakers](./circuit-breakers.md)** - Service resilience management
- **[MCP Tools](./mcp-tools.md)** - 51+ infrastructure automation tools
- **[Expert Consultation](./experts.md)** - AI-powered decision making
- **[Deployments](./deployments.md)** - Application deployment automation
- **[Security](./security.md)** - Vulnerability scanning and management
- **[Monitoring](./monitoring.md)** - Real-time metrics and alerting
- **[Webhooks](./webhooks.md)** - Event-driven notifications

### 💻 Client Libraries
- **[Python Client](./clients/python-client.py)** - Async Python client with retry logic
- **[JavaScript Client](./clients/javascript-client.js)** - Node.js/Browser client

### 📖 Advanced Topics
- **[Rate Limiting](./rate-limits.md)** - Usage limits and best practices
- **[Webhook Setup](./webhook-setup.md)** - Event notification configuration
- **[Authentication](./authentication.md)** - API key and JWT authentication

## 🏗️ Building Documentation

### Prerequisites

```bash
# Install Python dependencies
pip install -r requirements.txt

# Optional: Install OpenAPI tools
npm install -g @openapitools/openapi-generator-cli
```

### Build Commands

```bash
# Build HTML documentation
make html

# Serve with live reload (development)
make livehtml

# Build and check for errors
make check

# Full production build
make production

# Generate API clients
make generate-clients
```

### Development Workflow

```bash
# Start live development server
make dev-watch

# The documentation will be available at:
# http://localhost:8080
```

## 🎯 Key Features Documented

### MCP Tools Integration
51+ tools across 11 servers for complete infrastructure automation:

- **Docker**: Container lifecycle management (8 tools)
- **Kubernetes**: Cluster operations (6 tools)  
- **Security Scanner**: Vulnerability assessment (4 tools)
- **Slack Notifications**: Team communication (3 tools)
- **Prometheus Monitoring**: Metrics and alerting (3 tools)
- **S3 Storage**: Cloud storage automation (4 tools)
- **And more...** Desktop Commander, Azure DevOps, Windows System

### AI Expert Consultation
Circle of Experts system with multiple AI providers:
- Architecture guidance
- Deployment strategy recommendations
- Security best practices
- Performance optimization

### Real-Time Monitoring
Comprehensive observability features:
- Circuit breaker patterns
- Prometheus metrics integration
- Custom alerting rules
- System health dashboards

## 📋 API Quick Reference

### Base URL
```
Production: https://api.code-engine.io
Development: http://localhost:8000
```

### Authentication
```bash
# API Key (recommended)
curl -H "X-API-Key: your-api-key" https://api.code-engine.io/api/health

# JWT Token
curl -H "Authorization: Bearer your-jwt-token" https://api.code-engine.io/api/health
```

### Quick Examples

#### Execute MCP Tool
```bash
curl -X POST -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  https://api.code-engine.io/api/mcp/execute \
  -d '{
    "server": "docker",
    "tool": "docker_ps",
    "arguments": {}
  }'
```

#### Deploy Application
```bash
curl -X POST -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  https://api.code-engine.io/api/deployments \
  -d '{
    "application_name": "my-app",
    "environment": "production",
    "deployment_type": "kubernetes",
    "source": {
      "type": "git",
      "repository": "https://github.com/me/my-app.git"
    }
  }'
```

#### Consult AI Experts
```bash
curl -X POST -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  https://api.code-engine.io/api/experts/consult \
  -d '{
    "query": "What is the best deployment strategy for microservices?",
    "expert_types": ["deployment", "architecture"]
  }'
```

## 🔄 Rate Limits

| Endpoint Category | Requests/Min | Burst | Notes |
|------------------|--------------|-------|-------|
| Health Checks | 60 | 120 | System status |
| MCP Tools (Read) | 100 | 200 | List servers/tools |
| MCP Tools (Execute) | 30 | 60 | Tool execution |
| Expert Consultation | 10 | 20 | AI queries |
| Deployments | 20 | 40 | Create deployments |

See [Rate Limiting Documentation](./rate-limits.md) for complete details.

## 🔐 Security

- **HTTPS Everywhere**: All production endpoints use TLS 1.3
- **API Key Authentication**: Secure service-to-service communication
- **JWT Tokens**: User authentication with configurable expiration
- **Rate Limiting**: Protection against abuse and DoS attacks
- **Input Validation**: Comprehensive request validation
- **CORS Support**: Configurable cross-origin access

## 🚨 Error Handling

All API responses follow a consistent error format:

```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded for MCP tool execution",
    "details": {
      "limit": 30,
      "window": "1 minute",
      "retry_after": 30
    },
    "timestamp": "2025-05-31T10:19:30.000Z",
    "request_id": "req-123456789"
  }
}
```

Common HTTP status codes:
- `200` - Success
- `400` - Bad Request (validation error)
- `401` - Unauthorized (invalid API key)
- `403` - Forbidden (insufficient permissions)
- `429` - Too Many Requests (rate limited)
- `500` - Internal Server Error

## 🔗 Webhooks

Register for real-time event notifications:

```json
{
  "url": "https://your-app.com/webhooks/code",
  "events": [
    "deployment.completed",
    "deployment.failed",
    "security.vulnerability_found",
    "circuit_breaker.opened"
  ],
  "secret": "your-webhook-secret"
}
```

Supported events:
- Deployment lifecycle events
- Security scan results
- Circuit breaker state changes
- System health alerts
- Custom metric thresholds

## 📊 Client Libraries

### Python Client
```python
import asyncio
from code_client import CODEClient

async def main():
    async with CODEClient("https://api.code-engine.io", "your-key") as client:
        # Deploy application
        result = await client.deployments.create({
            "application_name": "my-app",
            "environment": "production",
            "deployment_type": "kubernetes"
        })
        print(f"Deployment ID: {result['deployment_id']}")

asyncio.run(main())
```

### JavaScript Client
```javascript
const { CODEClient } = require('./code-client');

async function main() {
    const client = new CODEClient('https://api.code-engine.io', 'your-key');
    
    // Execute MCP tool
    const containers = await client.mcp.dockerPs();
    console.log(`Running containers: ${containers.result.containers.length}`);
}

main().catch(console.error);
```

## 🧪 Testing

### Postman Collection
Import the [Postman collection](./postman-collection.json) for interactive API testing:

1. Download `postman-collection.json`
2. Import into Postman
3. Set environment variables:
   - `BASE_URL`: Your API base URL
   - `API_KEY`: Your API key
4. Start testing!

### curl Examples
Every endpoint includes curl examples with real request/response data.

### Client Libraries
Both Python and JavaScript clients include comprehensive examples and test suites.

## 📈 Monitoring & Analytics

Track API usage with built-in metrics:

- Request volume and latency
- Error rates by endpoint
- Rate limit utilization
- Circuit breaker states
- Expert consultation costs

Dashboard available at: https://api.code-engine.io/metrics

## 🆘 Support

### Documentation Issues
- [GitHub Issues](https://github.com/your-org/claude-optimized-deployment/issues)
- [Documentation Discussions](https://github.com/your-org/claude-optimized-deployment/discussions)

### API Support
- **Email**: api-support@code-engine.io
- **Response Time**: < 24 hours
- **Enterprise Support**: Available for dedicated plans

### Community
- [GitHub Discussions](https://github.com/your-org/claude-optimized-deployment/discussions)
- [Discord Server](https://discord.gg/code-engine)
- [Stack Overflow](https://stackoverflow.com/questions/tagged/code-engine)

## 🔄 Updates

Documentation is automatically updated with each API release:

- **Versioning**: Semantic versioning (v1.0.0)
- **Changelog**: Available in each release
- **Migration Guides**: For breaking changes
- **Deprecation Notices**: 90-day advance notice

Subscribe to updates:
- [GitHub Releases](https://github.com/your-org/claude-optimized-deployment/releases)
- [API Changelog RSS](https://api.code-engine.io/changelog.rss)

## 📄 License

This documentation is licensed under MIT License. See [LICENSE](../../LICENSE) for details.

---

**Built with ❤️ by the CODE development team**

Last updated: 2025-05-31 | [View source](https://github.com/your-org/claude-optimized-deployment/tree/main/docs/api)