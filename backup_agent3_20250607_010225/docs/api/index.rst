.. CODE API Documentation master file

==================================================
Claude-Optimized Deployment Engine (CODE) API
==================================================

.. image:: https://img.shields.io/badge/version-1.0.0-blue.svg
   :alt: Version 1.0.0

.. image:: https://img.shields.io/badge/Python-3.8+-green.svg
   :alt: Python 3.8+

.. image:: https://img.shields.io/badge/Node.js-16+-green.svg
   :alt: Node.js 16+

.. image:: https://img.shields.io/badge/API-REST-orange.svg
   :alt: REST API

.. image:: https://img.shields.io/badge/License-MIT-blue.svg
   :alt: MIT License

Welcome to the comprehensive API documentation for the Claude-Optimized Deployment Engine (CODE). 
This documentation provides everything you need to integrate with CODE's powerful infrastructure 
automation capabilities.

What is CODE?
=============

The Claude-Optimized Deployment Engine is a hybrid Python/Rust infrastructure management system 
with AI-powered consultation capabilities and comprehensive MCP (Model Context Protocol) integration. 
It provides:

✅ **51+ MCP Tools** across 11 servers for complete infrastructure automation

✅ **AI-Powered Consultation** through the Circle of Experts system  

✅ **Multi-Platform Support** for Docker, Kubernetes, AWS, Azure, and more

✅ **Security-First Design** with automated vulnerability scanning

✅ **Real-Time Monitoring** with Prometheus and alert management

✅ **Team Collaboration** through Slack notifications and webhooks

.. note::
   **Current Status**: 70% complete and fully functional for deployment automation.
   The system is production-ready for containerized applications and Kubernetes deployments.

Quick Start
===========

Get started with CODE in minutes:

.. tabs::

   .. tab:: Docker (Recommended)

      .. code-block:: bash

         # Clone and start with Docker Compose
         git clone https://github.com/your-org/claude-optimized-deployment.git
         cd claude-optimized-deployment
         docker-compose up -d

         # API available at http://localhost:8000

   .. tab:: Local Development

      .. code-block:: bash

         # Clone and setup
         git clone https://github.com/your-org/claude-optimized-deployment.git
         cd claude-optimized-deployment
         make dev-setup
         make api-run

         # API available at http://localhost:8000

   .. tab:: Python Client

      .. code-block:: python

         # Install and use Python client
         pip install aiohttp

         import asyncio
         from clients.python_client import CODEClient

         async def main():
             async with CODEClient("http://localhost:8000", "your-api-key") as client:
                 health = await client.circuit_breakers.get_health()
                 print(f"System health: {health['health']}")

         asyncio.run(main())

   .. tab:: JavaScript Client

      .. code-block:: javascript

         // Install and use JavaScript client
         npm install axios

         const { CODEClient } = require('./clients/javascript-client');

         async function main() {
             const client = new CODEClient('http://localhost:8000', 'your-api-key');
             const health = await client.circuitBreakers.getHealth();
             console.log(`System health: ${health.health}`);
         }

         main().catch(console.error);

API Overview
============

The CODE API is organized into several functional areas:

.. grid:: 2
   :gutter: 3

   .. grid-item-card:: 🔄 Circuit Breakers
      :link: circuit-breakers
      :link-type: ref

      Manage service resilience and failure recovery with automatic circuit breaker patterns.

   .. grid-item-card:: 🛠️ MCP Tools  
      :link: mcp-tools
      :link-type: ref

      Execute 51+ infrastructure tools across 11 servers for complete automation.

   .. grid-item-card:: 🧠 AI Experts
      :link: experts
      :link-type: ref

      Consult AI experts for intelligent deployment decisions and architecture guidance.

   .. grid-item-card:: 🚀 Deployments
      :link: deployments  
      :link-type: ref

      Automate application deployments with comprehensive pre-checks and monitoring.

   .. grid-item-card:: 🔒 Security
      :link: security
      :link-type: ref

      Scan for vulnerabilities in dependencies, containers, and source code.

   .. grid-item-card:: 📊 Monitoring
      :link: monitoring
      :link-type: ref

      Collect metrics, manage alerts, and monitor system health in real-time.

   .. grid-item-card:: 🔗 Webhooks
      :link: webhooks
      :link-type: ref

      Receive real-time notifications for deployments, security events, and system changes.

   .. grid-item-card:: ⚡ Rate Limiting
      :link: rate-limits
      :link-type: ref

      Understand API limits, implement proper retry logic, and optimize usage.

First API Call
==============

Verify your setup with a simple health check:

.. code-block:: bash

   curl -H "X-API-Key: your-api-key" http://localhost:8000/api/circuit-breakers/health

Expected response:

.. code-block:: json

   {
     "timestamp": "2025-05-31T10:00:00.000Z",
     "health": "healthy",
     "details": {
       "total_breakers": 10,
       "healthy_breakers": 10,
       "degraded_breakers": 0,
       "failed_breakers": 0
     },
     "recommendations": []
   }

MCP Tools Example
=================

Execute infrastructure tools through the MCP protocol:

.. code-block:: bash

   # Build and run a Docker container
   curl -X POST -H "X-API-Key: your-api-key" \
     -H "Content-Type: application/json" \
     http://localhost:8000/api/mcp/execute \
     -d '{
       "server": "docker",
       "tool": "docker_build",
       "arguments": {
         "dockerfile_path": ".",
         "image_tag": "my-app:latest"
       }
     }'

Documentation Sections
======================

.. toctree::
   :maxdepth: 2
   :caption: Getting Started

   quickstart
   authentication
   first-steps

.. toctree::
   :maxdepth: 2
   :caption: API Reference

   openapi-spec
   circuit-breakers
   mcp-tools  
   experts
   deployments
   security
   monitoring
   webhooks

.. toctree::
   :maxdepth: 2
   :caption: Client Libraries

   clients/python-client
   clients/javascript-client
   clients/examples

.. toctree::
   :maxdepth: 2
   :caption: Developer Resources

   rate-limits
   error-handling
   best-practices
   testing

.. toctree::
   :maxdepth: 2
   :caption: Integration Guides

   postman-collection
   webhook-setup
   monitoring-setup
   ci-cd-integration

.. toctree::
   :maxdepth: 1
   :caption: Examples & Tutorials

   examples/basic-usage
   examples/deployment-workflow
   examples/security-scanning
   examples/monitoring-dashboard

OpenAPI Specification
=====================

The complete OpenAPI 3.0 specification is available:

- **Interactive Documentation**: http://localhost:8000/docs
- **ReDoc Interface**: http://localhost:8000/redoc  
- **OpenAPI JSON**: http://localhost:8000/openapi.json
- **OpenAPI YAML**: :download:`openapi.yaml <openapi.yaml>`

.. openapi:: openapi.yaml
   :format: json

Key Features
============

🔧 **Infrastructure Automation**
   Deploy to Docker, Kubernetes, AWS, Azure, and more through unified MCP tools.

🤖 **AI-Powered Decisions**  
   Get intelligent recommendations from multiple AI experts for architecture and deployment choices.

🛡️ **Security-First**
   Automated vulnerability scanning for dependencies, containers, and source code.

📈 **Real-Time Monitoring**
   Prometheus integration with custom metrics, alerts, and dashboard automation.

💬 **Team Integration**
   Slack notifications, webhook events, and collaborative deployment workflows.

⚡ **High Performance**
   Rust-accelerated core operations with 2-20x performance improvements.

Use Cases
=========

**DevOps Teams**
   Automate deployment pipelines with AI-guided decision making and comprehensive security scanning.

**Development Teams**  
   Integrate deployment automation into existing workflows with minimal configuration.

**Enterprise Organizations**
   Scale infrastructure management across multiple environments with centralized monitoring.

**Security Teams**
   Implement automated security scanning and vulnerability management in CI/CD pipelines.

Support & Community
===================

- **Documentation**: This site and inline API docs
- **GitHub Issues**: `Report bugs and request features <https://github.com/your-org/claude-optimized-deployment/issues>`_
- **Community Discussions**: `Join the conversation <https://github.com/your-org/claude-optimized-deployment/discussions>`_
- **Email Support**: support@code-engine.io

License
=======

The Claude-Optimized Deployment Engine is released under the MIT License. 
See the `LICENSE <https://github.com/your-org/claude-optimized-deployment/blob/main/LICENSE>`_ file for details.

Contributing
============

We welcome contributions! Please see our `Contributing Guide <https://github.com/your-org/claude-optimized-deployment/blob/main/CONTRIBUTING.md>`_ 
for details on how to get started.

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`