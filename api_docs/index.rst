.. CODE MCP API documentation master file

Claude-Optimized Deployment Engine (CODE) MCP API Documentation
================================================================

Welcome to the comprehensive API documentation for the Claude-Optimized Deployment Engine (CODE). 
This documentation covers all Model Context Protocol (MCP) tools for infrastructure automation, 
monitoring, security, and team communication.

.. toctree::
   :maxdepth: 2
   :caption: Getting Started

   guides/quick_start_guide
   guides/authentication_guide
   guides/integration_patterns

.. toctree::
   :maxdepth: 2
   :caption: API Reference

   reference/mcp_tools_reference
   reference/openapi_specification
   reference/error_codes

.. toctree::
   :maxdepth: 2
   :caption: Developer Resources

   examples/deployment_examples
   examples/monitoring_examples
   examples/security_examples
   postman/postman_collection
   sdks/python_sdk
   sdks/typescript_sdk

.. toctree::
   :maxdepth: 2
   :caption: API Documentation

   api/mcp_servers
   api/mcp_tools
   api/mcp_protocols

Overview
--------

The CODE MCP API provides programmatic access to:

* **Infrastructure Automation** - Docker, Kubernetes, cloud services
* **DevOps Integration** - Azure DevOps, CI/CD pipelines
* **Security Scanning** - Vulnerability assessment and compliance
* **Real-time Monitoring** - Prometheus metrics and observability
* **Team Communication** - Slack notifications and alerts
* **Cloud Storage** - S3 and multi-cloud storage management

Key Features
------------

* **51+ Tools** across 11 MCP servers
* **Async/Await Support** for high-performance operations
* **Built-in Security** with authentication and audit logging
* **Extensible Architecture** for custom MCP servers
* **Comprehensive Error Handling** with retry mechanisms
* **Production-Ready** with battle-tested patterns

Quick Example
-------------

.. code-block:: python

   from src.mcp.manager import get_mcp_manager
   import asyncio

   async def deploy_application():
       manager = get_mcp_manager()
       await manager.initialize()
       
       # Build Docker image
       build_result = await manager.call_tool(
           "docker.docker_build",
           {
               "dockerfile_path": "./Dockerfile",
               "image_tag": "myapp:v1.0.0"
           }
       )
       
       # Deploy to Kubernetes
       deploy_result = await manager.call_tool(
           "kubernetes.kubectl_apply",
           {
               "manifest_path": "./k8s/production/",
               "namespace": "production"
           }
       )
       
       # Send notification
       await manager.call_tool(
           "slack-notifications.send_notification",
           {
               "channel": "#deployments",
               "notification_type": "deployment_success",
               "title": "Production Deployment Complete",
               "details": {"version": "v1.0.0"}
           }
       )

   asyncio.run(deploy_application())

Available MCP Servers
---------------------

1. **Desktop Commander** - Terminal commands and file operations
2. **Docker** - Container lifecycle management
3. **Kubernetes** - Cluster orchestration
4. **Azure DevOps** - CI/CD pipeline automation
5. **Windows System** - Native Windows automation
6. **Prometheus Monitoring** - Metrics and observability
7. **Security Scanner** - Vulnerability assessment
8. **Slack Notifications** - Team communication
9. **S3 Storage** - AWS S3 management
10. **Cloud Storage** - Multi-cloud storage abstraction
11. **Brave Search** - Web search and research

Getting Help
------------

* **GitHub Issues**: https://github.com/claude-optimized-deployment/code/issues
* **Community Forum**: https://forum.code-deployment.com
* **Slack Channel**: #code-deployment
* **Email Support**: support@code-deployment.com

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`