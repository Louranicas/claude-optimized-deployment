"""Integration tests for MCP cross-server workflows."""

import asyncio
import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Dict, Any

from src.mcp.manager import MCPManager
from src.mcp.protocols import MCPToolCall, MCPToolResult


class TestMCPWorkflows:
    """Test cross-server MCP workflows."""

    @pytest.fixture
    async def mcp_manager(self):
        """Create a configured MCP manager for testing."""
        manager = MCPManager()
        await manager.initialize()
        return manager

    @pytest.fixture
    def mock_tool_results(self):
        """Mock successful tool results for different servers."""
        return {
            "docker.docker_build": MCPToolResult(
                success=True,
                output="Successfully built image: my-app:latest",
                metadata={"image_id": "sha256:abc123", "size": "150MB"}
            ),
            "kubernetes.kubectl_apply": MCPToolResult(
                success=True,
                output="deployment.apps/my-app created\nservice/my-app created",
                metadata={"resources_created": ["deployment", "service"]}
            ),
            "security-scanner.docker_security_scan": MCPToolResult(
                success=True,
                output="No critical vulnerabilities found",
                metadata={"vulnerabilities": {"critical": 0, "high": 2, "medium": 5}}
            ),
            "slack.send_notification": MCPToolResult(
                success=True,
                output="Notification sent successfully",
                metadata={"message_id": "msg123", "channel": "#deployments"}
            ),
            "prometheus.prometheus_query": MCPToolResult(
                success=True,
                output="Query executed successfully",
                metadata={"result": [{"metric": {"pod": "my-app-1"}, "value": [1234567890, "0.95"]}]}
            )
        }

    @pytest.mark.asyncio
    async def test_docker_to_kubernetes_workflow(self, mcp_manager, mock_tool_results):
        """Test Docker build followed by Kubernetes deployment."""
        with patch.object(mcp_manager, 'call_tool', new_callable=AsyncMock) as mock_call:
            # Setup mock returns
            mock_call.side_effect = [
                mock_tool_results["docker.docker_build"],
                mock_tool_results["kubernetes.kubectl_apply"]
            ]

            # Execute workflow
            # Step 1: Build Docker image
            build_result = await mcp_manager.call_tool(
                "docker.docker_build",
                {
                    "dockerfile_path": "./Dockerfile",
                    "image_tag": "my-app:latest",
                    "build_args": {"VERSION": "1.0.0"}
                }
            )
            assert build_result.success
            assert "Successfully built" in build_result.output

            # Step 2: Deploy to Kubernetes
            deploy_result = await mcp_manager.call_tool(
                "kubernetes.kubectl_apply",
                {
                    "manifest_path": "./k8s/deployment.yaml",
                    "namespace": "production"
                }
            )
            assert deploy_result.success
            assert "created" in deploy_result.output

            # Verify workflow execution
            assert mock_call.call_count == 2
            mock_call.assert_any_call(
                "docker.docker_build",
                {
                    "dockerfile_path": "./Dockerfile",
                    "image_tag": "my-app:latest",
                    "build_args": {"VERSION": "1.0.0"}
                }
            )

    @pytest.mark.asyncio
    async def test_security_scan_to_notification_workflow(self, mcp_manager, mock_tool_results):
        """Test security scan followed by Slack notification."""
        with patch.object(mcp_manager, 'call_tool', new_callable=AsyncMock) as mock_call:
            # Setup mock returns
            mock_call.side_effect = [
                mock_tool_results["security-scanner.docker_security_scan"],
                mock_tool_results["slack.send_notification"]
            ]

            # Execute workflow
            # Step 1: Scan Docker image
            scan_result = await mcp_manager.call_tool(
                "security-scanner.docker_security_scan",
                {"image_name": "my-app:latest"}
            )
            assert scan_result.success

            # Step 2: Send notification based on results
            vulnerabilities = scan_result.metadata.get("vulnerabilities", {})
            if vulnerabilities.get("critical", 0) == 0:
                notification_message = "✅ Security scan passed: No critical vulnerabilities"
            else:
                notification_message = f"⚠️ Security scan failed: {vulnerabilities.get('critical')} critical vulnerabilities"

            notify_result = await mcp_manager.call_tool(
                "slack.send_notification",
                {
                    "channel": "#security-alerts",
                    "message": notification_message,
                    "level": "info" if vulnerabilities.get("critical", 0) == 0 else "error"
                }
            )
            assert notify_result.success

            # Verify workflow execution
            assert mock_call.call_count == 2

    @pytest.mark.asyncio
    async def test_monitoring_alert_workflow(self, mcp_manager, mock_tool_results):
        """Test Prometheus monitoring triggering alerts."""
        with patch.object(mcp_manager, 'call_tool', new_callable=AsyncMock) as mock_call:
            # Setup mock returns for high CPU alert
            high_cpu_result = MCPToolResult(
                success=True,
                output="Query executed successfully",
                metadata={"result": [{"metric": {"pod": "my-app-1"}, "value": [1234567890, "0.95"]}]}
            )
            mock_call.side_effect = [
                high_cpu_result,
                mock_tool_results["slack.send_notification"]
            ]

            # Execute workflow
            # Step 1: Query CPU usage
            cpu_result = await mcp_manager.call_tool(
                "prometheus.prometheus_query",
                {"query": 'rate(container_cpu_usage_seconds_total{pod=~"my-app-.*"}[5m])'}
            )
            assert cpu_result.success

            # Step 2: Check threshold and alert if needed
            cpu_value = float(cpu_result.metadata["result"][0]["value"][1])
            if cpu_value > 0.8:  # 80% CPU threshold
                alert_result = await mcp_manager.call_tool(
                    "slack.send_notification",
                    {
                        "channel": "#alerts",
                        "message": f"🚨 High CPU Alert: Pod my-app-1 at {cpu_value*100:.1f}% CPU",
                        "level": "warning"
                    }
                )
                assert alert_result.success

            # Verify alert was triggered
            assert mock_call.call_count == 2

    @pytest.mark.asyncio
    async def test_full_deployment_pipeline(self, mcp_manager, mock_tool_results):
        """Test complete deployment pipeline with all stages."""
        with patch.object(mcp_manager, 'call_tool', new_callable=AsyncMock) as mock_call:
            # Setup mock returns for full pipeline
            mock_call.side_effect = [
                mock_tool_results["security-scanner.docker_security_scan"],
                mock_tool_results["docker.docker_build"],
                mock_tool_results["kubernetes.kubectl_apply"],
                mock_tool_results["prometheus.prometheus_query"],
                mock_tool_results["slack.send_notification"]
            ]

            # Execute full pipeline
            pipeline_results = {}

            # Stage 1: Security scan
            scan_result = await mcp_manager.call_tool(
                "security-scanner.docker_security_scan",
                {"image_name": "my-app:dev"}
            )
            pipeline_results["security_scan"] = scan_result
            assert scan_result.success

            # Stage 2: Build if scan passed
            if scan_result.metadata.get("vulnerabilities", {}).get("critical", 0) == 0:
                build_result = await mcp_manager.call_tool(
                    "docker.docker_build",
                    {
                        "dockerfile_path": "./Dockerfile",
                        "image_tag": "my-app:latest"
                    }
                )
                pipeline_results["docker_build"] = build_result
                assert build_result.success

                # Stage 3: Deploy
                deploy_result = await mcp_manager.call_tool(
                    "kubernetes.kubectl_apply",
                    {"manifest_path": "./k8s/"}
                )
                pipeline_results["kubernetes_deploy"] = deploy_result
                assert deploy_result.success

                # Stage 4: Verify deployment
                await asyncio.sleep(0.1)  # Simulate wait for deployment
                health_result = await mcp_manager.call_tool(
                    "prometheus.prometheus_query",
                    {"query": 'up{job="my-app"}'}
                )
                pipeline_results["health_check"] = health_result
                assert health_result.success

                # Stage 5: Notify success
                notify_result = await mcp_manager.call_tool(
                    "slack.send_notification",
                    {
                        "channel": "#deployments",
                        "message": "✅ Deployment successful: my-app:latest deployed to production",
                        "level": "success"
                    }
                )
                pipeline_results["notification"] = notify_result
                assert notify_result.success

            # Verify full pipeline execution
            assert mock_call.call_count == 5
            assert all(result.success for result in pipeline_results.values())

    @pytest.mark.asyncio
    async def test_parallel_workflow_execution(self, mcp_manager, mock_tool_results):
        """Test parallel execution of independent MCP tools."""
        with patch.object(mcp_manager, 'call_tool', new_callable=AsyncMock) as mock_call:
            # Setup mock returns
            mock_call.side_effect = [
                mock_tool_results["security-scanner.docker_security_scan"],
                mock_tool_results["prometheus.prometheus_query"],
                mock_tool_results["docker.docker_build"]
            ]

            # Execute parallel tasks
            tasks = [
                mcp_manager.call_tool("security-scanner.docker_security_scan", {"image_name": "app1"}),
                mcp_manager.call_tool("prometheus.prometheus_query", {"query": "up"}),
                mcp_manager.call_tool("docker.docker_build", {"dockerfile_path": "./", "image_tag": "app2"})
            ]

            results = await asyncio.gather(*tasks)

            # Verify all tasks completed successfully
            assert len(results) == 3
            assert all(result.success for result in results)
            assert mock_call.call_count == 3

    @pytest.mark.asyncio
    async def test_workflow_error_handling(self, mcp_manager):
        """Test workflow behavior when tools fail."""
        with patch.object(mcp_manager, 'call_tool', new_callable=AsyncMock) as mock_call:
            # Setup mock failure
            mock_call.side_effect = [
                MCPToolResult(
                    success=False,
                    output="Build failed: Dockerfile not found",
                    error="FileNotFoundError"
                ),
                MCPToolResult(
                    success=True,
                    output="Error notification sent",
                    metadata={"message_id": "err123"}
                )
            ]

            # Execute workflow with error handling
            build_result = await mcp_manager.call_tool(
                "docker.docker_build",
                {"dockerfile_path": "./missing/Dockerfile", "image_tag": "app:latest"}
            )
            assert not build_result.success

            # Send error notification
            error_notify = await mcp_manager.call_tool(
                "slack.send_notification",
                {
                    "channel": "#errors",
                    "message": f"❌ Build failed: {build_result.output}",
                    "level": "error"
                }
            )
            assert error_notify.success

            # Verify error handling flow
            assert mock_call.call_count == 2

    @pytest.mark.asyncio
    async def test_conditional_workflow_branching(self, mcp_manager, mock_tool_results):
        """Test workflows with conditional branching based on results."""
        with patch.object(mcp_manager, 'call_tool', new_callable=AsyncMock) as mock_call:
            # Setup mock with high vulnerabilities
            high_vuln_result = MCPToolResult(
                success=True,
                output="3 critical vulnerabilities found",
                metadata={"vulnerabilities": {"critical": 3, "high": 5, "medium": 10}}
            )
            mock_call.side_effect = [
                high_vuln_result,
                mock_tool_results["slack.send_notification"]
            ]

            # Execute conditional workflow
            scan_result = await mcp_manager.call_tool(
                "security-scanner.docker_security_scan",
                {"image_name": "vulnerable-app:latest"}
            )

            # Branch based on scan results
            if scan_result.metadata.get("vulnerabilities", {}).get("critical", 0) > 0:
                # Critical vulnerabilities - stop deployment
                await mcp_manager.call_tool(
                    "slack.send_notification",
                    {
                        "channel": "#security-alerts",
                        "message": "🛑 Deployment blocked: 3 critical vulnerabilities detected",
                        "level": "error"
                    }
                )
                # Don't proceed with deployment
                deploy_executed = False
            else:
                # No critical vulnerabilities - proceed
                deploy_executed = True

            # Verify conditional execution
            assert not deploy_executed
            assert mock_call.call_count == 2

    @pytest.mark.asyncio
    async def test_workflow_with_retries(self, mcp_manager):
        """Test workflow resilience with retry logic."""
        with patch.object(mcp_manager, 'call_tool', new_callable=AsyncMock) as mock_call:
            # Setup mock with intermittent failures
            mock_call.side_effect = [
                MCPToolResult(success=False, output="Network timeout", error="TimeoutError"),
                MCPToolResult(success=False, output="Network timeout", error="TimeoutError"),
                MCPToolResult(success=True, output="Deployment successful", metadata={})
            ]

            # Execute with retries
            max_retries = 3
            retry_count = 0
            result = None

            while retry_count < max_retries:
                result = await mcp_manager.call_tool(
                    "kubernetes.kubectl_apply",
                    {"manifest_path": "./k8s/deployment.yaml"}
                )
                if result.success:
                    break
                retry_count += 1
                await asyncio.sleep(0.1)  # Backoff

            # Verify retry success
            assert result.success
            assert mock_call.call_count == 3

    @pytest.mark.asyncio
    async def test_multi_environment_workflow(self, mcp_manager, mock_tool_results):
        """Test workflows across multiple environments."""
        environments = ["dev", "staging", "production"]
        
        with patch.object(mcp_manager, 'call_tool', new_callable=AsyncMock) as mock_call:
            mock_call.return_value = mock_tool_results["kubernetes.kubectl_apply"]

            # Deploy to multiple environments
            deployment_results = {}
            
            for env in environments:
                result = await mcp_manager.call_tool(
                    "kubernetes.kubectl_apply",
                    {
                        "manifest_path": f"./k8s/{env}/",
                        "namespace": env
                    }
                )
                deployment_results[env] = result

            # Verify all environments deployed
            assert len(deployment_results) == 3
            assert all(result.success for result in deployment_results.values())
            assert mock_call.call_count == 3