"""End-to-end tests for complete deployment pipeline using MCP servers."""

import asyncio
import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime
from typing import Dict, Any, List

from src.mcp.manager import MCPManager, get_mcp_manager
from src.mcp.protocols import MCPToolResult
from src.circle_of_experts.core.expert_manager import ExpertManager
from src.circle_of_experts.models.query import Query
from src.circle_of_experts.models.response import Response, ResponseStatus


class TestDeploymentPipeline:
    """End-to-end tests for the complete deployment pipeline."""

    @pytest.fixture
    async def mcp_manager(self):
        """Create configured MCP manager."""
        manager = get_mcp_manager()
        await manager.initialize()
        return manager

    @pytest.fixture
    async def expert_manager(self):
        """Create configured expert manager."""
        manager = ExpertManager()
        # Mock expert initialization to avoid API calls
        with patch.object(manager, '_initialize_experts'):
            await manager.initialize()
        return manager

    @pytest.fixture
    def deployment_config(self):
        """Standard deployment configuration."""
        return {
            "app_name": "test-app",
            "version": "1.0.0",
            "environment": "staging",
            "dockerfile_path": "./Dockerfile",
            "k8s_manifests": "./k8s/staging/",
            "security_threshold": {
                "critical": 0,
                "high": 5,
                "medium": 20
            },
            "health_check": {
                "endpoint": "/health",
                "timeout": 30,
                "retries": 3
            },
            "notifications": {
                "slack_channel": "#deployments",
                "email_list": ["devops@example.com"]
            }
        }

    @pytest.mark.asyncio
    async def test_complete_deployment_pipeline(self, mcp_manager, deployment_config):
        """Test complete deployment pipeline from code to production."""
        pipeline_state = {
            "start_time": datetime.now(),
            "steps_completed": [],
            "artifacts": {},
            "errors": []
        }

        with patch.object(mcp_manager, 'call_tool', new_callable=AsyncMock) as mock_call:
            # Setup successful mock responses for all pipeline steps
            mock_responses = {
                "security-scanner.file_security_scan": MCPToolResult(
                    success=True,
                    output="No security issues found in source code",
                    metadata={"issues": 0}
                ),
                "docker.docker_build": MCPToolResult(
                    success=True,
                    output=f"Successfully built {deployment_config['app_name']}:{deployment_config['version']}",
                    metadata={"image_id": "sha256:abc123", "size_mb": 150}
                ),
                "security-scanner.docker_security_scan": MCPToolResult(
                    success=True,
                    output="Image scan complete",
                    metadata={"vulnerabilities": {"critical": 0, "high": 2, "medium": 15}}
                ),
                "docker.docker_run": MCPToolResult(
                    success=True,
                    output="Container started for testing",
                    metadata={"container_id": "test123"}
                ),
                "desktop-commander.execute_command": MCPToolResult(
                    success=True,
                    output="All tests passed (50 tests in 5.2s)",
                    metadata={"tests_passed": 50, "tests_failed": 0}
                ),
                "kubernetes.kubectl_apply": MCPToolResult(
                    success=True,
                    output="Deployment updated successfully",
                    metadata={"resources_updated": ["deployment/test-app", "service/test-app"]}
                ),
                "prometheus.prometheus_query": MCPToolResult(
                    success=True,
                    output="Health check passed",
                    metadata={"result": [{"value": [1234567890, "1"]}]}  # up = 1
                ),
                "slack.send_notification": MCPToolResult(
                    success=True,
                    output="Notification sent",
                    metadata={"message_id": "msg123"}
                ),
                "s3.s3_upload_file": MCPToolResult(
                    success=True,
                    output="Artifacts uploaded",
                    metadata={"s3_url": "s3://deployments/test-app/1.0.0/"}
                )
            }

            # Configure mock to return appropriate responses
            def mock_tool_call(tool_name, params):
                return mock_responses.get(tool_name, MCPToolResult(success=False, output="Unknown tool"))

            mock_call.side_effect = mock_tool_call

            # STEP 1: Pre-deployment security scan
            print("🔍 Step 1: Security scanning source code...")
            scan_result = await mcp_manager.call_tool(
                "security-scanner.file_security_scan",
                {"directory": "./src", "patterns": ["*.py", "*.js", "*.yml"]}
            )
            assert scan_result.success
            pipeline_state["steps_completed"].append("source_security_scan")

            # STEP 2: Build Docker image
            print("🔨 Step 2: Building Docker image...")
            build_result = await mcp_manager.call_tool(
                "docker.docker_build",
                {
                    "dockerfile_path": deployment_config["dockerfile_path"],
                    "image_tag": f"{deployment_config['app_name']}:{deployment_config['version']}",
                    "build_args": {"VERSION": deployment_config["version"]}
                }
            )
            assert build_result.success
            pipeline_state["artifacts"]["docker_image"] = build_result.metadata["image_id"]
            pipeline_state["steps_completed"].append("docker_build")

            # STEP 3: Scan Docker image for vulnerabilities
            print("🛡️ Step 3: Scanning Docker image...")
            image_scan_result = await mcp_manager.call_tool(
                "security-scanner.docker_security_scan",
                {"image_name": f"{deployment_config['app_name']}:{deployment_config['version']}"}
            )
            assert image_scan_result.success
            vulnerabilities = image_scan_result.metadata["vulnerabilities"]
            
            # Check against thresholds
            assert vulnerabilities["critical"] <= deployment_config["security_threshold"]["critical"]
            assert vulnerabilities["high"] <= deployment_config["security_threshold"]["high"]
            pipeline_state["steps_completed"].append("docker_security_scan")

            # STEP 4: Run integration tests
            print("🧪 Step 4: Running integration tests...")
            test_container = await mcp_manager.call_tool(
                "docker.docker_run",
                {
                    "image": f"{deployment_config['app_name']}:{deployment_config['version']}",
                    "command": "pytest tests/integration",
                    "environment": {"ENV": "test"}
                }
            )
            assert test_container.success

            test_result = await mcp_manager.call_tool(
                "desktop-commander.execute_command",
                {"command": f"docker logs {test_container.metadata['container_id']}"}
            )
            assert test_result.success
            assert "passed" in test_result.output
            pipeline_state["steps_completed"].append("integration_tests")

            # STEP 5: Deploy to Kubernetes
            print("🚀 Step 5: Deploying to Kubernetes...")
            deploy_result = await mcp_manager.call_tool(
                "kubernetes.kubectl_apply",
                {
                    "manifest_path": deployment_config["k8s_manifests"],
                    "namespace": deployment_config["environment"]
                }
            )
            assert deploy_result.success
            pipeline_state["artifacts"]["k8s_resources"] = deploy_result.metadata["resources_updated"]
            pipeline_state["steps_completed"].append("kubernetes_deploy")

            # STEP 6: Health check verification
            print("❤️ Step 6: Verifying deployment health...")
            await asyncio.sleep(0.1)  # Simulate deployment time
            
            health_result = await mcp_manager.call_tool(
                "prometheus.prometheus_query",
                {
                    "query": f'up{{job="{deployment_config["app_name"]}",environment="{deployment_config["environment"]}"}}'
                }
            )
            assert health_result.success
            assert health_result.metadata["result"][0]["value"][1] == "1"  # up = 1
            pipeline_state["steps_completed"].append("health_check")

            # STEP 7: Upload artifacts to S3
            print("📦 Step 7: Archiving deployment artifacts...")
            artifact_result = await mcp_manager.call_tool(
                "s3.s3_upload_file",
                {
                    "file_path": f"/tmp/deployment-{deployment_config['version']}.tar.gz",
                    "bucket": "deployment-artifacts",
                    "key": f"{deployment_config['app_name']}/{deployment_config['version']}/deployment.tar.gz"
                }
            )
            assert artifact_result.success
            pipeline_state["artifacts"]["s3_backup"] = artifact_result.metadata["s3_url"]
            pipeline_state["steps_completed"].append("artifact_backup")

            # STEP 8: Send success notification
            print("📢 Step 8: Sending deployment notification...")
            notification_result = await mcp_manager.call_tool(
                "slack.send_notification",
                {
                    "channel": deployment_config["notifications"]["slack_channel"],
                    "message": f"✅ Successfully deployed {deployment_config['app_name']} v{deployment_config['version']} to {deployment_config['environment']}",
                    "level": "success",
                    "metadata": {
                        "duration": str(datetime.now() - pipeline_state["start_time"]),
                        "steps": len(pipeline_state["steps_completed"]),
                        "artifacts": list(pipeline_state["artifacts"].keys())
                    }
                }
            )
            assert notification_result.success
            pipeline_state["steps_completed"].append("notification_sent")

            # Verify complete pipeline execution
            assert len(pipeline_state["steps_completed"]) == 8
            assert len(pipeline_state["errors"]) == 0
            print(f"\n✅ Deployment pipeline completed successfully in {datetime.now() - pipeline_state['start_time']}")

    @pytest.mark.asyncio
    async def test_pipeline_with_rollback(self, mcp_manager, deployment_config):
        """Test deployment pipeline with rollback on failure."""
        with patch.object(mcp_manager, 'call_tool', new_callable=AsyncMock) as mock_call:
            # Setup mock responses with deployment failure
            mock_call.side_effect = [
                # Build succeeds
                MCPToolResult(success=True, output="Build successful", metadata={"image_id": "sha256:abc123"}),
                # Deploy fails
                MCPToolResult(success=False, output="Deployment failed: ImagePullBackOff", error="K8sError"),
                # Rollback operations
                MCPToolResult(success=True, output="Rolled back to previous version"),
                MCPToolResult(success=True, output="Rollback notification sent")
            ]

            # Execute pipeline with rollback
            try:
                # Build
                build_result = await mcp_manager.call_tool(
                    "docker.docker_build",
                    {"dockerfile_path": "./", "image_tag": "app:new"}
                )
                assert build_result.success

                # Deploy (will fail)
                deploy_result = await mcp_manager.call_tool(
                    "kubernetes.kubectl_apply",
                    {"manifest_path": "./k8s/"}
                )
                
                if not deploy_result.success:
                    # Initiate rollback
                    print("⚠️ Deployment failed, initiating rollback...")
                    
                    rollback_result = await mcp_manager.call_tool(
                        "kubernetes.kubectl_rollout",
                        {"action": "undo", "deployment": deployment_config["app_name"]}
                    )
                    assert rollback_result.success

                    # Notify about rollback
                    notify_result = await mcp_manager.call_tool(
                        "slack.send_notification",
                        {
                            "channel": "#incidents",
                            "message": f"🔄 Rolled back {deployment_config['app_name']} due to: {deploy_result.output}",
                            "level": "error"
                        }
                    )
                    assert notify_result.success

            except Exception as e:
                pytest.fail(f"Pipeline failed unexpectedly: {e}")

            # Verify rollback was executed
            assert mock_call.call_count == 4

    @pytest.mark.asyncio
    async def test_pipeline_with_expert_consultation(self, mcp_manager, expert_manager, deployment_config):
        """Test deployment pipeline with AI expert consultation."""
        with patch.object(mcp_manager, 'call_tool', new_callable=AsyncMock) as mock_mcp:
            with patch.object(expert_manager, 'consult_experts', new_callable=AsyncMock) as mock_consult:
                # Setup mock responses
                mock_mcp.return_value = MCPToolResult(
                    success=True,
                    output="Security scan complete",
                    metadata={"vulnerabilities": {"critical": 2, "high": 10}}
                )

                mock_consult.return_value = Response(
                    query_id="test123",
                    status=ResponseStatus.COMPLETE,
                    consensus="Block deployment due to critical vulnerabilities",
                    confidence_score=0.95,
                    expert_responses=[],
                    metadata={"recommendation": "fix_before_deploy"}
                )

                # Run security scan
                scan_result = await mcp_manager.call_tool(
                    "security-scanner.docker_security_scan",
                    {"image_name": "app:latest"}
                )

                # Consult experts about vulnerabilities
                if scan_result.metadata["vulnerabilities"]["critical"] > 0:
                    query = Query(
                        id="sec-review-123",
                        question=f"Should we deploy with {scan_result.metadata['vulnerabilities']['critical']} critical vulnerabilities?",
                        context={"scan_result": scan_result.metadata}
                    )
                    
                    expert_response = await expert_manager.consult_experts(query)
                    
                    # Make decision based on expert consensus
                    if "block" in expert_response.consensus.lower():
                        print("🛑 Deployment blocked based on expert recommendation")
                        deployment_proceed = False
                    else:
                        deployment_proceed = True

                # Verify expert consultation happened
                assert not deployment_proceed
                mock_consult.assert_called_once()

    @pytest.mark.asyncio
    async def test_multi_environment_progressive_deployment(self, mcp_manager):
        """Test progressive deployment across multiple environments."""
        environments = ["dev", "staging", "production"]
        deployment_results = {}

        with patch.object(mcp_manager, 'call_tool', new_callable=AsyncMock) as mock_call:
            # Setup mock responses for each environment
            mock_call.side_effect = [
                # Dev environment
                MCPToolResult(success=True, output="Dev: build success"),
                MCPToolResult(success=True, output="Dev: deploy success"),
                MCPToolResult(success=True, output="Dev: tests pass"),
                # Staging environment
                MCPToolResult(success=True, output="Staging: deploy success"),
                MCPToolResult(success=True, output="Staging: smoke tests pass"),
                MCPToolResult(success=True, output="Staging: performance good"),
                # Production environment
                MCPToolResult(success=True, output="Prod: canary deploy success"),
                MCPToolResult(success=True, output="Prod: canary metrics good"),
                MCPToolResult(success=True, output="Prod: full deploy success"),
            ]

            for env in environments:
                print(f"\n🌍 Deploying to {env}...")
                
                if env == "dev":
                    # Full build and test in dev
                    build = await mcp_manager.call_tool("docker.docker_build", {"image_tag": f"app:{env}"})
                    deploy = await mcp_manager.call_tool("kubernetes.kubectl_apply", {"namespace": env})
                    tests = await mcp_manager.call_tool("desktop-commander.execute_command", {"command": "make test"})
                    deployment_results[env] = all([build.success, deploy.success, tests.success])
                    
                elif env == "staging":
                    # Deploy and run integration tests
                    deploy = await mcp_manager.call_tool("kubernetes.kubectl_apply", {"namespace": env})
                    smoke = await mcp_manager.call_tool("desktop-commander.execute_command", {"command": "make smoke-test"})
                    perf = await mcp_manager.call_tool("prometheus.prometheus_query", {"query": "http_latency"})
                    deployment_results[env] = all([deploy.success, smoke.success, perf.success])
                    
                elif env == "production":
                    # Canary deployment first
                    canary = await mcp_manager.call_tool("kubernetes.kubectl_apply", {"manifest": "canary.yaml"})
                    canary_check = await mcp_manager.call_tool("prometheus.prometheus_query", {"query": "canary_errors"})
                    
                    if canary.success and canary_check.success:
                        # Full production rollout
                        full_deploy = await mcp_manager.call_tool("kubernetes.kubectl_apply", {"namespace": env})
                        deployment_results[env] = full_deploy.success
                    else:
                        deployment_results[env] = False

                # Stop if any environment fails
                if not deployment_results.get(env, False):
                    print(f"❌ Deployment failed in {env}, stopping pipeline")
                    break

            # Verify progressive deployment
            assert deployment_results["dev"]
            assert deployment_results["staging"]
            assert deployment_results.get("production", False)
            assert mock_call.call_count == 9  # All environments completed

    @pytest.mark.asyncio
    async def test_pipeline_with_performance_gates(self, mcp_manager):
        """Test deployment pipeline with performance gate checks."""
        performance_thresholds = {
            "response_time_p99": 500,  # ms
            "error_rate": 0.01,  # 1%
            "cpu_usage": 0.8,  # 80%
            "memory_usage": 0.9  # 90%
        }

        with patch.object(mcp_manager, 'call_tool', new_callable=AsyncMock) as mock_call:
            # Setup mock responses
            mock_call.side_effect = [
                # Deploy succeeds
                MCPToolResult(success=True, output="Deployed"),
                # Performance checks
                MCPToolResult(
                    success=True,
                    output="Response time query",
                    metadata={"result": [{"value": [1234567890, "450"]}]}  # 450ms - PASS
                ),
                MCPToolResult(
                    success=True,
                    output="Error rate query",
                    metadata={"result": [{"value": [1234567890, "0.005"]}]}  # 0.5% - PASS
                ),
                MCPToolResult(
                    success=True,
                    output="CPU usage query",
                    metadata={"result": [{"value": [1234567890, "0.75"]}]}  # 75% - PASS
                ),
                MCPToolResult(
                    success=True,
                    output="Memory usage query",
                    metadata={"result": [{"value": [1234567890, "0.95"]}]}  # 95% - FAIL
                ),
                # Rollback due to memory threshold breach
                MCPToolResult(success=True, output="Rolled back due to high memory usage")
            ]

            # Deploy
            deploy_result = await mcp_manager.call_tool(
                "kubernetes.kubectl_apply",
                {"manifest_path": "./k8s/"}
            )
            assert deploy_result.success

            # Check performance gates
            gates_passed = True
            failed_metrics = []

            # Response time check
            rt_result = await mcp_manager.call_tool(
                "prometheus.prometheus_query",
                {"query": "histogram_quantile(0.99, http_request_duration_seconds)"}
            )
            rt_value = float(rt_result.metadata["result"][0]["value"][1])
            if rt_value > performance_thresholds["response_time_p99"]:
                gates_passed = False
                failed_metrics.append(f"Response time: {rt_value}ms")

            # Error rate check
            err_result = await mcp_manager.call_tool(
                "prometheus.prometheus_query",
                {"query": "rate(http_requests_total{status=~'5..'}[5m])"}
            )
            err_value = float(err_result.metadata["result"][0]["value"][1])
            if err_value > performance_thresholds["error_rate"]:
                gates_passed = False
                failed_metrics.append(f"Error rate: {err_value*100}%")

            # CPU usage check
            cpu_result = await mcp_manager.call_tool(
                "prometheus.prometheus_query",
                {"query": "avg(rate(container_cpu_usage_seconds_total[5m]))"}
            )
            cpu_value = float(cpu_result.metadata["result"][0]["value"][1])
            if cpu_value > performance_thresholds["cpu_usage"]:
                gates_passed = False
                failed_metrics.append(f"CPU usage: {cpu_value*100}%")

            # Memory usage check
            mem_result = await mcp_manager.call_tool(
                "prometheus.prometheus_query",
                {"query": "avg(container_memory_usage_bytes / container_spec_memory_limit_bytes)"}
            )
            mem_value = float(mem_result.metadata["result"][0]["value"][1])
            if mem_value > performance_thresholds["memory_usage"]:
                gates_passed = False
                failed_metrics.append(f"Memory usage: {mem_value*100}%")

            # Rollback if gates failed
            if not gates_passed:
                print(f"⚠️ Performance gates failed: {', '.join(failed_metrics)}")
                rollback_result = await mcp_manager.call_tool(
                    "kubernetes.kubectl_rollout",
                    {"action": "undo", "deployment": "app"}
                )
                assert rollback_result.success

            # Verify performance gate failure and rollback
            assert not gates_passed
            assert "Memory usage: 95.0%" in failed_metrics
            assert mock_call.call_count == 6

    @pytest.mark.asyncio
    async def test_blue_green_deployment(self, mcp_manager):
        """Test blue-green deployment strategy."""
        with patch.object(mcp_manager, 'call_tool', new_callable=AsyncMock) as mock_call:
            # Setup mock responses
            mock_call.side_effect = [
                # Deploy to green environment
                MCPToolResult(success=True, output="Green deployment created"),
                # Health check green
                MCPToolResult(success=True, output="Green healthy", metadata={"healthy": True}),
                # Switch traffic to green
                MCPToolResult(success=True, output="Traffic switched to green"),
                # Verify traffic switch
                MCPToolResult(success=True, output="All traffic on green"),
                # Delete blue deployment
                MCPToolResult(success=True, output="Blue deployment removed")
            ]

            # Step 1: Deploy to green environment
            green_deploy = await mcp_manager.call_tool(
                "kubernetes.kubectl_apply",
                {
                    "manifest_path": "./k8s/green/",
                    "labels": {"version": "green", "app": "myapp"}
                }
            )
            assert green_deploy.success

            # Step 2: Health check green environment
            green_health = await mcp_manager.call_tool(
                "desktop-commander.execute_command",
                {"command": "curl -f http://myapp-green/health"}
            )
            assert green_health.success

            # Step 3: Switch traffic to green
            switch_result = await mcp_manager.call_tool(
                "kubernetes.kubectl_patch",
                {
                    "resource": "service/myapp",
                    "patch": {"spec": {"selector": {"version": "green"}}}
                }
            )
            assert switch_result.success

            # Step 4: Verify traffic switch
            verify_result = await mcp_manager.call_tool(
                "prometheus.prometheus_query",
                {"query": 'sum(rate(http_requests_total{version="green"}[1m]))'}
            )
            assert verify_result.success

            # Step 5: Remove blue deployment
            cleanup_result = await mcp_manager.call_tool(
                "kubernetes.kubectl_delete",
                {"resource": "deployment", "name": "myapp-blue"}
            )
            assert cleanup_result.success

            print("✅ Blue-green deployment completed successfully")
            assert mock_call.call_count == 5