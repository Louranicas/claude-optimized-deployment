"""
Official Python Client for Claude-Optimized Deployment Engine (CODE) API

A comprehensive, production-ready Python client with async support, 
automatic retry logic, rate limiting, and error handling.

Installation:
    pip install aiohttp pydantic

Usage:
    async with CODEClient("http://localhost:8000", api_key="your-key") as client:
        result = await client.mcp.execute("docker", "docker_ps", {})
        print(result)
"""

import asyncio
import aiohttp
import json
import time
import logging
from typing import Dict, Any, List, Optional, Union, AsyncGenerator
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
import hmac

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EventType(Enum):
    """Webhook event types."""
    DEPLOYMENT_STARTED = "deployment.started"
    DEPLOYMENT_COMPLETED = "deployment.completed"
    DEPLOYMENT_FAILED = "deployment.failed"
    SECURITY_VULNERABILITY_FOUND = "security.vulnerability_found"
    CIRCUIT_BREAKER_OPENED = "circuit_breaker.opened"
    ALERT_TRIGGERED = "alert.triggered"


@dataclass
class DeploymentConfig:
    """Deployment configuration."""
    application_name: str
    environment: str
    deployment_type: str
    source: Dict[str, Any]
    configuration: Optional[Dict[str, Any]] = None
    pre_deployment_checks: Optional[List[str]] = None
    notifications: Optional[Dict[str, Any]] = None


@dataclass
class WebhookConfig:
    """Webhook configuration."""
    url: str
    events: List[str]
    secret: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    retry_policy: Optional[Dict[str, Any]] = None


class CODEError(Exception):
    """Base exception for CODE API errors."""
    
    def __init__(self, message: str, status_code: int = None, response_data: Dict = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_data = response_data or {}


class RateLimitError(CODEError):
    """Rate limit exceeded error."""
    
    def __init__(self, retry_after: int, message: str = "Rate limit exceeded"):
        super().__init__(message, 429)
        self.retry_after = retry_after


class RateLimitHandler:
    """Handle rate limiting with exponential backoff."""
    
    def __init__(self, base_delay: float = 1.0, max_delay: float = 60.0):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.current_delay = base_delay
        self.request_times = []
    
    def reset_delay(self):
        """Reset delay after successful request."""
        self.current_delay = self.base_delay
    
    def increase_delay(self):
        """Increase delay for next retry."""
        self.current_delay = min(self.current_delay * 2, self.max_delay)
    
    def should_wait(self, requests_per_minute: int = 100) -> int:
        """Check if we should wait due to rate limiting."""
        now = time.time()
        self.request_times = [t for t in self.request_times if now - t < 60]
        
        if len(self.request_times) >= requests_per_minute:
            return 60 - (now - self.request_times[0])
        
        return 0
    
    def record_request(self):
        """Record a request for rate limiting."""
        self.request_times.append(time.time())


class CircuitBreakersAPI:
    """Circuit breaker management API."""
    
    def __init__(self, client):
        self._client = client
    
    async def get_status(self) -> Dict[str, Any]:
        """Get overall circuit breaker system status."""
        return await self._client._request('GET', '/api/circuit-breakers/status')
    
    async def list_all(self, state: Optional[str] = None) -> Dict[str, Any]:
        """List all circuit breakers with optional state filtering."""
        params = {}
        if state:
            params['state'] = state
        return await self._client._request('GET', '/api/circuit-breakers/breakers', params=params)
    
    async def get(self, breaker_name: str) -> Dict[str, Any]:
        """Get specific circuit breaker details."""
        return await self._client._request('GET', f'/api/circuit-breakers/breakers/{breaker_name}')
    
    async def reset(self, breaker_name: str) -> Dict[str, Any]:
        """Reset specific circuit breaker."""
        return await self._client._request('POST', f'/api/circuit-breakers/breakers/{breaker_name}/reset')
    
    async def reset_all(self) -> Dict[str, Any]:
        """Reset all circuit breakers."""
        return await self._client._request('POST', '/api/circuit-breakers/breakers/reset-all')
    
    async def get_health(self) -> Dict[str, Any]:
        """Get system health based on circuit breaker states."""
        return await self._client._request('GET', '/api/circuit-breakers/health')
    
    async def get_alerts(self, limit: int = 10) -> Dict[str, Any]:
        """Get recent circuit breaker alerts."""
        return await self._client._request('GET', '/api/circuit-breakers/alerts', params={'limit': limit})
    
    async def start_monitoring(self, **config) -> Dict[str, Any]:
        """Start circuit breaker monitoring."""
        return await self._client._request('POST', '/api/circuit-breakers/monitoring/start', params=config)
    
    async def stop_monitoring(self) -> Dict[str, Any]:
        """Stop circuit breaker monitoring."""
        return await self._client._request('POST', '/api/circuit-breakers/monitoring/stop')


class MCPAPI:
    """MCP (Model Context Protocol) tools API."""
    
    def __init__(self, client):
        self._client = client
    
    async def list_servers(self) -> Dict[str, Any]:
        """List all available MCP servers."""
        return await self._client._request('GET', '/api/mcp/servers')
    
    async def get_server_tools(self, server_name: str) -> Dict[str, Any]:
        """Get tools available from a specific server."""
        return await self._client._request('GET', f'/api/mcp/servers/{server_name}/tools')
    
    async def execute(self, server: str, tool: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute an MCP tool."""
        payload = {
            'server': server,
            'tool': tool,
            'arguments': arguments
        }
        return await self._client._request('POST', '/api/mcp/execute', json=payload)
    
    # Convenience methods for common operations
    async def docker_build(self, dockerfile_path: str, image_tag: str, **kwargs) -> Dict[str, Any]:
        """Build Docker image."""
        arguments = {
            'dockerfile_path': dockerfile_path,
            'image_tag': image_tag,
            **kwargs
        }
        return await self.execute('docker', 'docker_build', arguments)
    
    async def docker_run(self, image: str, container_name: str = None, **kwargs) -> Dict[str, Any]:
        """Run Docker container."""
        arguments = {
            'image': image,
            **kwargs
        }
        if container_name:
            arguments['container_name'] = container_name
        return await self.execute('docker', 'docker_run', arguments)
    
    async def docker_ps(self, all_containers: bool = False, **kwargs) -> Dict[str, Any]:
        """List Docker containers."""
        arguments = {
            'all': all_containers,
            **kwargs
        }
        return await self.execute('docker', 'docker_ps', arguments)
    
    async def kubectl_apply(self, manifest_path: str, namespace: str = None, **kwargs) -> Dict[str, Any]:
        """Apply Kubernetes manifests."""
        arguments = {
            'manifest_path': manifest_path,
            **kwargs
        }
        if namespace:
            arguments['namespace'] = namespace
        return await self.execute('kubernetes', 'kubectl_apply', arguments)
    
    async def kubectl_get(self, resource: str, name: str = None, namespace: str = None, **kwargs) -> Dict[str, Any]:
        """Get Kubernetes resources."""
        arguments = {
            'resource': resource,
            **kwargs
        }
        if name:
            arguments['name'] = name
        if namespace:
            arguments['namespace'] = namespace
        return await self.execute('kubernetes', 'kubectl_get', arguments)
    
    async def security_scan_npm(self, package_json_path: str, **kwargs) -> Dict[str, Any]:
        """Run NPM security audit."""
        arguments = {
            'package_json_path': package_json_path,
            **kwargs
        }
        return await self.execute('security-scanner', 'npm_audit', arguments)
    
    async def security_scan_docker(self, image_name: str, **kwargs) -> Dict[str, Any]:
        """Run Docker security scan."""
        arguments = {
            'image_name': image_name,
            **kwargs
        }
        return await self.execute('security-scanner', 'docker_security_scan', arguments)
    
    async def slack_notify(self, channel: str, message: str, **kwargs) -> Dict[str, Any]:
        """Send Slack notification."""
        arguments = {
            'channel': channel,
            'message': message,
            **kwargs
        }
        return await self.execute('slack-notifications', 'send_notification', arguments)
    
    async def prometheus_query(self, query: str, **kwargs) -> Dict[str, Any]:
        """Execute Prometheus query."""
        arguments = {
            'query': query,
            **kwargs
        }
        return await self.execute('prometheus-monitoring', 'prometheus_query', arguments)
    
    async def s3_upload(self, local_path: str, bucket: str, key: str, **kwargs) -> Dict[str, Any]:
        """Upload file to S3."""
        arguments = {
            'local_path': local_path,
            'bucket': bucket,
            'key': key,
            **kwargs
        }
        return await self.execute('s3-storage', 's3_upload_file', arguments)


class ExpertsAPI:
    """AI expert consultation API."""
    
    def __init__(self, client):
        self._client = client
    
    async def consult(self, query: str, expert_types: List[str] = None, **kwargs) -> Dict[str, Any]:
        """Consult AI experts."""
        payload = {
            'query': query,
            **kwargs
        }
        if expert_types:
            payload['expert_types'] = expert_types
        return await self._client._request('POST', '/api/experts/consult', json=payload)
    
    async def get_health(self) -> Dict[str, Any]:
        """Get expert availability status."""
        return await self._client._request('GET', '/api/experts/health')


class DeploymentsAPI:
    """Deployment management API."""
    
    def __init__(self, client):
        self._client = client
    
    async def create(self, config: Union[DeploymentConfig, Dict[str, Any]]) -> Dict[str, Any]:
        """Create a new deployment."""
        if isinstance(config, DeploymentConfig):
            payload = asdict(config)
        else:
            payload = config
        return await self._client._request('POST', '/api/deployments', json=payload)
    
    async def get(self, deployment_id: str) -> Dict[str, Any]:
        """Get deployment status and details."""
        return await self._client._request('GET', f'/api/deployments/{deployment_id}')
    
    async def get_logs(self, deployment_id: str, follow: bool = False, tail: int = 100) -> Union[str, AsyncGenerator[str, None]]:
        """Get deployment logs."""
        params = {'follow': follow, 'tail': tail}
        
        if follow:
            # Return async generator for streaming logs
            return self._stream_logs(deployment_id, params)
        else:
            response = await self._client._request('GET', f'/api/deployments/{deployment_id}/logs', params=params)
            return response
    
    async def _stream_logs(self, deployment_id: str, params: Dict) -> AsyncGenerator[str, None]:
        """Stream deployment logs."""
        url = f"{self._client.base_url}/api/deployments/{deployment_id}/logs"
        headers = self._client._get_headers()
        
        async with self._client.session.get(url, headers=headers, params=params) as response:
            async for line in response.content:
                yield line.decode('utf-8')


class SecurityAPI:
    """Security scanning and management API."""
    
    def __init__(self, client):
        self._client = client
    
    async def scan(self, scan_config: Dict[str, Any]) -> Dict[str, Any]:
        """Run security scan."""
        return await self._client._request('POST', '/api/security/scan', json=scan_config)
    
    async def list_vulnerabilities(self, severity: str = None, fixed: bool = None) -> Dict[str, Any]:
        """List known vulnerabilities."""
        params = {}
        if severity:
            params['severity'] = severity
        if fixed is not None:
            params['fixed'] = fixed
        return await self._client._request('GET', '/api/security/vulnerabilities', params=params)


class MonitoringAPI:
    """System monitoring and metrics API."""
    
    def __init__(self, client):
        self._client = client
    
    async def get_metrics(self, metric_names: List[str] = None) -> Dict[str, Any]:
        """Get system metrics."""
        params = {}
        if metric_names:
            params['metric_names'] = ','.join(metric_names)
        return await self._client._request('GET', '/api/monitoring/metrics', params=params)
    
    async def get_alerts(self, severity: str = None, acknowledged: bool = None) -> Dict[str, Any]:
        """Get active alerts."""
        params = {}
        if severity:
            params['severity'] = severity
        if acknowledged is not None:
            params['acknowledged'] = acknowledged
        return await self._client._request('GET', '/api/monitoring/alerts', params=params)


class WebhooksAPI:
    """Webhook management API."""
    
    def __init__(self, client):
        self._client = client
    
    async def register(self, config: Union[WebhookConfig, Dict[str, Any]]) -> Dict[str, Any]:
        """Register a new webhook."""
        if isinstance(config, WebhookConfig):
            payload = asdict(config)
        else:
            payload = config
        return await self._client._request('POST', '/api/webhooks', json=payload)
    
    async def list(self) -> Dict[str, Any]:
        """List registered webhooks."""
        return await self._client._request('GET', '/api/webhooks')
    
    async def update(self, webhook_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Update webhook configuration."""
        return await self._client._request('PUT', f'/api/webhooks/{webhook_id}', json=config)
    
    async def delete(self, webhook_id: str) -> bool:
        """Delete a webhook."""
        await self._client._request('DELETE', f'/api/webhooks/{webhook_id}')
        return True
    
    @staticmethod
    def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
        """Verify webhook signature."""
        expected = hmac.new(
            secret.encode('utf-8'),
            payload,
            hashlib.sha256
        ).hexdigest()
        
        actual = signature.replace('sha256=', '') if signature.startswith('sha256=') else signature
        return hmac.compare_digest(expected, actual)


class CODEClient:
    """
    Comprehensive Python client for the CODE API.
    
    Features:
    - Async/await support
    - Automatic retry with exponential backoff
    - Rate limiting handling
    - Comprehensive error handling
    - Type hints and dataclasses
    - Logging integration
    
    Example:
        async with CODEClient("http://localhost:8000", "your-api-key") as client:
            # Get system health
            health = await client.circuit_breakers.get_health()
            
            # Execute MCP tools
            containers = await client.mcp.docker_ps()
            
            # Deploy application
            deployment = await client.deployments.create({
                "application_name": "my-app",
                "environment": "production",
                "deployment_type": "kubernetes",
                "source": {
                    "type": "git",
                    "repository": "https://github.com/me/my-app.git"
                }
            })
    """
    
    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_key: str = None,
        timeout: int = 30,
        max_retries: int = 3,
        retry_backoff: float = 1.0
    ):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_retries = max_retries
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Rate limiting
        self.rate_limiter = RateLimitHandler(base_delay=retry_backoff)
        
        # API sections
        self.circuit_breakers = CircuitBreakersAPI(self)
        self.mcp = MCPAPI(self)
        self.experts = ExpertsAPI(self)
        self.deployments = DeploymentsAPI(self)
        self.security = SecurityAPI(self)
        self.monitoring = MonitoringAPI(self)
        self.webhooks = WebhooksAPI(self)
    
    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession(timeout=self.timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    def _get_headers(self) -> Dict[str, str]:
        """Get request headers."""
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'CODE-Python-Client/1.0.0'
        }
        
        if self.api_key:
            headers['X-API-Key'] = self.api_key
        
        return headers
    
    async def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict] = None,
        json: Optional[Dict] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Make HTTP request with retry logic and rate limiting."""
        if not self.session:
            raise RuntimeError("Client not initialized. Use 'async with' statement.")
        
        url = f"{self.base_url}{path}"
        headers = self._get_headers()
        
        # Check rate limiting
        wait_time = self.rate_limiter.should_wait()
        if wait_time > 0:
            logger.info(f"Rate limiting: waiting {wait_time:.1f}s")
            await asyncio.sleep(wait_time)
        
        for attempt in range(self.max_retries + 1):
            try:
                self.rate_limiter.record_request()
                
                async with self.session.request(
                    method, url, headers=headers, params=params, json=json, **kwargs
                ) as response:
                    # Process rate limit headers
                    remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
                    reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
                    
                    if response.status == 200 or response.status == 201:
                        self.rate_limiter.reset_delay()
                        if response.content_type == 'application/json':
                            return await response.json()
                        else:
                            return await response.text()
                    
                    elif response.status == 429:
                        # Rate limit exceeded
                        retry_after = int(response.headers.get('Retry-After', self.rate_limiter.current_delay))
                        
                        if attempt < self.max_retries:
                            logger.warning(f"Rate limited. Retrying in {retry_after}s (attempt {attempt + 1})")
                            await asyncio.sleep(retry_after)
                            self.rate_limiter.increase_delay()
                            continue
                        else:
                            error_data = await response.json() if response.content_type == 'application/json' else {}
                            raise RateLimitError(retry_after, f"Rate limit exceeded after {self.max_retries} retries")
                    
                    elif response.status == 503:
                        # Service unavailable
                        retry_after = int(response.headers.get('Retry-After', 60))
                        
                        if attempt < self.max_retries:
                            logger.warning(f"Service unavailable. Retrying in {retry_after}s (attempt {attempt + 1})")
                            await asyncio.sleep(retry_after)
                            continue
                        else:
                            error_data = await response.json() if response.content_type == 'application/json' else {}
                            raise CODEError("Service unavailable after retries", response.status, error_data)
                    
                    else:
                        # Other HTTP errors
                        error_data = await response.json() if response.content_type == 'application/json' else {}
                        error_msg = error_data.get('error', {}).get('message', f'HTTP {response.status}')
                        raise CODEError(error_msg, response.status, error_data)
            
            except aiohttp.ClientError as e:
                if attempt < self.max_retries:
                    delay = self.rate_limiter.current_delay
                    logger.warning(f"Request failed: {e}. Retrying in {delay}s (attempt {attempt + 1})")
                    await asyncio.sleep(delay)
                    self.rate_limiter.increase_delay()
                    continue
                else:
                    raise CODEError(f"Request failed after {self.max_retries} retries: {e}")
    
    async def health_check(self) -> Dict[str, Any]:
        """Check API health."""
        return await self._request('GET', '/health')
    
    # Convenience methods for common workflows
    async def deploy_application(
        self,
        app_name: str,
        environment: str,
        source: Dict[str, Any],
        **kwargs
    ) -> Dict[str, Any]:
        """Deploy application with pre-checks."""
        config = DeploymentConfig(
            application_name=app_name,
            environment=environment,
            deployment_type="kubernetes",
            source=source,
            **kwargs
        )
        return await self.deployments.create(config)
    
    async def build_and_deploy(
        self,
        dockerfile_path: str,
        image_tag: str,
        k8s_manifest_path: str,
        namespace: str = "default"
    ) -> Dict[str, Any]:
        """Complete build and deploy workflow."""
        # Build Docker image
        logger.info(f"Building Docker image: {image_tag}")
        build_result = await self.mcp.docker_build(dockerfile_path, image_tag)
        
        if not build_result.get('success'):
            raise CODEError(f"Docker build failed: {build_result.get('error')}")
        
        # Deploy to Kubernetes
        logger.info(f"Deploying to Kubernetes namespace: {namespace}")
        deploy_result = await self.mcp.kubectl_apply(k8s_manifest_path, namespace=namespace)
        
        if not deploy_result.get('success'):
            raise CODEError(f"Kubernetes deployment failed: {deploy_result.get('error')}")
        
        return {
            'build_result': build_result,
            'deploy_result': deploy_result,
            'image_tag': image_tag,
            'namespace': namespace
        }
    
    async def security_audit(self, project_path: str = ".") -> Dict[str, Any]:
        """Run comprehensive security audit."""
        results = {}
        
        # NPM audit if package.json exists
        try:
            npm_result = await self.mcp.security_scan_npm(f"{project_path}/package.json")
            results['npm_audit'] = npm_result
        except CODEError:
            logger.info("No package.json found, skipping NPM audit")
        
        # Python safety check if requirements.txt exists
        try:
            python_result = await self.mcp.execute(
                'security-scanner', 
                'python_safety_check',
                {'requirements_path': f"{project_path}/requirements.txt"}
            )
            results['python_safety'] = python_result
        except CODEError:
            logger.info("No requirements.txt found, skipping Python safety check")
        
        # File security scan
        try:
            file_result = await self.mcp.execute(
                'security-scanner',
                'file_security_scan',
                {'file_path': project_path, 'recursive': True}
            )
            results['file_scan'] = file_result
        except CODEError:
            logger.warning("File security scan failed")
        
        return results


# Example usage and workflow functions
async def example_basic_usage():
    """Example of basic API usage."""
    async with CODEClient("http://localhost:8000", "your-api-key") as client:
        # Check system health
        health = await client.circuit_breakers.get_health()
        print(f"System health: {health['health']}")
        
        # List Docker containers
        containers = await client.mcp.docker_ps()
        print(f"Running containers: {len(containers['result']['containers'])}")
        
        # Get system metrics
        metrics = await client.monitoring.get_metrics(['cpu_usage', 'memory_usage'])
        print(f"Current metrics: {metrics}")


async def example_deployment_workflow():
    """Example of complete deployment workflow."""
    async with CODEClient("http://localhost:8000", "your-api-key") as client:
        try:
            # Security audit first
            print("🔍 Running security audit...")
            audit_results = await client.security_audit(".")
            
            # Check for critical vulnerabilities
            critical_issues = sum(
                result.get('result', {}).get('vulnerabilities', {}).get('critical', 0)
                for result in audit_results.values()
                if result.get('success')
            )
            
            if critical_issues > 0:
                print(f"❌ Found {critical_issues} critical security issues. Aborting deployment.")
                return
            
            # Build and deploy
            print("🏗️ Building and deploying...")
            result = await client.build_and_deploy(
                dockerfile_path=".",
                image_tag="my-app:latest",
                k8s_manifest_path="./k8s/",
                namespace="production"
            )
            
            # Send notification
            await client.mcp.slack_notify(
                channel="#deployments",
                message=f"🚀 Deployment completed: {result['image_tag']}",
                severity="success"
            )
            
            print("✅ Deployment completed successfully!")
            
        except CODEError as e:
            print(f"❌ Deployment failed: {e}")
            
            # Send failure notification
            await client.mcp.slack_notify(
                channel="#alerts",
                message=f"❌ Deployment failed: {e}",
                severity="error"
            )


async def example_monitoring_setup():
    """Example of setting up monitoring and webhooks."""
    async with CODEClient("http://localhost:8000", "your-api-key") as client:
        # Register webhook for deployment events
        webhook_config = WebhookConfig(
            url="https://your-app.com/webhooks/code",
            events=[
                EventType.DEPLOYMENT_COMPLETED.value,
                EventType.DEPLOYMENT_FAILED.value,
                EventType.SECURITY_VULNERABILITY_FOUND.value
            ],
            secret="your-webhook-secret"
        )
        
        webhook = await client.webhooks.register(webhook_config)
        print(f"Webhook registered: {webhook['webhook_id']}")
        
        # Start circuit breaker monitoring
        await client.circuit_breakers.start_monitoring(
            check_interval=10,
            alert_on_open=True,
            alert_on_half_open=True
        )
        
        print("Monitoring started successfully!")


if __name__ == "__main__":
    # Run examples
    asyncio.run(example_basic_usage())
    # asyncio.run(example_deployment_workflow())
    # asyncio.run(example_monitoring_setup())