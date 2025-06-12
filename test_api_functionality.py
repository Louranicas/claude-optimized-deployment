#!/usr/bin/env python3
"""
Comprehensive API functionality test script for Claude Optimized Deployment.

This script tests:
1. FastAPI setup and configuration
2. Circuit breaker API endpoints
3. Authentication middleware integration
4. Monitoring API endpoints
5. Error handling and validation
"""

import asyncio
import sys
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
import json

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.security import HTTPBearer
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

# Import project modules
from src.api.circuit_breaker_api import router as circuit_breaker_router, include_router
from src.auth.api import auth_router, get_auth_dependencies
from src.auth.middleware import AuthMiddleware
from src.monitoring.api import monitoring_router, health_check_middleware
from src.core.logging_config import setup_logging, get_logger
from src.core.circuit_breaker import get_circuit_breaker_manager, CircuitBreakerManager
from src.core.cors_config import get_fastapi_cors_config, Environment
from src.monitoring.health import get_health_checker
from src.monitoring.metrics import get_metrics_collector


class APITestApplication:
    """Test application for API functionality."""
    
    def __init__(self):
        self.app = FastAPI(
            title="Claude Optimized Deployment API Test",
            description="Testing API functionality and integration",
            version="1.0.0",
            docs_url="/docs",
            redoc_url="/redoc"
        )
        
        # Setup logging
        setup_logging(
            log_level="DEBUG",
            enable_console=True,
            structured=False
        )
        self.logger = get_logger(__name__)
        
        # Initialize components
        self._setup_middleware()
        self._setup_routes()
        self._setup_exception_handlers()
        
    def _setup_middleware(self):
        """Configure middleware."""
        # CORS middleware with secure configuration
        cors_config = get_fastapi_cors_config(Environment.TESTING)
        self.app.add_middleware(
            CORSMiddleware,
            **cors_config
        )
        
        # Request logging middleware
        @self.app.middleware("http")
        async def log_requests(request: Request, call_next):
            start_time = datetime.now()
            self.logger.debug(f"Request: {request.method} {request.url}")
            
            try:
                response = await call_next(request)
                duration = (datetime.now() - start_time).total_seconds()
                self.logger.info(
                    f"Response: {request.method} {request.url} "
                    f"- Status: {response.status_code} - Duration: {duration:.3f}s"
                )
                return response
            except Exception as e:
                duration = (datetime.now() - start_time).total_seconds()
                self.logger.error(
                    f"Error: {request.method} {request.url} "
                    f"- Error: {str(e)} - Duration: {duration:.3f}s"
                )
                raise
        
        # Add health check middleware (from monitoring module)
        self.app.middleware("http")(health_check_middleware)
        
    def _setup_routes(self):
        """Setup API routes."""
        # Root endpoint
        @self.app.get("/")
        async def root():
            return {
                "message": "Claude Optimized Deployment API Test",
                "timestamp": datetime.now().isoformat(),
                "endpoints": {
                    "docs": "/docs",
                    "redoc": "/redoc",
                    "health": "/health",
                    "circuit_breakers": "/api/circuit-breakers",
                    "monitoring": "/monitoring",
                    "auth": "/auth"
                }
            }
        
        # Include routers
        self.app.include_router(circuit_breaker_router)
        self.app.include_router(monitoring_router)
        self.app.include_router(auth_router)
        
        # Test endpoints
        @self.app.get("/test/error")
        async def test_error():
            """Test error handling."""
            raise HTTPException(status_code=500, detail="Test error")
        
        @self.app.get("/test/validation/{item_id}")
        async def test_validation(item_id: int, q: Optional[str] = None):
            """Test parameter validation."""
            return {"item_id": item_id, "query": q}
        
        @self.app.post("/test/json")
        async def test_json(data: Dict[str, Any]):
            """Test JSON parsing."""
            return {"received": data, "keys": list(data.keys())}
        
    def _setup_exception_handlers(self):
        """Setup custom exception handlers."""
        @self.app.exception_handler(ValueError)
        async def value_error_handler(request: Request, exc: ValueError):
            return JSONResponse(
                status_code=400,
                content={"detail": str(exc), "type": "validation_error"}
            )
        
        @self.app.exception_handler(Exception)
        async def general_exception_handler(request: Request, exc: Exception):
            self.logger.exception("Unhandled exception", exc_info=exc)
            return JSONResponse(
                status_code=500,
                content={"detail": "Internal server error", "type": "internal_error"}
            )


class APITester:
    """Test runner for API functionality."""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.logger = get_logger(__name__)
        
    async def test_endpoints(self):
        """Test various API endpoints."""
        import aiohttp
        
        tests = [
            ("GET", "/", None, 200),
            ("GET", "/docs", None, 200),
            ("GET", "/health", None, 200),
            ("GET", "/api/circuit-breakers/status", None, 200),
            ("GET", "/api/circuit-breakers/breakers", None, 200),
            ("GET", "/api/circuit-breakers/health", None, 200),
            ("GET", "/monitoring/health", None, 200),
            ("GET", "/monitoring/metrics", None, 200),
            ("GET", "/monitoring/health/live", None, 200),
            ("GET", "/monitoring/health/ready", None, 200),
            ("GET", "/auth/health", None, 200),
            ("GET", "/test/error", None, 500),
            ("GET", "/test/validation/123", None, 200),
            ("GET", "/test/validation/abc", None, 422),  # Invalid int
            ("POST", "/test/json", {"key": "value"}, 200),
        ]
        
        async with aiohttp.ClientSession() as session:
            for method, path, data, expected_status in tests:
                url = f"{self.base_url}{path}"
                
                try:
                    if method == "GET":
                        async with session.get(url) as response:
                            status = response.status
                            content = await response.text()
                    else:  # POST
                        async with session.post(url, json=data) as response:
                            status = response.status
                            content = await response.text()
                    
                    if status == expected_status:
                        self.logger.info(f"✓ {method} {path} - Status: {status}")
                    else:
                        self.logger.error(
                            f"✗ {method} {path} - Expected: {expected_status}, "
                            f"Got: {status}, Content: {content[:100]}"
                        )
                        
                except Exception as e:
                    self.logger.error(f"✗ {method} {path} - Error: {str(e)}")
    
    async def test_circuit_breaker_functionality(self):
        """Test circuit breaker specific functionality."""
        import aiohttp
        
        async with aiohttp.ClientSession() as session:
            # Test circuit breaker manager initialization
            cb_manager = get_circuit_breaker_manager()
            self.logger.info(f"Circuit breaker manager initialized: {cb_manager}")
            
            # Test creating a circuit breaker
            test_breaker = cb_manager.get_or_create("test_service")
            self.logger.info(f"Created test circuit breaker: {test_breaker.name}")
            
            # Test API endpoints
            endpoints = [
                "/api/circuit-breakers/status",
                "/api/circuit-breakers/breakers",
                "/api/circuit-breakers/breakers/test_service",
                "/api/circuit-breakers/health",
            ]
            
            for endpoint in endpoints:
                url = f"{self.base_url}{endpoint}"
                try:
                    async with session.get(url) as response:
                        if response.status == 200:
                            data = await response.json()
                            self.logger.info(f"✓ {endpoint} - Response: {json.dumps(data, indent=2)[:200]}...")
                        else:
                            self.logger.error(f"✗ {endpoint} - Status: {response.status}")
                except Exception as e:
                    self.logger.error(f"✗ {endpoint} - Error: {str(e)}")
            
            # Test circuit breaker state changes
            test_breaker.record_failure()
            test_breaker.record_failure()
            test_breaker.record_failure()
            test_breaker.record_failure()
            test_breaker.record_failure()
            
            # Check if breaker opened
            async with session.get(f"{self.base_url}/api/circuit-breakers/breakers/test_service") as response:
                if response.status == 200:
                    data = await response.json()
                    self.logger.info(f"Circuit breaker state after failures: {data['breaker']['state']}")
            
            # Test reset
            async with session.post(f"{self.base_url}/api/circuit-breakers/breakers/test_service/reset") as response:
                if response.status == 200:
                    data = await response.json()
                    self.logger.info(f"✓ Circuit breaker reset: {data['message']}")
    
    async def test_monitoring_integration(self):
        """Test monitoring integration."""
        import aiohttp
        
        async with aiohttp.ClientSession() as session:
            # Test health checker
            health_checker = get_health_checker()
            self.logger.info(f"Health checker initialized: {health_checker}")
            
            # Test metrics collector
            metrics_collector = get_metrics_collector()
            self.logger.info(f"Metrics collector initialized: {metrics_collector}")
            
            # Test monitoring endpoints
            endpoints = [
                ("/monitoring/health", "json"),
                ("/monitoring/health?detailed=true", "json"),
                ("/monitoring/metrics", "text"),
                ("/monitoring/sla/objectives", "json"),
                ("/monitoring/alerts", "json"),
                ("/monitoring/alerts/rules", "json"),
            ]
            
            for endpoint, content_type in endpoints:
                url = f"{self.base_url}{endpoint}"
                try:
                    async with session.get(url) as response:
                        if response.status == 200:
                            if content_type == "json":
                                data = await response.json()
                                self.logger.info(f"✓ {endpoint} - Response: {json.dumps(data, indent=2)[:200]}...")
                            else:
                                data = await response.text()
                                self.logger.info(f"✓ {endpoint} - Metrics data received ({len(data)} bytes)")
                        else:
                            self.logger.error(f"✗ {endpoint} - Status: {response.status}")
                except Exception as e:
                    self.logger.error(f"✗ {endpoint} - Error: {str(e)}")


async def run_tests():
    """Run all API tests."""
    logger = get_logger(__name__)
    
    # Create test application
    app_tester = APITestApplication()
    
    # Start server in background
    config = uvicorn.Config(
        app_tester.app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
    server = uvicorn.Server(config)
    
    # Run server in background task
    server_task = asyncio.create_task(server.serve())
    
    # Wait for server to start
    await asyncio.sleep(2)
    
    # Run tests
    tester = APITester()
    
    logger.info("=" * 60)
    logger.info("Testing API Endpoints")
    logger.info("=" * 60)
    await tester.test_endpoints()
    
    logger.info("\n" + "=" * 60)
    logger.info("Testing Circuit Breaker Functionality")
    logger.info("=" * 60)
    await tester.test_circuit_breaker_functionality()
    
    logger.info("\n" + "=" * 60)
    logger.info("Testing Monitoring Integration")
    logger.info("=" * 60)
    await tester.test_monitoring_integration()
    
    # Shutdown server
    server.should_exit = True
    await server_task


def main():
    """Main entry point."""
    print("\n🚀 Claude Optimized Deployment - API Functionality Test\n")
    
    try:
        # Run async tests
        asyncio.run(run_tests())
        
        print("\n✅ API functionality tests completed!")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Tests interrupted by user")
    except Exception as e:
        print(f"\n❌ Test failed with error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()