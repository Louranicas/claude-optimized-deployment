"""
Main FastAPI Application

This module defines the main FastAPI application with all middleware,
routes, and services including the distributed rate limiting system.
"""

import os
import logging
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exception_handlers import http_exception_handler

from .core.rate_limit_init import initialize_rate_limiting_for_app
from .core.rate_limit_middleware import RateLimitMiddleware
from .core.cors_config import get_cors_config
from .auth.api import auth_router, initialize_auth_services
from .auth.startup import initialize_authentication
from .api.circuit_breaker_api import router as circuit_breaker_router
from .api.rate_limiting_api import rate_limit_router
from .monitoring.api import monitoring_router

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    logger.info("Starting up application...")
    
    try:
        # Initialize authentication services
        await initialize_auth_services()
        logger.info("Authentication services initialized")
        
        # Initialize rate limiting
        environment = os.getenv('ENVIRONMENT', 'development')
        enable_monitoring = environment == 'production'
        
        await initialize_rate_limiting_for_app(
            app=app,
            environment=environment,
            enable_monitoring=enable_monitoring
        )
        logger.info("Rate limiting system initialized")
        
        # Initialize authentication middleware
        await initialize_authentication(app)
        logger.info("Authentication middleware initialized")
        
        logger.info("Application startup complete")
        
    except Exception as e:
        logger.exception(f"Failed to initialize application: {e}")
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down application...")
    
    try:
        # Shutdown will be handled by the rate limiting system's shutdown handler
        logger.info("Application shutdown complete")
        
    except Exception as e:
        logger.exception(f"Error during application shutdown: {e}")


# Create FastAPI application
app = FastAPI(
    title="Claude-Optimized Deployment Engine",
    description="High-performance AI deployment system with distributed rate limiting",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure CORS
cors_config = get_cors_config()
app.add_middleware(
    CORSMiddleware,
    **cors_config.get_fastapi_config()
)

# Add routers
app.include_router(auth_router)
app.include_router(circuit_breaker_router)
app.include_router(rate_limit_router)
app.include_router(monitoring_router)


# Global exception handlers
@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    """Custom HTTP exception handler that includes rate limiting info."""
    # Add rate limiting headers if this is a 429 error
    if exc.status_code == 429:
        headers = getattr(exc, 'headers', {})
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.detail,
            headers=headers
        )
    
    # Use default handler for other HTTP exceptions
    return await http_exception_handler(request, exc)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler for unhandled exceptions."""
    logger.exception("Unhandled exception occurred", exc_info=exc)
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal server error",
            "detail": "An unexpected error occurred"
        }
    )


# Health check endpoints
@app.get("/health")
async def health_check():
    """Application health check."""
    from .core.rate_limit_init import get_rate_limiting_setup
    
    try:
        # Check rate limiting system health
        setup = get_rate_limiting_setup()
        rate_limit_health = await setup.health_check()
        
        # Overall health status
        all_healthy = (
            rate_limit_health.get("status") in ["healthy", "degraded"]
        )
        
        return {
            "status": "healthy" if all_healthy else "unhealthy",
            "timestamp": "2025-01-13T22:47:19Z",  # Current timestamp would be used in production
            "services": {
                "rate_limiting": rate_limit_health,
                "authentication": {"status": "healthy"},  # Would check auth services
                "database": {"status": "healthy"},  # Would check DB
                "redis": {"status": rate_limit_health.get("redis_connected", False)}
            }
        }
        
    except Exception as e:
        logger.exception("Health check failed")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "unhealthy",
                "timestamp": "2025-01-13T22:47:19Z",
                "error": str(e)
            }
        )


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "Claude-Optimized Deployment Engine",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health"
    }


# Example protected endpoints to demonstrate rate limiting
@app.get("/api/test")
async def test_endpoint():
    """Test endpoint for rate limiting demonstration."""
    return {
        "message": "This endpoint is rate limited",
        "timestamp": "2025-01-13T22:47:19Z"
    }


@app.post("/api/heavy-operation")
async def heavy_operation_endpoint():
    """Simulated heavy operation endpoint with strict rate limits."""
    import asyncio
    
    # Simulate processing time
    await asyncio.sleep(0.1)
    
    return {
        "message": "Heavy operation completed",
        "processing_time": "0.1s"
    }


@app.get("/api/public")
async def public_endpoint():
    """Public endpoint with lenient rate limits."""
    return {
        "message": "This is a public endpoint",
        "access": "unlimited"
    }


# Middleware setup function for external use
async def setup_app_middleware(
    app: FastAPI,
    environment: str = None,
    enable_rate_limiting: bool = True,
    enable_monitoring: bool = True
):
    """
    Setup middleware for the FastAPI application.
    
    This function can be used to configure the application
    programmatically from other modules.
    """
    environment = environment or os.getenv('ENVIRONMENT', 'development')
    
    if enable_rate_limiting:
        await initialize_rate_limiting_for_app(
            app=app,
            environment=environment,
            enable_monitoring=enable_monitoring
        )
        logger.info(f"Rate limiting configured for {environment} environment")
    
    # Add other middleware as needed
    logger.info("Application middleware setup complete")


# Configuration for different environments
def get_app_config() -> Dict[str, Any]:
    """Get application configuration based on environment."""
    environment = os.getenv('ENVIRONMENT', 'development')
    
    base_config = {
        "debug": environment == "development",
        "testing": environment == "testing",
        "docs_url": "/docs" if environment != "production" else None,
        "redoc_url": "/redoc" if environment != "production" else None,
    }
    
    if environment == "production":
        base_config.update({
            "debug": False,
            "docs_url": None,
            "redoc_url": None,
        })
    elif environment == "testing":
        base_config.update({
            "debug": True,
            "testing": True,
        })
    
    return base_config


if __name__ == "__main__":
    import uvicorn
    
    # Get configuration
    config = get_app_config()
    environment = os.getenv('ENVIRONMENT', 'development')
    
    # Configure uvicorn
    uvicorn_config = {
        "host": "0.0.0.0",
        "port": int(os.getenv('PORT', 8000)),
        "reload": environment == "development",
        "log_level": "info",
        "access_log": True,
    }
    
    if environment == "production":
        uvicorn_config.update({
            "workers": int(os.getenv('WORKERS', 4)),
            "reload": False,
        })
    
    logger.info(f"Starting server in {environment} mode")
    uvicorn.run("src.app:app", **uvicorn_config)