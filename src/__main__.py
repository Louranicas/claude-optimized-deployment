"""
Main entry point for Claude-Optimized Deployment Engine.

This module initializes logging and provides the main application entry point.
"""

import os
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.core.logging_config import setup_logging, get_logger


def initialize_application():
    """Initialize the application with proper logging configuration."""
    # Setup logging based on environment
    environment = os.getenv("ENVIRONMENT", "development")
    log_level = os.getenv("LOG_LEVEL", None)
    
    # Configure log directory
    log_dir = Path("logs")
    if environment == "production":
        log_dir = Path("/var/log/claude-optimized-deployment")
    
    # Initialize logging
    setup_logging(
        log_level=log_level,
        log_dir=log_dir,
        enable_rotation=True,
        structured=(environment != "development"),  # Use structured logs in production
        enable_console=True,
        enable_file=(environment != "test")
    )
    
    logger = get_logger(__name__)
    logger.info(
        "Application initialized",
        extra={
            "structured_data": {
                "environment": environment,
                "python_version": sys.version,
                "project_root": str(project_root)
            }
        }
    )
    
    return logger


def main():
    """Main application entry point."""
    logger = initialize_application()
    
    try:
        # Import application components after logging is configured
        from src.mcp.manager import MCPManager
        from src.circle_of_experts.core.expert_manager import ExpertManager
        
        logger.info("Starting Claude-Optimized Deployment Engine")
        
        # Application startup logic here
        # This is a placeholder - actual implementation would start services
        
    except Exception as e:
        logger.exception("Application startup failed", exc_info=e)
        sys.exit(1)


if __name__ == "__main__":
    main()