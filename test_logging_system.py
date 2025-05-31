#!/usr/bin/env python3
"""
Test script to verify the comprehensive logging system.

Run this to ensure all logging components are working correctly.
"""

import asyncio
import json
import time
from pathlib import Path

from src.core.logging_config import (
    setup_logging,
    get_logger,
    get_performance_logger,
    get_security_logger,
    correlation_context,
    performance_logged,
    mcp_logger,
    ai_logger,
    infra_logger,
    log_with_context
)


@performance_logged("test_operation")
def slow_operation():
    """Simulate a slow operation."""
    time.sleep(0.1)
    return "completed"


async def test_logging_system():
    """Test all logging functionality."""
    # Setup logging
    setup_logging(
        log_level="DEBUG",
        log_dir=Path("test_logs"),
        enable_rotation=True,
        structured=True
    )
    
    logger = get_logger(__name__)
    perf_logger = get_performance_logger(__name__)
    security_logger = get_security_logger(__name__)
    
    print("🧪 Testing Comprehensive Logging System\n")
    
    # Test 1: Basic logging
    print("1️⃣ Testing basic logging...")
    logger.debug("Debug message")
    logger.info("Info message")
    logger.warning("Warning message")
    logger.error("Error message (not a real error)")
    print("   ✅ Basic logging complete\n")
    
    # Test 2: Structured logging
    print("2️⃣ Testing structured logging...")
    log_with_context(
        logger,
        logging.INFO,
        "Structured log test",
        user_id="test123",
        action="test_logging",
        metadata={"test": True, "version": "1.0"}
    )
    print("   ✅ Structured logging complete\n")
    
    # Test 3: Correlation context
    print("3️⃣ Testing correlation context...")
    with correlation_context("test-correlation-123"):
        logger.info("Log with correlation ID")
        logger.info("Another log with same correlation ID")
    print("   ✅ Correlation context complete\n")
    
    # Test 4: Performance logging
    print("4️⃣ Testing performance logging...")
    with perf_logger.track_operation("database_query", query_type="SELECT"):
        time.sleep(0.05)  # Simulate work
    
    # Test decorator
    result = slow_operation()
    
    # Test metric logging
    perf_logger.log_metric("cache_hit_rate", 0.85, unit="ratio", cache_type="redis")
    print("   ✅ Performance logging complete\n")
    
    # Test 5: Security logging
    print("5️⃣ Testing security logging...")
    security_logger.log_access(
        resource="api/users",
        action="read",
        user="test_user",
        result="success",
        ip_address="192.168.1.1"
    )
    
    security_logger.log_authentication(
        user="test_user",
        method="oauth2",
        success=True,
        provider="google"
    )
    
    security_logger.log_authentication(
        user="hacker",
        method="password",
        success=False,
        reason="invalid_credentials"
    )
    print("   ✅ Security logging complete\n")
    
    # Test 6: MCP operation logging
    print("6️⃣ Testing MCP operation logging...")
    mcp_logger.log_tool_call(
        "docker",
        "build",
        {"dockerfile": ".", "tag": "test:latest"},
        correlation_id="mcp-test-456"
    )
    
    mcp_logger.log_tool_result(
        "docker",
        "build",
        success=True,
        duration_ms=2500
    )
    print("   ✅ MCP logging complete\n")
    
    # Test 7: AI request logging
    print("7️⃣ Testing AI request logging...")
    ai_logger.log_request(
        provider="openai",
        model="gpt-4",
        prompt_tokens=1500,
        correlation_id="ai-test-789"
    )
    
    ai_logger.log_response(
        provider="openai",
        model="gpt-4",
        response_tokens=500,
        duration_ms=3000,
        success=True,
        cost=0.05
    )
    print("   ✅ AI logging complete\n")
    
    # Test 8: Infrastructure logging
    print("8️⃣ Testing infrastructure logging...")
    infra_logger.log_deployment(
        service="test-service",
        version="1.2.3",
        environment="staging",
        user="deploy-bot",
        success=True
    )
    print("   ✅ Infrastructure logging complete\n")
    
    # Test 9: Exception logging
    print("9️⃣ Testing exception logging...")
    try:
        raise ValueError("Test exception for logging")
    except ValueError:
        logger.error("Caught test exception", exc_info=True, extra={
            "structured_data": {
                "test_case": "exception_logging",
                "handled": True
            }
        })
    print("   ✅ Exception logging complete\n")
    
    # Test 10: Sensitive data redaction
    print("🔟 Testing sensitive data redaction...")
    logger.info("Testing redaction", extra={
        "structured_data": {
            "username": "test_user",
            "password": "super_secret_password",
            "api_key": "sk-1234567890abcdef",
            "safe_field": "this is safe"
        }
    })
    print("   ✅ Sensitive data redaction complete\n")
    
    print("✅ All logging tests completed successfully!")
    print(f"\n📁 Log files created in: {Path('test_logs').absolute()}")
    
    # Read and display a sample log entry
    log_file = Path("test_logs/development.log")
    if log_file.exists():
        print("\n📋 Sample log entry (last line):")
        with open(log_file, 'r') as f:
            lines = f.readlines()
            if lines:
                try:
                    last_log = json.loads(lines[-1])
                    print(json.dumps(last_log, indent=2))
                except json.JSONDecodeError:
                    print(lines[-1])


if __name__ == "__main__":
    import logging
    asyncio.run(test_logging_system())