"""
Examples demonstrating comprehensive retry patterns usage.

This file shows how to use the retry patterns system for:
- Basic service calls with retry
- AI service integration
- Database operations
- HTTP API calls
- Custom fallback strategies
- Configuration-driven setup
"""

import asyncio
import logging
import random
from datetime import datetime, timedelta

from src.core.retry_patterns import (
    RetryPolicyConfig, RetryStrategy, ServiceType,
    comprehensive_retry, retry_ai_service, retry_database, retry_api_call
)
from src.core.retry_config import create_default_config_file, load_config_from_file
from src.core.retry_monitoring import start_prometheus_server, get_retry_monitor
from src.core.graceful_degradation import (
    FallbackStrategy, ServicePriority, graceful_degradation
)
from src.core.retry_integration import (
    resilient_service, resilient_call, initialize_from_config_file,
    UnifiedServiceConfig, get_unified_manager
)
from src.core.retry_testing import run_comprehensive_test_suite

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Example 1: Basic retry with custom configuration
@comprehensive_retry(
    service_name="external_api",
    service_type=ServiceType.HTTP_API,
    custom_config=RetryPolicyConfig(
        max_attempts=5,
        base_delay=1.0,
        strategy=RetryStrategy.EXPONENTIAL_JITTER,
        enable_circuit_breaker=True,
        enable_retry_budget=True
    )
)
async def call_external_api(data: dict) -> dict:
    """Example external API call with comprehensive retry."""
    # Simulate API call that might fail
    if random.random() < 0.3:  # 30% chance of failure
        raise ConnectionError("API connection failed")
    
    await asyncio.sleep(0.1)  # Simulate API response time
    return {"status": "success", "data": data, "timestamp": datetime.now().isoformat()}


# Example 2: AI service with specialized retry policy
@retry_ai_service("claude_api", max_attempts=5, base_delay=2.0)
async def call_claude_api(prompt: str) -> str:
    """Example Claude API call with AI-optimized retry."""
    # Simulate Claude API call
    if random.random() < 0.2:  # 20% chance of failure
        raise Exception("Claude API rate limit exceeded")
    
    await asyncio.sleep(0.5)  # Simulate AI processing time
    return f"Claude response to: {prompt}"


# Example 3: Database operation with retry
@retry_database("postgres_db", max_attempts=3, base_delay=0.5)
async def database_operation(query: str) -> list:
    """Example database operation with retry."""
    # Simulate database call
    if random.random() < 0.15:  # 15% chance of failure
        raise ConnectionError("Database connection timeout")
    
    await asyncio.sleep(0.05)  # Simulate DB query time
    return [{"id": 1, "result": "data"}]


# Example 4: Service with graceful degradation
def create_fallback_response(prompt: str) -> str:
    """Fallback function for AI service."""
    return f"Fallback response for: {prompt[:50]}..."

@graceful_degradation(
    service_name="ai_service_with_fallback",
    priority=ServicePriority.HIGH,
    fallback_strategy=FallbackStrategy(
        name="ai_fallback",
        fallback_func=create_fallback_response,
        cache_enabled=True,
        cache_ttl=600
    )
)
async def ai_service_with_fallback(prompt: str) -> str:
    """AI service with fallback strategy."""
    if random.random() < 0.4:  # 40% chance of failure
        raise Exception("AI service temporarily unavailable")
    
    await asyncio.sleep(1.0)  # Simulate AI processing
    return f"AI response: {prompt}"


# Example 5: Unified resilient service
@resilient_service(
    service_name="payment_service",
    service_type=ServiceType.MICROSERVICE,
    retry_enabled=True,
    circuit_breaker_enabled=True,
    degradation_enabled=True,
    priority=ServicePriority.CRITICAL
)
async def process_payment(amount: float, currency: str) -> dict:
    """Payment processing with full resilience patterns."""
    if random.random() < 0.1:  # 10% chance of failure
        raise Exception("Payment gateway error")
    
    await asyncio.sleep(0.2)  # Simulate payment processing
    return {
        "transaction_id": f"txn_{random.randint(1000, 9999)}",
        "amount": amount,
        "currency": currency,
        "status": "completed"
    }


# Example 6: Manual resilient call
async def manual_service_call():
    """Example of manual resilient service call."""
    async def unreliable_service():
        if random.random() < 0.3:
            raise Exception("Service error")
        return "Service response"
    
    try:
        result = await resilient_call("manual_service", unreliable_service)
        logger.info(f"Manual service call result: {result}")
        return result
    except Exception as e:
        logger.error(f"Manual service call failed: {e}")
        return None


async def demonstration_scenario():
    """Demonstrate various retry patterns in action."""
    logger.info("Starting retry patterns demonstration...")
    
    # Example 1: External API calls
    logger.info("\n1. Testing external API with retry patterns...")
    for i in range(5):
        try:
            result = await call_external_api({"request_id": i})
            logger.info(f"API call {i} successful: {result['status']}")
        except Exception as e:
            logger.error(f"API call {i} failed: {e}")
    
    # Example 2: AI service calls
    logger.info("\n2. Testing AI service with specialized retry...")
    prompts = [
        "What is the weather like?",
        "Explain quantum computing",
        "Write a haiku about programming"
    ]
    
    for prompt in prompts:
        try:
            response = await call_claude_api(prompt)
            logger.info(f"AI response: {response}")
        except Exception as e:
            logger.error(f"AI call failed: {e}")
    
    # Example 3: Database operations
    logger.info("\n3. Testing database operations with retry...")
    queries = [
        "SELECT * FROM users WHERE active = true",
        "INSERT INTO logs (message) VALUES ('test')",
        "UPDATE settings SET value = 'new_value'"
    ]
    
    for query in queries:
        try:
            result = await database_operation(query)
            logger.info(f"Database query successful: {len(result)} rows")
        except Exception as e:
            logger.error(f"Database query failed: {e}")
    
    # Example 4: Service with fallback
    logger.info("\n4. Testing service with graceful degradation...")
    test_prompts = [
        "Generate a creative story",
        "Analyze this data set",
        "Provide recommendations"
    ]
    
    for prompt in test_prompts:
        try:
            response = await ai_service_with_fallback(prompt)
            logger.info(f"AI service response: {response}")
        except Exception as e:
            logger.error(f"AI service failed: {e}")
    
    # Example 5: Payment processing
    logger.info("\n5. Testing payment service with full resilience...")
    payments = [
        (100.0, "USD"),
        (50.0, "EUR"),
        (25.0, "GBP")
    ]
    
    for amount, currency in payments:
        try:
            result = await process_payment(amount, currency)
            logger.info(f"Payment processed: {result['transaction_id']}")
        except Exception as e:
            logger.error(f"Payment failed: {e}")
    
    # Example 6: Manual service calls
    logger.info("\n6. Testing manual resilient calls...")
    for i in range(3):
        result = await manual_service_call()
        if result:
            logger.info(f"Manual call {i} successful")


async def monitoring_example():
    """Demonstrate monitoring and metrics collection."""
    logger.info("\nStarting monitoring demonstration...")
    
    # Get retry monitor
    monitor = get_retry_monitor()
    
    # Make some calls to generate metrics
    for i in range(20):
        try:
            await call_external_api({"test": i})
        except:
            pass  # Ignore errors for metrics
    
    # Get dashboard data
    dashboard_data = await monitor.get_dashboard_data()
    logger.info(f"Dashboard data: {dashboard_data}")
    
    # Export metrics
    await monitor.export_metrics("/tmp/retry_metrics.json")
    logger.info("Exported retry metrics to /tmp/retry_metrics.json")


async def configuration_example():
    """Demonstrate configuration-driven setup."""
    logger.info("\nTesting configuration-driven setup...")
    
    # Create default configuration file
    config_file = "/tmp/retry_config.yaml"
    create_default_config_file(config_file)
    logger.info(f"Created default config file: {config_file}")
    
    # Initialize from configuration
    success = await initialize_from_config_file(config_file)
    if success:
        logger.info("Successfully initialized from configuration file")
        
        # Get status of all services
        manager = get_unified_manager()
        status = await manager.get_all_services_status()
        logger.info(f"Services status: {status['summary']}")
    else:
        logger.error("Failed to initialize from configuration file")


async def testing_example():
    """Demonstrate comprehensive testing framework."""
    logger.info("\nRunning comprehensive test suite...")
    
    # Run test suite with default configurations
    test_results = await run_comprehensive_test_suite()
    
    logger.info(f"Test suite completed:")
    logger.info(f"Summary: {test_results['summary']}")
    
    # Export test results
    import json
    with open("/tmp/test_results.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    logger.info("Test results exported to /tmp/test_results.json")


async def load_testing_example():
    """Demonstrate load testing capabilities."""
    logger.info("\nStarting load testing example...")
    
    from src.core.retry_testing import RetryTester
    
    tester = RetryTester()
    
    # Create configuration for load testing
    config = RetryPolicyConfig(
        max_attempts=3,
        base_delay=0.5,
        strategy=RetryStrategy.EXPONENTIAL_JITTER,
        service_name="load_test_service"
    )
    
    # Run load test
    load_result = await tester.run_load_test(
        config=config,
        concurrent_operations=50,
        total_operations=500,
        failure_rate=0.2
    )
    
    logger.info(f"Load test results:")
    logger.info(f"Throughput: {load_result.throughput:.2f} ops/sec")
    logger.info(f"Success rate: {load_result.successful_operations / load_result.total_operations:.2%}")
    logger.info(f"Average response time: {load_result.avg_response_time:.3f}s")
    logger.info(f"P95 response time: {load_result.p95_response_time:.3f}s")


async def main():
    """Main demonstration function."""
    logger.info("=== Comprehensive Retry Patterns Demonstration ===")
    
    # Start Prometheus server for metrics (optional)
    # start_prometheus_server(port=8000)
    
    try:
        # Run demonstrations
        await demonstration_scenario()
        await monitoring_example()
        await configuration_example()
        await testing_example()
        await load_testing_example()
        
        # Export comprehensive metrics
        manager = get_unified_manager()
        await manager.export_comprehensive_metrics("/tmp/comprehensive_metrics.json")
        logger.info("Exported comprehensive metrics to /tmp/comprehensive_metrics.json")
        
    except Exception as e:
        logger.error(f"Demonstration failed: {e}")
    
    logger.info("=== Demonstration completed ===")


if __name__ == "__main__":
    asyncio.run(main())