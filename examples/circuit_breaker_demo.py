"""
Comprehensive demonstration of standardized circuit breaker patterns.

This script shows how to use all the circuit breaker implementations including:
- Different circuit breaker types (count-based, time-based, percentage-based, adaptive)
- FastAPI middleware integration
- Database connection protection
- External API call protection
- MCP server communication protection
- Bulkhead pattern for service isolation
- Monitoring and metrics collection
- Configuration management
- Automatic recovery and health checking
"""

import asyncio
import time
import logging
from typing import Dict, Any
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import circuit breaker components
from src.core.circuit_breaker_standard import (
    StandardizedCircuitBreaker,
    StandardizedCircuitBreakerFactory,
    CircuitBreakerType,
    get_standardized_circuit_breaker,
    reset_all_standardized_breakers
)
from src.core.circuit_breaker_database import (
    DatabaseCircuitBreaker,
    DatabaseCircuitBreakerConfig,
    get_database_circuit_breaker
)
from src.core.circuit_breaker_mcp import (
    MCPCircuitBreaker,
    MCPServerConfig,
    MCPServerType,
    get_mcp_circuit_breaker
)
from src.core.circuit_breaker_middleware import (
    ExternalServiceCircuitBreakerManager,
    get_external_service_manager
)
from src.core.circuit_breaker_monitoring import (
    get_circuit_breaker_monitor,
    start_circuit_breaker_monitoring,
    stop_circuit_breaker_monitoring
)
from src.core.circuit_breaker_configuration import (
    get_configuration_manager,
    create_circuit_breaker_config
)


class CircuitBreakerDemo:
    """Comprehensive circuit breaker demonstration."""
    
    def __init__(self):
        """Initialize the demo."""
        self.demo_services = {}
        self.monitor = None
        
    async def run_demo(self):
        """Run the complete circuit breaker demonstration."""
        logger.info("Starting Circuit Breaker Standardization Demo")
        logger.info("=" * 60)
        
        try:
            # 1. Configuration Management Demo
            await self.demo_configuration_management()
            
            # 2. Different Circuit Breaker Types Demo
            await self.demo_circuit_breaker_types()
            
            # 3. Database Circuit Breaker Demo
            await self.demo_database_circuit_breaker()
            
            # 4. MCP Server Circuit Breaker Demo
            await self.demo_mcp_circuit_breaker()
            
            # 5. External API Circuit Breaker Demo
            await self.demo_external_api_circuit_breaker()
            
            # 6. Monitoring and Metrics Demo
            await self.demo_monitoring_and_metrics()
            
            # 7. Bulkhead Pattern Demo
            await self.demo_bulkhead_pattern()
            
            # 8. Health Checking and Recovery Demo
            await self.demo_health_checking()
            
            # 9. Integration Demo
            await self.demo_integration_patterns()
            
            logger.info("Circuit Breaker Demo completed successfully!")
            
        except Exception as e:
            logger.error(f"Demo failed: {e}")
            raise
        finally:
            # Cleanup
            await self.cleanup()
    
    async def demo_configuration_management(self):
        """Demonstrate configuration management."""
        logger.info("\n1. Configuration Management Demo")
        logger.info("-" * 40)
        
        config_manager = get_configuration_manager()
        
        # Create configurations from templates
        ai_config = create_circuit_breaker_config(
            "claude_anthropic",
            "ai_provider",
            environment="development",
            failure_threshold=3,
            timeout=30.0
        )
        logger.info(f"Created AI config: {ai_config['name']}")
        
        db_config = create_circuit_breaker_config(
            "main_database",
            "database", 
            environment="development",
            max_connections=25
        )
        logger.info(f"Created DB config: {db_config['name']}")
        
        mcp_config = create_circuit_breaker_config(
            "docker_mcp",
            "mcp_service",
            environment="development",
            failure_threshold=5
        )
        logger.info(f"Created MCP config: {mcp_config['name']}")
        
        # Show configuration summary
        summary = config_manager.get_configuration_summary()
        logger.info(f"Configuration summary: {summary}")
    
    async def demo_circuit_breaker_types(self):
        """Demonstrate different circuit breaker types."""
        logger.info("\n2. Different Circuit Breaker Types Demo")
        logger.info("-" * 40)
        
        # Count-based circuit breaker
        count_breaker = StandardizedCircuitBreakerFactory.create_ai_provider_breaker(
            "count_service", CircuitBreakerType.COUNT_BASED
        )
        self.demo_services["count_service"] = count_breaker
        logger.info("Created count-based circuit breaker")
        
        # Time-based circuit breaker
        time_breaker = StandardizedCircuitBreakerFactory.create_external_api_breaker(
            "time_service", CircuitBreakerType.TIME_BASED
        )
        self.demo_services["time_service"] = time_breaker
        logger.info("Created time-based circuit breaker")
        
        # Percentage-based circuit breaker
        percentage_breaker = StandardizedCircuitBreakerFactory.create_database_breaker(
            "percentage_db", CircuitBreakerType.PERCENTAGE_BASED
        )
        self.demo_services["percentage_db"] = percentage_breaker
        logger.info("Created percentage-based circuit breaker")
        
        # Adaptive circuit breaker
        adaptive_breaker = StandardizedCircuitBreakerFactory.create_ai_provider_breaker(
            "adaptive_ai", CircuitBreakerType.ADAPTIVE
        )
        self.demo_services["adaptive_ai"] = adaptive_breaker
        logger.info("Created adaptive circuit breaker")
        
        # Test each type with simulated calls
        await self.test_circuit_breaker_behavior(count_breaker, "Count-based")
        await self.test_circuit_breaker_behavior(time_breaker, "Time-based")
        await self.test_circuit_breaker_behavior(percentage_breaker, "Percentage-based")
        await self.test_circuit_breaker_behavior(adaptive_breaker, "Adaptive")
    
    async def test_circuit_breaker_behavior(self, breaker: StandardizedCircuitBreaker, type_name: str):
        """Test circuit breaker behavior with simulated calls."""
        logger.info(f"Testing {type_name} circuit breaker...")
        
        # Simulate some successful calls
        for i in range(5):
            try:
                await breaker.call(self.simulate_successful_call)
            except Exception as e:
                logger.warning(f"Call {i+1} failed: {e}")
        
        # Simulate some failing calls
        for i in range(3):
            try:
                await breaker.call(self.simulate_failing_call)
            except Exception as e:
                logger.warning(f"Failing call {i+1}: {e}")
        
        # Check state
        state = breaker.get_state()
        metrics = breaker.get_metrics()
        logger.info(f"{type_name} state: {state.value}, calls: {metrics.get('total_calls', 0)}")
    
    async def simulate_successful_call(self):
        """Simulate a successful service call."""
        await asyncio.sleep(0.1)  # Simulate work
        return {"status": "success", "data": "response data"}
    
    async def simulate_failing_call(self):
        """Simulate a failing service call."""
        await asyncio.sleep(0.05)
        raise Exception("Simulated service failure")
    
    async def demo_database_circuit_breaker(self):
        """Demonstrate database circuit breaker."""
        logger.info("\n3. Database Circuit Breaker Demo")
        logger.info("-" * 40)
        
        # Create database circuit breaker
        db_breaker = get_database_circuit_breaker(
            "demo_database",
            DatabaseCircuitBreakerConfig(
                database_name="demo_database",
                max_connections=10,
                query_timeout=30.0,
                health_check_query="SELECT 1"
            )
        )
        self.demo_services["demo_database"] = db_breaker
        logger.info("Created database circuit breaker")
        
        # Simulate database operations
        try:
            async with db_breaker.get_connection() as conn:
                logger.info("Got database connection")
                
                # Execute some queries
                result1 = await db_breaker.execute_query("SELECT * FROM users LIMIT 10")
                logger.info(f"Query result: {result1}")
                
                result2 = await db_breaker.execute_query(
                    "SELECT * FROM orders WHERE user_id = ?", 
                    [123]
                )
                logger.info(f"Parameterized query result: {result2}")
                
                # Use transaction
                async with db_breaker.transaction() as tx:
                    await tx.execute("INSERT INTO audit_log VALUES (?, ?)", [1, "demo"])
                    await tx.execute("UPDATE user_stats SET last_login = NOW()")
                    logger.info("Transaction completed")
                
        except Exception as e:
            logger.error(f"Database operation failed: {e}")
        
        # Show database metrics
        db_metrics = db_breaker.get_metrics()
        logger.info(f"Database metrics: {db_metrics}")
    
    async def demo_mcp_circuit_breaker(self):
        """Demonstrate MCP server circuit breaker."""
        logger.info("\n4. MCP Server Circuit Breaker Demo")
        logger.info("-" * 40)
        
        # Create MCP server config
        server_config = MCPServerConfig(
            name="demo_docker",
            server_type=MCPServerType.DOCKER,
            transport_uri="stdio",
            command=["docker", "mcp"],
            tools={"run_container", "list_containers", "stop_container"},
            resources={"container_logs", "container_stats"}
        )
        
        # Create MCP circuit breaker
        mcp_breaker = get_mcp_circuit_breaker("demo_docker", server_config)
        self.demo_services["demo_docker"] = mcp_breaker
        logger.info("Created MCP circuit breaker")
        
        # Simulate MCP operations
        try:
            # Connect to server
            connected = await mcp_breaker.connect()
            logger.info(f"MCP connection status: {connected}")
            
            if connected:
                # Call some tools
                result1 = await mcp_breaker.call_tool(
                    "list_containers", 
                    {"filter": "running"}
                )
                logger.info(f"Tool call result: {result1}")
                
                # Read some resources
                result2 = await mcp_breaker.read_resource("container://nginx/logs")
                logger.info(f"Resource read result: {result2}")
        
        except Exception as e:
            logger.error(f"MCP operation failed: {e}")
        
        # Show MCP metrics
        mcp_metrics = mcp_breaker.get_metrics()
        logger.info(f"MCP metrics: {mcp_metrics}")
    
    async def demo_external_api_circuit_breaker(self):
        """Demonstrate external API circuit breaker."""
        logger.info("\n5. External API Circuit Breaker Demo")
        logger.info("-" * 40)
        
        # Register external service
        external_manager = get_external_service_manager()
        payment_breaker = external_manager.register_service(
            "payment_service",
            "https://api.payment-provider.com",
            CircuitBreakerType.TIME_BASED
        )
        self.demo_services["payment_service"] = payment_breaker
        logger.info("Registered external payment service")
        
        # Simulate API calls
        try:
            # Direct call through circuit breaker
            result = await external_manager.call_service(
                "payment_service",
                self.simulate_payment_api_call,
                amount=100.0,
                currency="USD"
            )
            logger.info(f"Payment API result: {result}")
            
        except Exception as e:
            logger.error(f"External API call failed: {e}")
        
        # Show external service metrics
        external_metrics = external_manager.get_all_metrics()
        logger.info(f"External service metrics: {external_metrics}")
    
    async def simulate_payment_api_call(self, amount: float, currency: str):
        """Simulate a payment API call."""
        await asyncio.sleep(0.2)  # Simulate network delay
        return {
            "transaction_id": f"tx_{int(time.time())}",
            "amount": amount,
            "currency": currency,
            "status": "completed"
        }
    
    async def demo_monitoring_and_metrics(self):
        """Demonstrate monitoring and metrics collection."""
        logger.info("\n6. Monitoring and Metrics Demo")
        logger.info("-" * 40)
        
        # Start monitoring
        self.monitor = get_circuit_breaker_monitor()
        await start_circuit_breaker_monitoring()
        logger.info("Started circuit breaker monitoring")
        
        # Let monitoring collect some data
        await asyncio.sleep(2)
        
        # Generate some activity for metrics
        for service_name, breaker in self.demo_services.items():
            if hasattr(breaker, 'call'):  # Standardized breakers
                try:
                    await breaker.call(self.simulate_successful_call)
                    await breaker.call(self.simulate_successful_call)
                    await breaker.call(self.simulate_failing_call)
                except Exception:
                    pass  # Expected failures
        
        # Wait for metrics collection
        await asyncio.sleep(1)
        
        # Get dashboard data
        dashboard_data = self.monitor.get_dashboard_data()
        logger.info("Dashboard Overview:")
        logger.info(f"  Total services: {dashboard_data['overview']['total_services']}")
        logger.info(f"  Healthy services: {dashboard_data['overview']['healthy_services']}")
        logger.info(f"  Total calls: {dashboard_data['overview']['total_calls']}")
        logger.info(f"  Overall failure rate: {dashboard_data['overview']['overall_failure_rate']:.2%}")
        
        # Show alerts
        alerts = dashboard_data.get('active_alerts', [])
        if alerts:
            logger.info(f"Active alerts: {len(alerts)}")
            for alert in alerts[:3]:  # Show first 3
                logger.info(f"  - {alert['severity']}: {alert['message']}")
        else:
            logger.info("No active alerts")
    
    async def demo_bulkhead_pattern(self):
        """Demonstrate bulkhead pattern for service isolation."""
        logger.info("\n7. Bulkhead Pattern Demo")
        logger.info("-" * 40)
        
        # Create services with different bulkhead configurations
        high_priority_service = get_standardized_circuit_breaker(
            "high_priority", "ai", CircuitBreakerType.COUNT_BASED
        )
        low_priority_service = get_standardized_circuit_breaker(
            "low_priority", "external", CircuitBreakerType.COUNT_BASED
        )
        
        logger.info("Created services with bulkhead isolation")
        
        # Simulate concurrent load on both services
        async def load_test_service(service, service_name, calls):
            logger.info(f"Starting load test for {service_name} ({calls} calls)")
            for i in range(calls):
                try:
                    await service.call(self.simulate_successful_call)
                except Exception as e:
                    logger.debug(f"{service_name} call {i+1} failed: {e}")
        
        # Run concurrent load tests
        await asyncio.gather(
            load_test_service(high_priority_service, "high_priority", 10),
            load_test_service(low_priority_service, "low_priority", 15)
        )
        
        logger.info("Bulkhead pattern prevented resource starvation")
    
    async def demo_health_checking(self):
        """Demonstrate health checking and automatic recovery."""
        logger.info("\n8. Health Checking and Recovery Demo")
        logger.info("-" * 40)
        
        # Create service with health checking
        health_service = get_standardized_circuit_breaker(
            "health_monitored", "ai", CircuitBreakerType.ADAPTIVE
        )
        
        logger.info("Created service with health monitoring")
        
        # Simulate health check scenarios
        logger.info("Simulating service degradation...")
        
        # Force some failures to trigger circuit opening
        for i in range(5):
            try:
                await health_service.call(self.simulate_failing_call)
            except Exception:
                pass
        
        state = health_service.get_state()
        logger.info(f"Service state after failures: {state.value}")
        
        # Wait for potential recovery
        await asyncio.sleep(2)
        
        # Try successful calls for recovery
        logger.info("Simulating service recovery...")
        for i in range(3):
            try:
                await health_service.call(self.simulate_successful_call)
                logger.info(f"Recovery call {i+1} succeeded")
            except Exception as e:
                logger.info(f"Recovery call {i+1} rejected: {e}")
        
        final_state = health_service.get_state()
        logger.info(f"Final service state: {final_state.value}")
    
    async def demo_integration_patterns(self):
        """Demonstrate integration patterns and best practices."""
        logger.info("\n9. Integration Patterns Demo")
        logger.info("-" * 40)
        
        # Show how to use decorators
        @get_standardized_circuit_breaker("decorated_service", "external").call
        async def decorated_api_call():
            return await self.simulate_successful_call()
        
        result = await decorated_api_call()
        logger.info(f"Decorated call result: {result}")
        
        # Show configuration updates
        config_manager = get_configuration_manager()
        config_manager.update_configuration(
            "claude_anthropic",
            {"failure_threshold": 2, "timeout": 15.0}
        )
        logger.info("Updated configuration dynamically")
        
        # Show template usage
        templates = config_manager.get_all_templates()
        logger.info(f"Available templates: {list(templates.keys())}")
        
        # Show comprehensive metrics
        all_breakers = {
            **{name: breaker for name, breaker in self.demo_services.items() 
               if hasattr(breaker, 'get_metrics')},
        }
        
        total_calls = sum(
            breaker.get_metrics().get('total_calls', 0) 
            for breaker in all_breakers.values()
        )
        logger.info(f"Total calls across all services: {total_calls}")
    
    async def cleanup(self):
        """Clean up demo resources."""
        logger.info("\nCleaning up demo resources...")
        
        # Stop monitoring
        if self.monitor:
            await stop_circuit_breaker_monitoring()
        
        # Reset all circuit breakers
        reset_all_standardized_breakers()
        
        logger.info("Demo cleanup completed")


async def main():
    """Run the circuit breaker demonstration."""
    demo = CircuitBreakerDemo()
    await demo.run_demo()


if __name__ == "__main__":
    asyncio.run(main())