"""
Test and demonstrate the circuit breaker implementation.

This script shows how circuit breakers protect external services from cascading failures.
"""

import asyncio
import random
from typing import Dict, Any
import aiohttp

from src.core.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    get_circuit_breaker_manager,
    CircuitOpenError
)
from src.core.circuit_breaker_monitoring import (
    CircuitBreakerMonitor,
    MonitoringConfig,
    log_alert
)


# Simulate external services
class SimulatedService:
    """Simulated external service that can fail."""
    
    def __init__(self, name: str, failure_rate: float = 0.1):
        self.name = name
        self.failure_rate = failure_rate
        self.call_count = 0
        self.is_healthy = True
    
    async def call(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate a service call that might fail."""
        self.call_count += 1
        
        # Simulate network delay
        await asyncio.sleep(random.uniform(0.01, 0.1))
        
        # Simulate failures
        if not self.is_healthy or random.random() < self.failure_rate:
            raise ConnectionError(f"Service {self.name} failed to respond")
        
        return {
            "service": self.name,
            "response": f"Processed request {self.call_count}",
            "data": request
        }
    
    def set_healthy(self, healthy: bool):
        """Set service health status."""
        self.is_healthy = healthy


async def test_basic_circuit_breaker():
    """Test basic circuit breaker functionality."""
    print("\n=== Testing Basic Circuit Breaker ===")
    
    # Create a simulated service
    service = SimulatedService("api_service", failure_rate=0.3)
    
    # Create circuit breaker
    config = CircuitBreakerConfig(
        failure_threshold=3,
        timeout=5,
        failure_rate_threshold=0.5,
        minimum_calls=5
    )
    breaker = CircuitBreaker(config)
    
    # Make calls through circuit breaker
    success_count = 0
    failure_count = 0
    circuit_open_count = 0
    
    for i in range(20):
        try:
            result = await breaker.call(service.call, {"request_id": i})
            success_count += 1
            print(f"Call {i}: Success - {result['response']}")
        except CircuitOpenError:
            circuit_open_count += 1
            print(f"Call {i}: Circuit OPEN - Request rejected")
        except Exception as e:
            failure_count += 1
            print(f"Call {i}: Failed - {e}")
        
        # Small delay between calls
        await asyncio.sleep(0.1)
    
    # Get final metrics
    metrics = breaker.get_metrics()
    print(f"\nFinal Circuit State: {metrics['state']}")
    print(f"Success: {success_count}, Failures: {failure_count}, Rejected: {circuit_open_count}")
    print(f"Failure Rate: {metrics['metrics']['failure_rate']:.1%}")


async def test_circuit_breaker_recovery():
    """Test circuit breaker recovery after service becomes healthy."""
    print("\n=== Testing Circuit Breaker Recovery ===")
    
    # Create a service that will fail then recover
    service = SimulatedService("database_service", failure_rate=0.0)
    
    # Create circuit breaker with short timeout for testing
    config = CircuitBreakerConfig(
        failure_threshold=3,
        timeout=2,  # 2 seconds before trying to recover
        success_threshold=2,  # 2 successes to close circuit
        half_open_max_calls=3
    )
    breaker = CircuitBreaker(config)
    
    # Phase 1: Service is unhealthy
    print("\nPhase 1: Service unhealthy")
    service.set_healthy(False)
    
    for i in range(5):
        try:
            await breaker.call(service.call, {"request_id": i})
        except CircuitOpenError:
            print(f"Call {i}: Circuit OPEN")
        except Exception:
            print(f"Call {i}: Failed (Circuit {breaker.state.value})")
    
    print(f"Circuit State: {breaker.state.value}")
    
    # Phase 2: Wait for timeout and service recovers
    print("\nPhase 2: Waiting for timeout and service recovery...")
    service.set_healthy(True)
    await asyncio.sleep(2.5)
    
    # Phase 3: Circuit should go to half-open and eventually close
    print("\nPhase 3: Testing recovery")
    for i in range(5):
        try:
            result = await breaker.call(service.call, {"request_id": i})
            print(f"Call {i}: Success (Circuit {breaker.state.value})")
        except CircuitOpenError:
            print(f"Call {i}: Circuit still OPEN")
        except Exception as e:
            print(f"Call {i}: Failed - {e}")
    
    print(f"\nFinal Circuit State: {breaker.state.value}")


async def test_multiple_services_with_monitoring():
    """Test multiple services with circuit breakers and monitoring."""
    print("\n=== Testing Multiple Services with Monitoring ===")
    
    # Create monitoring
    monitor_config = MonitoringConfig(
        check_interval=1.0,
        alert_on_open=True,
        alert_on_half_open=True
    )
    monitor = CircuitBreakerMonitor(monitor_config)
    monitor.add_alert_callback(log_alert)
    
    # Start monitoring
    await monitor.start()
    
    # Create multiple services with different characteristics
    services = {
        "auth_service": SimulatedService("auth_service", failure_rate=0.1),
        "payment_service": SimulatedService("payment_service", failure_rate=0.7),  # High failure
        "notification_service": SimulatedService("notification_service", failure_rate=0.2)
    }
    
    # Get circuit breaker manager
    manager = get_circuit_breaker_manager()
    
    # Configure circuit breakers for each service
    for service_name in services:
        await manager.get_or_create(
            service_name,
            CircuitBreakerConfig(
                failure_threshold=3,
                timeout=5,
                failure_rate_threshold=0.5,
                minimum_calls=5,
                name=service_name
            )
        )
    
    # Simulate concurrent calls to all services
    async def call_service(service_name: str, service: SimulatedService, num_calls: int):
        breaker = manager.get(service_name)
        results = {"success": 0, "failed": 0, "rejected": 0}
        
        for i in range(num_calls):
            try:
                await breaker.call(service.call, {"service": service_name, "call": i})
                results["success"] += 1
            except CircuitOpenError:
                results["rejected"] += 1
            except Exception:
                results["failed"] += 1
            
            await asyncio.sleep(0.05)
        
        return service_name, results
    
    # Run concurrent calls
    tasks = [
        call_service(name, service, 20)
        for name, service in services.items()
    ]
    
    results = await asyncio.gather(*tasks)
    
    # Wait a bit for monitoring to catch up
    await asyncio.sleep(2)
    
    # Print results
    print("\n--- Service Call Results ---")
    for service_name, result in results:
        print(f"{service_name}: {result}")
    
    # Get monitoring status
    status = monitor.get_status()
    print(f"\n--- Monitoring Status ---")
    print(f"Open Circuits: {status['open_circuits']}")
    print(f"Half-Open Circuits: {status['half_open_circuits']}")
    print(f"Overall Failure Rate: {status['overall_failure_rate']:.1%}")
    
    # Get recent alerts
    alerts = monitor.get_recent_alerts(5)
    if alerts:
        print(f"\n--- Recent Alerts ({len(alerts)}) ---")
        for alert in alerts:
            print(f"- {alert['breaker_name']}: {alert['old_state']} -> {alert['new_state']}")
    
    # Stop monitoring
    await monitor.stop()


async def test_fallback_mechanism():
    """Test circuit breaker with fallback responses."""
    print("\n=== Testing Fallback Mechanism ===")
    
    # Create a service that will fail
    service = SimulatedService("search_service", failure_rate=0.9)
    
    # Define fallback function
    def search_fallback(*args, **kwargs) -> Dict[str, Any]:
        return {
            "service": "search_service",
            "response": "Cached results (fallback)",
            "cached": True,
            "data": []
        }
    
    # Create circuit breaker with fallback
    config = CircuitBreakerConfig(
        failure_threshold=2,
        timeout=10,
        fallback=search_fallback
    )
    breaker = CircuitBreaker(config)
    
    # Make calls - should get fallback when circuit opens
    for i in range(10):
        result = await breaker.call(service.call, {"query": f"search_{i}"})
        
        if result.get("cached"):
            print(f"Call {i}: Got fallback response")
        else:
            print(f"Call {i}: Got real response")
    
    metrics = breaker.get_metrics()
    print(f"\nCircuit State: {metrics['state']}")
    print(f"Fallback Calls: {metrics['metrics']['fallback_calls']}")


async def test_circuit_breaker_with_api_calls():
    """Test circuit breakers with real-world API simulation."""
    print("\n=== Testing Circuit Breakers with API Calls ===")
    
    # Simulate different API endpoints
    class APIEndpoint:
        def __init__(self, name: str, latency: float, error_rate: float):
            self.name = name
            self.latency = latency
            self.error_rate = error_rate
            self.request_count = 0
        
        async def call(self, method: str, data: Dict[str, Any]) -> Dict[str, Any]:
            self.request_count += 1
            
            # Simulate latency
            await asyncio.sleep(self.latency)
            
            # Simulate errors
            if random.random() < self.error_rate:
                if random.random() < 0.5:
                    raise aiohttp.ClientError(f"Connection to {self.name} failed")
                else:
                    raise TimeoutError(f"Request to {self.name} timed out")
            
            return {
                "endpoint": self.name,
                "method": method,
                "request_id": self.request_count,
                "data": data,
                "timestamp": asyncio.get_event_loop().time()
            }
    
    # Create API endpoints with different characteristics
    endpoints = {
        "users_api": APIEndpoint("users_api", latency=0.05, error_rate=0.1),
        "orders_api": APIEndpoint("orders_api", latency=0.1, error_rate=0.3),
        "inventory_api": APIEndpoint("inventory_api", latency=0.02, error_rate=0.05),
        "payment_api": APIEndpoint("payment_api", latency=0.2, error_rate=0.4)
    }
    
    # Create circuit breakers for each endpoint
    manager = get_circuit_breaker_manager()
    
    for endpoint_name in endpoints:
        await manager.get_or_create(
            f"api_{endpoint_name}",
            CircuitBreakerConfig(
                failure_threshold=3,
                timeout=10,
                failure_rate_threshold=0.4,
                minimum_calls=5,
                excluded_exceptions=[ValueError, TypeError]  # Don't count programming errors
            )
        )
    
    # Simulate a typical application workflow
    async def process_order(order_id: int) -> Dict[str, Any]:
        results = {}
        
        # Get user info
        breaker = manager.get("api_users_api")
        try:
            user_data = await breaker.call(
                endpoints["users_api"].call,
                "GET",
                {"user_id": f"user_{order_id}"}
            )
            results["user"] = user_data
        except CircuitOpenError:
            results["user"] = {"error": "User service unavailable"}
        except Exception as e:
            results["user"] = {"error": str(e)}
        
        # Check inventory
        breaker = manager.get("api_inventory_api")
        try:
            inventory_data = await breaker.call(
                endpoints["inventory_api"].call,
                "GET",
                {"order_id": order_id}
            )
            results["inventory"] = inventory_data
        except CircuitOpenError:
            results["inventory"] = {"error": "Inventory service unavailable"}
        except Exception as e:
            results["inventory"] = {"error": str(e)}
        
        # Process payment
        breaker = manager.get("api_payment_api")
        try:
            payment_data = await breaker.call(
                endpoints["payment_api"].call,
                "POST",
                {"order_id": order_id, "amount": 100}
            )
            results["payment"] = payment_data
        except CircuitOpenError:
            results["payment"] = {"error": "Payment service unavailable"}
        except Exception as e:
            results["payment"] = {"error": str(e)}
        
        # Create order
        breaker = manager.get("api_orders_api")
        try:
            order_data = await breaker.call(
                endpoints["orders_api"].call,
                "POST",
                {"order_id": order_id, "status": "processing"}
            )
            results["order"] = order_data
        except CircuitOpenError:
            results["order"] = {"error": "Order service unavailable"}
        except Exception as e:
            results["order"] = {"error": str(e)}
        
        return results
    
    # Process multiple orders concurrently
    print("\nProcessing orders...")
    tasks = [process_order(i) for i in range(20)]
    order_results = await asyncio.gather(*tasks)
    
    # Analyze results
    successful_orders = 0
    partial_failures = 0
    total_failures = 0
    
    for i, result in enumerate(order_results):
        errors = [k for k, v in result.items() if isinstance(v, dict) and "error" in v]
        if not errors:
            successful_orders += 1
        elif len(errors) == len(result):
            total_failures += 1
        else:
            partial_failures += 1
        
        if errors:
            print(f"Order {i}: Failed services: {errors}")
    
    print(f"\n--- Order Processing Results ---")
    print(f"Successful: {successful_orders}")
    print(f"Partial Failures: {partial_failures}")
    print(f"Total Failures: {total_failures}")
    
    # Show circuit breaker states
    print(f"\n--- Circuit Breaker States ---")
    summary = manager.get_summary()
    for breaker_name in sorted(summary["open_circuits"] + summary["half_open_circuits"] + summary["closed_circuits"]):
        breaker = manager.get(breaker_name)
        metrics = breaker.get_metrics()
        print(f"{breaker_name}: {metrics['state']} "
              f"(calls: {metrics['metrics']['total_calls']}, "
              f"failures: {metrics['metrics']['failed_calls']}, "
              f"rate: {metrics['metrics']['failure_rate']:.1%})")


async def main():
    """Run all circuit breaker tests."""
    print("Circuit Breaker Implementation Test Suite")
    print("=" * 50)
    
    # Run tests
    await test_basic_circuit_breaker()
    await test_circuit_breaker_recovery()
    await test_fallback_mechanism()
    await test_multiple_services_with_monitoring()
    await test_circuit_breaker_with_api_calls()
    
    print("\n" + "=" * 50)
    print("All tests completed!")


if __name__ == "__main__":
    asyncio.run(main())