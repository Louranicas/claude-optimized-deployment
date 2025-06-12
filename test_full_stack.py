#!/usr/bin/env python3
"""
Final full stack verification test
"""

import asyncio
import sys
from datetime import datetime

async def test_imports():
    """Test all critical imports"""
    print("\n🧪 Testing Critical Imports...")
    
    tests = []
    
    # Circle of Experts
    try:
        from src.circle_of_experts import EnhancedExpertManager, ExpertManager
        tests.append(("Circle of Experts", "✅ Pass"))
    except Exception as e:
        tests.append(("Circle of Experts", f"❌ Fail: {e}"))
    
    # MCP Manager
    try:
        from src.mcp.manager import get_mcp_manager
        tests.append(("MCP Manager", "✅ Pass"))
    except Exception as e:
        tests.append(("MCP Manager", f"❌ Fail: {e}"))
    
    # Core Components
    try:
        from src.core.circuit_breaker import CircuitBreaker
        from src.core.exceptions import BaseDeploymentError, DatabaseError, AuthorizationError
        from src.core.retry import retry_with_backoff
        tests.append(("Core Components", "✅ Pass"))
    except Exception as e:
        tests.append(("Core Components", f"❌ Fail: {e}"))
    
    # Database
    try:
        from src.database.models import User
        from src.database.connection import get_database_manager
        tests.append(("Database", "✅ Pass"))
    except Exception as e:
        tests.append(("Database", f"❌ Fail: {e}"))
    
    # Authentication
    try:
        from src.auth.rbac import RBACManager
        from src.auth.tokens import TokenManager
        tests.append(("Authentication", "✅ Pass"))
    except Exception as e:
        tests.append(("Authentication", f"❌ Fail: {e}"))
    
    # Monitoring
    try:
        from src.monitoring.metrics import MetricsCollector
        from src.monitoring.health import HealthCheck
        from src.monitoring.tracing import TracingManager
        tests.append(("Monitoring", "✅ Pass"))
    except Exception as e:
        tests.append(("Monitoring", f"❌ Fail: {e}"))
    
    # API
    try:
        from src.api.circuit_breaker_api import CircuitBreakerAPI, router
        tests.append(("API", "✅ Pass"))
    except Exception as e:
        tests.append(("API", f"❌ Fail: {e}"))
    
    # Print results
    print("\nImport Test Results:")
    print("-" * 40)
    for name, result in tests:
        print(f"{name}: {result}")
    
    passed = sum(1 for _, r in tests if "✅" in r)
    total = len(tests)
    print(f"\nTotal: {passed}/{total} passed ({(passed/total)*100:.1f}%)")
    
    return passed == total

async def test_basic_functionality():
    """Test basic functionality"""
    print("\n🔧 Testing Basic Functionality...")
    
    tests = []
    
    # Test Circuit Breaker
    try:
        from src.core.circuit_breaker import CircuitBreaker
        cb = CircuitBreaker("test", failure_threshold=3)
        tests.append(("Circuit Breaker Creation", "✅ Pass"))
    except Exception as e:
        tests.append(("Circuit Breaker Creation", f"❌ Fail: {e}"))
    
    # Test MCP Manager
    try:
        from src.mcp.manager import get_mcp_manager
        manager = get_mcp_manager()
        await manager.initialize()
        tools = manager.get_available_tools()
        tests.append(("MCP Manager", f"✅ Pass ({len(tools)} tools available)"))
    except Exception as e:
        tests.append(("MCP Manager", f"❌ Fail: {e}"))
    
    # Test Metrics
    try:
        from src.monitoring.metrics import MetricsCollector
        metrics = MetricsCollector()
        metrics.increment_counter("test_counter")
        tests.append(("Metrics Collection", "✅ Pass"))
    except Exception as e:
        tests.append(("Metrics Collection", f"❌ Fail: {e}"))
    
    # Print results
    print("\nFunctionality Test Results:")
    print("-" * 40)
    for name, result in tests:
        print(f"{name}: {result}")
    
    passed = sum(1 for _, r in tests if "✅" in r)
    total = len(tests)
    print(f"\nTotal: {passed}/{total} passed ({(passed/total)*100:.1f}%)")
    
    return passed == total

async def main():
    """Run all tests"""
    print("=" * 60)
    print("FULL STACK VERIFICATION TEST")
    print("=" * 60)
    print(f"Started at: {datetime.now().isoformat()}")
    
    # Run tests
    import_success = await test_imports()
    functionality_success = await test_basic_functionality()
    
    # Summary
    print("\n" + "=" * 60)
    print("FINAL SUMMARY")
    print("=" * 60)
    
    if import_success and functionality_success:
        print("✅ ALL TESTS PASSED - Stack is fully operational!")
        sys.exit(0)
    else:
        print("❌ Some tests failed - Review the output above")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())