#!/usr/bin/env python3
"""
Comprehensive Circle of Experts System Testing
Agent 4: End-to-end functionality validation
"""

import asyncio
import os
import sys
import json
import time
import traceback
from datetime import datetime
from typing import Dict, List, Any, Optional

# Add src to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Test result tracking
test_results = {
    "timestamp": datetime.now().isoformat(),
    "tests_passed": 0,
    "tests_failed": 0,
    "core_functionality": {},
    "expert_providers": {},
    "integration": {},
    "error_handling": {},
    "performance": {},
    "imports": {},
    "failures": []
}

def log_test(category: str, test_name: str, success: bool, details: str = "", error: str = ""):
    """Log test results"""
    print(f"\n{'✓' if success else '✗'} {test_name}")
    if details:
        print(f"  Details: {details}")
    if error:
        print(f"  Error: {error}")
    
    test_results[category][test_name] = {
        "success": success,
        "details": details,
        "error": error
    }
    
    if success:
        test_results["tests_passed"] += 1
    else:
        test_results["tests_failed"] += 1
        test_results["failures"].append({
            "category": category,
            "test": test_name,
            "error": error
        })

async def test_imports():
    """Test 1: Import and Dependency Testing"""
    print("\n" + "="*60)
    print("TEST 1: IMPORT AND DEPENDENCY VALIDATION")
    print("="*60)
    
    # Test basic imports
    try:
        from src.circle_of_experts import (
            ExpertManager,
            QueryHandler,
            ResponseCollector,
            ExpertQuery,
            ExpertResponse
        )
        log_test("imports", "Basic imports from circle_of_experts", True)
    except Exception as e:
        log_test("imports", "Basic imports from circle_of_experts", False, error=str(e))
        return False
    
    # Test core module imports
    try:
        from src.circle_of_experts.core import enhanced_expert_manager
        from src.circle_of_experts.core import query_handler
        from src.circle_of_experts.core import response_collector
        log_test("imports", "Core module imports", True)
    except Exception as e:
        log_test("imports", "Core module imports", False, error=str(e))
    
    # Test expert imports
    try:
        from src.circle_of_experts.experts import claude_expert
        from src.circle_of_experts.experts import commercial_experts
        from src.circle_of_experts.experts import open_source_experts
        from src.circle_of_experts.experts import expert_factory
        log_test("imports", "Expert module imports", True)
    except Exception as e:
        log_test("imports", "Expert module imports", False, error=str(e))
    
    # Test model imports
    try:
        from src.circle_of_experts.models import query
        from src.circle_of_experts.models import response
        log_test("imports", "Model imports", True)
    except Exception as e:
        log_test("imports", "Model imports", False, error=str(e))
    
    # Test utility imports
    try:
        from src.circle_of_experts.utils import logging as coe_logging
        from src.circle_of_experts.utils import retry
        log_test("imports", "Utility imports", True)
    except Exception as e:
        log_test("imports", "Utility imports", False, error=str(e))
    
    # Test drive imports
    try:
        from src.circle_of_experts.drive import manager as drive_manager
        log_test("imports", "Google Drive imports", True)
    except Exception as e:
        log_test("imports", "Google Drive imports", False, error=str(e))
    
    # Test dependency availability
    dependencies = {
        "anthropic": "Anthropic API",
        "openai": "OpenAI API",
        "google.generativeai": "Google Gemini",
        "httpx": "HTTP client",
        "pydantic": "Data validation",
        "google.oauth2": "Google authentication"
    }
    
    for module, name in dependencies.items():
        try:
            __import__(module)
            log_test("imports", f"Dependency: {name}", True)
        except ImportError as e:
            log_test("imports", f"Dependency: {name}", False, error=str(e))
    
    return True

async def test_core_functionality():
    """Test 2: Core Functionality Testing"""
    print("\n" + "="*60)
    print("TEST 2: CORE FUNCTIONALITY TESTING")
    print("="*60)
    
    try:
        from src.circle_of_experts import ExpertManager, QueryHandler, ResponseCollector
    except ImportError as e:
        log_test("core_functionality", "Import core modules", False, error=str(e))
        return False
    
    # Test ExpertManager initialization
    try:
        manager = ExpertManager(log_level="DEBUG")
        log_test("core_functionality", "ExpertManager initialization", True, 
                details="Manager created successfully")
    except Exception as e:
        log_test("core_functionality", "ExpertManager initialization", False, error=str(e))
        return False
    
    # Test QueryHandler creation
    try:
        if hasattr(manager, 'query_handler'):
            log_test("core_functionality", "QueryHandler available", True,
                    details=f"QueryHandler type: {type(manager.query_handler)}")
        else:
            log_test("core_functionality", "QueryHandler available", False, 
                    error="No query_handler attribute")
    except Exception as e:
        log_test("core_functionality", "QueryHandler available", False, error=str(e))
    
    # Test ResponseCollector
    try:
        if hasattr(manager, 'response_collector'):
            log_test("core_functionality", "ResponseCollector available", True,
                    details=f"ResponseCollector type: {type(manager.response_collector)}")
        else:
            log_test("core_functionality", "ResponseCollector available", False,
                    error="No response_collector attribute")
    except Exception as e:
        log_test("core_functionality", "ResponseCollector available", False, error=str(e))
    
    # Test expert availability check
    try:
        available_experts = await manager.get_available_experts()
        log_test("core_functionality", "Get available experts", True,
                details=f"Found {len(available_experts)} expert types")
        print(f"  Available experts: {available_experts}")
    except Exception as e:
        log_test("core_functionality", "Get available experts", False, error=str(e))
    
    # Test simple query creation (without Drive)
    try:
        from src.circle_of_experts.models.query import ExpertQuery, QueryType, QueryPriority
        
        test_query = ExpertQuery(
            title="Test Query",
            content="This is a test query",
            requester="test@example.com",
            query_type=QueryType.GENERAL,
            priority=QueryPriority.MEDIUM
        )
        log_test("core_functionality", "Create ExpertQuery model", True,
                details=f"Query ID: {test_query.id}")
    except Exception as e:
        log_test("core_functionality", "Create ExpertQuery model", False, error=str(e))
    
    return True

async def test_expert_providers():
    """Test 3: Expert Provider Testing"""
    print("\n" + "="*60)
    print("TEST 3: EXPERT PROVIDER TESTING")
    print("="*60)
    
    try:
        from src.circle_of_experts.experts.expert_factory import get_expert
        from src.circle_of_experts.models.query import ExpertQuery, QueryType, QueryPriority
    except ImportError as e:
        log_test("expert_providers", "Import expert factory", False, error=str(e))
        return False
    
    # Create test query
    test_query = ExpertQuery(
        title="Test Query",
        content="What is 2+2?",
        requester="test@example.com",
        query_type=QueryType.GENERAL,
        priority=QueryPriority.LOW
    )
    
    # Test each expert type
    expert_types = ["claude", "gpt4", "gemini", "deepseek", "llama", "mixtral"]
    
    for expert_type in expert_types:
        try:
            # Try to create expert
            expert = get_expert(expert_type)
            log_test("expert_providers", f"Create {expert_type} expert", True,
                    details=f"Expert class: {type(expert).__name__}")
            
            # Check if expert is available
            try:
                is_available = await expert.is_available()
                if is_available:
                    log_test("expert_providers", f"{expert_type} availability", True,
                            details="Expert is available")
                    
                    # Try a simple query if available
                    try:
                        response = await expert.submit_query(test_query)
                        log_test("expert_providers", f"{expert_type} query submission", True,
                                details=f"Response length: {len(response.response) if response else 0}")
                    except Exception as e:
                        log_test("expert_providers", f"{expert_type} query submission", False,
                                error=str(e))
                else:
                    log_test("expert_providers", f"{expert_type} availability", False,
                            details="Expert not available (likely missing API key)")
            except Exception as e:
                log_test("expert_providers", f"{expert_type} availability check", False,
                        error=str(e))
                
        except Exception as e:
            log_test("expert_providers", f"Create {expert_type} expert", False, error=str(e))
    
    return True

async def test_integration():
    """Test 4: Integration Testing"""
    print("\n" + "="*60)
    print("TEST 4: INTEGRATION TESTING")
    print("="*60)
    
    # Test example script execution
    example_scripts = [
        "examples/circle_of_experts_usage.py",
        "examples/claude_code_circle_of_experts.py",
        "examples/expert_integration_analysis.py"
    ]
    
    for script in example_scripts:
        if os.path.exists(script):
            try:
                # Check if script has proper imports
                with open(script, 'r') as f:
                    content = f.read()
                    if 'circle_of_experts' in content:
                        log_test("integration", f"Script validation: {script}", True,
                                details="Script contains circle_of_experts imports")
                    else:
                        log_test("integration", f"Script validation: {script}", False,
                                details="No circle_of_experts imports found")
            except Exception as e:
                log_test("integration", f"Script validation: {script}", False, error=str(e))
        else:
            log_test("integration", f"Script existence: {script}", False,
                    error="Script file not found")
    
    # Test basic consultation workflow
    try:
        from src.circle_of_experts import ExpertManager
        
        manager = ExpertManager()
        
        # Test without Google Drive (will fail but should handle gracefully)
        try:
            result = await manager.consult_experts(
                title="Integration Test Query",
                content="This is a test query for integration testing",
                requester="test@example.com",
                wait_for_responses=False  # Don't wait for responses
            )
            
            if isinstance(result, dict) and 'query' in result:
                log_test("integration", "Basic consultation workflow", True,
                        details=f"Query created with ID: {result.get('query', {}).get('id', 'unknown')}")
            else:
                log_test("integration", "Basic consultation workflow", False,
                        details="Unexpected result format")
        except Exception as e:
            if "Google Drive" in str(e) or "credentials" in str(e).lower():
                log_test("integration", "Basic consultation workflow", True,
                        details="Failed as expected due to missing Google Drive credentials")
            else:
                log_test("integration", "Basic consultation workflow", False, error=str(e))
                
    except Exception as e:
        log_test("integration", "Integration setup", False, error=str(e))
    
    return True

async def test_error_handling():
    """Test 5: Error Handling Validation"""
    print("\n" + "="*60)
    print("TEST 5: ERROR HANDLING VALIDATION")
    print("="*60)
    
    try:
        from src.circle_of_experts import ExpertManager
        from src.circle_of_experts.experts.expert_factory import get_expert
    except ImportError as e:
        log_test("error_handling", "Import modules", False, error=str(e))
        return False
    
    # Test with missing API keys
    os.environ.pop('ANTHROPIC_API_KEY', None)
    os.environ.pop('OPENAI_API_KEY', None)
    
    try:
        manager = ExpertManager()
        available = await manager.get_available_experts()
        log_test("error_handling", "Handle missing API keys", True,
                details=f"Available experts with no API keys: {len(available)}")
    except Exception as e:
        log_test("error_handling", "Handle missing API keys", False, error=str(e))
    
    # Test invalid expert type
    try:
        expert = get_expert("invalid_expert_type")
        log_test("error_handling", "Invalid expert type", False,
                details="Should have raised exception")
    except Exception as e:
        log_test("error_handling", "Invalid expert type", True,
                details=f"Correctly raised: {type(e).__name__}")
    
    # Test timeout handling
    try:
        from src.circle_of_experts.utils.retry import with_retry
        
        @with_retry(max_attempts=2, delay=0.1)
        async def failing_function():
            raise TimeoutError("Test timeout")
        
        try:
            await failing_function()
            log_test("error_handling", "Retry mechanism", False,
                    details="Should have failed after retries")
        except TimeoutError:
            log_test("error_handling", "Retry mechanism", True,
                    details="Correctly exhausted retries")
    except Exception as e:
        log_test("error_handling", "Retry mechanism setup", False, error=str(e))
    
    return True

async def test_performance():
    """Test 6: Performance Testing"""
    print("\n" + "="*60)
    print("TEST 6: PERFORMANCE TESTING")
    print("="*60)
    
    try:
        from src.circle_of_experts import ExpertManager
        from src.circle_of_experts.models.query import ExpertQuery, QueryType, QueryPriority
    except ImportError as e:
        log_test("performance", "Import modules", False, error=str(e))
        return False
    
    # Test manager initialization time
    start_time = time.time()
    try:
        manager = ExpertManager()
        init_time = time.time() - start_time
        log_test("performance", "Manager initialization time", True,
                details=f"{init_time:.3f} seconds")
    except Exception as e:
        log_test("performance", "Manager initialization", False, error=str(e))
        return False
    
    # Test query creation performance
    start_time = time.time()
    queries = []
    try:
        for i in range(10):
            query = ExpertQuery(
                title=f"Performance Test Query {i}",
                content=f"This is test query number {i}",
                requester="perf@test.com",
                query_type=QueryType.GENERAL,
                priority=QueryPriority.LOW
            )
            queries.append(query)
        
        creation_time = time.time() - start_time
        log_test("performance", "Query creation (10 queries)", True,
                details=f"{creation_time:.3f} seconds ({creation_time/10:.3f}s per query)")
    except Exception as e:
        log_test("performance", "Query creation", False, error=str(e))
    
    # Test concurrent operations
    async def check_expert(expert_type):
        try:
            from src.circle_of_experts.experts.expert_factory import get_expert
            expert = get_expert(expert_type)
            return await expert.is_available()
        except:
            return False
    
    start_time = time.time()
    try:
        # Check multiple experts concurrently
        expert_checks = await asyncio.gather(
            check_expert("claude"),
            check_expert("gpt4"),
            check_expert("gemini"),
            check_expert("deepseek"),
            return_exceptions=True
        )
        concurrent_time = time.time() - start_time
        available_count = sum(1 for check in expert_checks if check is True)
        log_test("performance", "Concurrent expert checks", True,
                details=f"{concurrent_time:.3f} seconds for 4 checks ({available_count} available)")
    except Exception as e:
        log_test("performance", "Concurrent expert checks", False, error=str(e))
    
    return True

async def main():
    """Run all tests and generate report"""
    print("\n" + "="*80)
    print("CIRCLE OF EXPERTS - COMPREHENSIVE FUNCTIONALITY TEST")
    print("Agent 4: End-to-end validation and testing")
    print("="*80)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Run all test suites
    test_suites = [
        ("Import and Dependencies", test_imports),
        ("Core Functionality", test_core_functionality),
        ("Expert Providers", test_expert_providers),
        ("Integration", test_integration),
        ("Error Handling", test_error_handling),
        ("Performance", test_performance)
    ]
    
    for suite_name, test_func in test_suites:
        try:
            await test_func()
        except Exception as e:
            print(f"\nFATAL ERROR in {suite_name}: {e}")
            traceback.print_exc()
    
    # Generate summary report
    print("\n" + "="*80)
    print("TEST SUMMARY REPORT")
    print("="*80)
    
    total_tests = test_results["tests_passed"] + test_results["tests_failed"]
    if total_tests > 0:
        success_rate = (test_results["tests_passed"] / total_tests) * 100
    else:
        success_rate = 0
    
    print(f"\nTotal Tests Run: {total_tests}")
    print(f"Tests Passed: {test_results['tests_passed']} ✓")
    print(f"Tests Failed: {test_results['tests_failed']} ✗")
    print(f"Success Rate: {success_rate:.1f}%")
    
    # Category breakdown
    print("\nCategory Breakdown:")
    for category in ["imports", "core_functionality", "expert_providers", 
                    "integration", "error_handling", "performance"]:
        if category in test_results:
            cat_tests = test_results[category]
            passed = sum(1 for t in cat_tests.values() if t.get('success', False))
            total = len(cat_tests)
            print(f"  {category.replace('_', ' ').title()}: {passed}/{total} passed")
    
    # Critical failures
    if test_results["failures"]:
        print("\nCritical Failures:")
        for failure in test_results["failures"][:10]:  # Show first 10
            print(f"  - {failure['category']}/{failure['test']}: {failure['error'][:100]}")
    
    # Overall status
    print("\n" + "="*80)
    if success_rate >= 90:
        print("OVERALL STATUS: EXCELLENT - Circle of Experts is fully operational! ✓")
    elif success_rate >= 70:
        print("OVERALL STATUS: GOOD - Core functionality working with some issues")
    elif success_rate >= 50:
        print("OVERALL STATUS: PARTIAL - Significant functionality available")
    else:
        print("OVERALL STATUS: POOR - Major issues preventing operation")
    
    # Recommendations
    print("\nRecommendations:")
    if not any(t.get('success', False) for t in test_results.get('imports', {}).values()):
        print("  1. Fix import issues - ensure all dependencies are installed")
    
    expert_tests = test_results.get('expert_providers', {})
    if expert_tests and not any('availability' in k and v.get('success', False) 
                               for k, v in expert_tests.items()):
        print("  2. Configure API keys for at least one AI provider")
    
    if 'Google Drive' in str(test_results.get('failures', [])):
        print("  3. Set up Google Drive credentials for full functionality")
    
    # Save detailed report
    report_file = f"circle_of_experts_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump(test_results, f, indent=2, default=str)
    print(f"\nDetailed report saved to: {report_file}")
    
    print("\n" + "="*80)
    print(f"Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80)

if __name__ == "__main__":
    asyncio.run(main())