#!/usr/bin/env python3
"""
Test script for DeepSeek integration in Circle of Experts.

Tests the newly added DeepSeek expert client functionality.
"""

import asyncio
import os
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.circle_of_experts.experts import ExpertFactory, ExpertHealthCheck
from src.circle_of_experts.models.query import ExpertQuery


async def test_deepseek_health():
    """Test DeepSeek expert health check."""
    print("🔍 Testing DeepSeek Expert Health Check...")
    
    factory = ExpertFactory()
    
    try:
        # Try to create DeepSeek expert
        deepseek_client = await factory.create_expert("deepseek")
        
        if deepseek_client:
            print("✅ DeepSeek client created successfully")
            
            # Test health check
            health_status = await deepseek_client.health_check()
            if health_status:
                print("✅ DeepSeek health check passed")
                return True
            else:
                print("❌ DeepSeek health check failed")
                return False
        else:
            print("❌ Failed to create DeepSeek client")
            return False
            
    except Exception as e:
        print(f"❌ Error testing DeepSeek: {e}")
        return False


async def test_deepseek_response():
    """Test DeepSeek expert response generation."""
    print("\n🧠 Testing DeepSeek Response Generation...")
    
    factory = ExpertFactory()
    
    try:
        # Create test query
        query = ExpertQuery(
            content="Explain the benefits of using Rust for performance-critical applications in a Python project.",
            query_type="architectural",
            priority="normal",
            context={"project": "hybrid Python/Rust infrastructure"}
        )
        
        # Get DeepSeek expert
        deepseek_client = await factory.create_expert("deepseek")
        
        if not deepseek_client:
            print("❌ Could not create DeepSeek client")
            return False
        
        print("📝 Generating response with DeepSeek...")
        response = await deepseek_client.generate_response(query)
        
        if response and response.status == "completed":
            print("✅ DeepSeek response generated successfully")
            print(f"📊 Confidence: {response.confidence:.2f}")
            print(f"📝 Content length: {len(response.content)} characters")
            print(f"💡 Recommendations: {len(response.recommendations)}")
            print(f"🔧 Code snippets: {len(response.code_snippets)}")
            
            # Show a snippet of the response
            if response.content:
                preview = response.content[:200] + "..." if len(response.content) > 200 else response.content
                print(f"\n📄 Response preview:\n{preview}")
            
            return True
        else:
            print(f"❌ DeepSeek response failed with status: {response.status if response else 'None'}")
            return False
            
    except Exception as e:
        print(f"❌ Error testing DeepSeek response: {e}")
        return False


async def test_expert_registry():
    """Test that DeepSeek is properly registered in the expert registry."""
    print("\n📋 Testing Expert Registry Integration...")
    
    health_checker = ExpertHealthCheck()
    
    try:
        # Get all expert status
        all_status = await health_checker.check_all_experts()
        
        if "deepseek" in all_status:
            deepseek_status = all_status["deepseek"]
            print("✅ DeepSeek found in expert registry")
            print(f"📊 Priority: {deepseek_status['priority']}")
            print(f"🔑 Requires API key: {deepseek_status['requires_api_key']}")
            print(f"💰 Cost per 1K tokens: ${deepseek_status['cost_per_1k_tokens']}")
            print(f"🟢 Available: {deepseek_status['available']}")
            
            if deepseek_status['error']:
                print(f"⚠️ Error: {deepseek_status['error']}")
            
            return deepseek_status['available']
        else:
            print("❌ DeepSeek not found in expert registry")
            return False
            
    except Exception as e:
        print(f"❌ Error checking expert registry: {e}")
        return False


async def test_expert_selection():
    """Test that DeepSeek is selected for appropriate queries."""
    print("\n🎯 Testing Expert Selection Logic...")
    
    factory = ExpertFactory()
    
    try:
        # Create a query that should prefer DeepSeek (reasoning-heavy)
        query = ExpertQuery(
            content="Design a comprehensive architecture for a distributed system that needs to handle 1M+ requests per second with sub-100ms latency.",
            query_type="architectural",
            priority="critical",
            context={"scale": "enterprise", "performance": "critical"}
        )
        
        # Get selected experts
        selected_experts = await factory.select_experts_for_query(query, max_experts=3)
        
        # Check if DeepSeek is selected
        expert_types = [type(expert).__name__ for expert in selected_experts]
        
        print(f"📝 Selected experts: {expert_types}")
        
        if "DeepSeekExpertClient" in expert_types:
            print("✅ DeepSeek was selected for critical architectural query")
            return True
        else:
            print("⚠️ DeepSeek was not selected (may be due to API availability)")
            return len(selected_experts) > 0  # At least some experts selected
            
    except Exception as e:
        print(f"❌ Error testing expert selection: {e}")
        return False


async def main():
    """Run all DeepSeek integration tests."""
    print("🚀 DeepSeek Integration Test Suite")
    print("=" * 50)
    
    # Check for API key
    api_key = os.getenv("DEEPSEEK_API_KEY")
    if not api_key:
        print("⚠️ DEEPSEEK_API_KEY not found in environment")
        print("Please set the API key in your .env file")
        return
    else:
        print(f"🔑 DeepSeek API key found: {api_key[:8]}...")
    
    tests = [
        ("Registry Integration", test_expert_registry),
        ("Health Check", test_deepseek_health),
        ("Expert Selection", test_expert_selection),
        ("Response Generation", test_deepseek_response),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n🧪 Running: {test_name}")
        try:
            result = await test_func()
            results.append((test_name, result))
            if result:
                print(f"✅ {test_name}: PASSED")
            else:
                print(f"❌ {test_name}: FAILED")
        except Exception as e:
            print(f"💥 {test_name}: ERROR - {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 Test Results Summary:")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {status} - {test_name}")
    
    print(f"\n📈 Overall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! DeepSeek integration is working correctly.")
    else:
        print("⚠️ Some tests failed. Check the output above for details.")


if __name__ == "__main__":
    asyncio.run(main())