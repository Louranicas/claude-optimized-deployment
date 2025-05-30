#!/usr/bin/env python3
"""Simple test of DeepSeek integration."""

import os
import sys

# Add the project to path
sys.path.insert(0, '/mnt/c/Users/luke_/Desktop/My Programming/claude_optimized_deployment')

def test_env():
    """Test environment configuration."""
    print("🔍 Testing DeepSeek Environment Configuration...")
    
    api_key = os.getenv('DEEPSEEK_API_KEY')
    if api_key:
        print(f"✅ DeepSeek API key found: {api_key[:8]}...")
        return True
    else:
        print("❌ DeepSeek API key not found in environment")
        return False

def test_imports():
    """Test that DeepSeek can be imported."""
    print("\n📦 Testing DeepSeek Imports...")
    
    try:
        # Test expert registry import
        from src.circle_of_experts.experts.expert_factory import EXPERT_REGISTRY
        print("✅ Expert registry imported successfully")
        
        # Check if DeepSeek is registered
        if 'deepseek' in EXPERT_REGISTRY:
            config = EXPERT_REGISTRY['deepseek']
            print(f"✅ DeepSeek found in registry")
            print(f"   Priority: {config.priority.value}")
            print(f"   Cost per 1K tokens: ${config.cost_per_1k_tokens}")
            print(f"   Requires API key: {config.requires_api_key}")
            print(f"   Environment variable: {config.env_var_name}")
        else:
            print("❌ DeepSeek not found in registry")
            return False
        
        # Test DeepSeek client import
        from src.circle_of_experts.experts.commercial_experts import DeepSeekExpertClient
        print("✅ DeepSeekExpertClient imported successfully")
        
        # Test expert type enum
        from src.circle_of_experts.models.response import ExpertType
        if hasattr(ExpertType, 'DEEPSEEK'):
            print("✅ DEEPSEEK expert type exists")
        else:
            print("❌ DEEPSEEK expert type not found")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ Import error: {e}")
        return False

def test_client_creation():
    """Test DeepSeek client creation."""
    print("\n🔧 Testing DeepSeek Client Creation...")
    
    try:
        from src.circle_of_experts.experts.commercial_experts import DeepSeekExpertClient
        
        # Create client with API key
        api_key = os.getenv('DEEPSEEK_API_KEY')
        if not api_key:
            print("⚠️ Skipping client creation - no API key")
            return True
        
        client = DeepSeekExpertClient(api_key=api_key)
        print("✅ DeepSeek client created successfully")
        print(f"   Base URL: {client.base_url}")
        print(f"   Default model: {client.model}")
        print(f"   Available models: {list(client.model_selection.keys())}")
        
        return True
        
    except Exception as e:
        print(f"❌ Client creation error: {e}")
        return False

def main():
    """Run all tests."""
    print("🚀 DeepSeek Integration Simple Test")
    print("=" * 40)
    
    tests = [
        ("Environment Configuration", test_env),
        ("Import Tests", test_imports),
        ("Client Creation", test_client_creation),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"💥 {test_name}: ERROR - {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 40)
    print("📊 Test Results:")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {status} - {test_name}")
    
    print(f"\n📈 Overall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 DeepSeek integration looks good!")
    else:
        print("⚠️ Some issues found. Check output above.")

if __name__ == "__main__":
    main()