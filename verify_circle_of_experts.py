#!/usr/bin/env python3
"""
Verify Circle of Experts actual functionality
"""
import os
import asyncio
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add src to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

async def verify_experts():
    """Verify actual expert availability and functionality"""
    print("🔍 VERIFYING CIRCLE OF EXPERTS STATUS...\n")
    
    from src.circle_of_experts.experts.expert_factory import ExpertFactory
    from src.circle_of_experts.models.query import ExpertQuery, QueryType, QueryPriority
    
    factory = ExpertFactory()
    
    # Test each expert individually
    results = {
        "claude": {"configured": False, "working": False, "error": None},
        "deepseek": {"configured": False, "working": False, "error": None},
        "openrouter": {"configured": False, "working": False, "error": None},
        "gemini": {"configured": False, "working": False, "error": None},
        "gpt4": {"configured": False, "working": False, "error": None},
    }
    
    # Check API keys
    api_keys = {
        "claude": os.getenv("ANTHROPIC_API_KEY"),
        "deepseek": os.getenv("DEEPSEEK_API_KEY"),
        "openrouter": os.getenv("OPENROUTER_API_KEY"),
        "gemini": os.getenv("GOOGLE_GEMINI_API_KEY"),
        "gpt4": os.getenv("OPENAI_API_KEY"),
    }
    
    for name, key in api_keys.items():
        if key and not key.startswith("your_"):
            results[name]["configured"] = True
    
    # Test actual functionality
    test_query = ExpertQuery(
        title="Test",
        content="What is 2+2?",
        requester="test@example.com",
        query_type=QueryType.GENERAL,
        priority=QueryPriority.LOW
    )
    
    print("EXPERT STATUS:")
    print("-" * 50)
    
    for expert_name in results.keys():
        try:
            if results[expert_name]["configured"]:
                expert = await factory.create_expert(expert_name)
                if expert:
                    # Try to get a response
                    response = await asyncio.wait_for(
                        expert.generate_response(test_query), 
                        timeout=10.0
                    )
                    if response and response.content:
                        results[expert_name]["working"] = True
                        print(f"✅ {expert_name}: WORKING (responded with: {response.content[:30]}...)")
                    else:
                        print(f"⚠️  {expert_name}: CONFIGURED but no response")
                else:
                    print(f"❌ {expert_name}: CONFIGURED but failed to create")
            else:
                print(f"❌ {expert_name}: NO API KEY")
        except asyncio.TimeoutError:
            results[expert_name]["error"] = "Timeout"
            print(f"⏱️  {expert_name}: TIMEOUT")
        except Exception as e:
            results[expert_name]["error"] = str(e)[:50]
            print(f"❌ {expert_name}: ERROR - {str(e)[:50]}")
    
    # Summary
    print("\n" + "=" * 50)
    print("SUMMARY:")
    working_count = sum(1 for r in results.values() if r["working"])
    configured_count = sum(1 for r in results.values() if r["configured"])
    
    print(f"Total Configured: {configured_count}/5")
    print(f"Actually Working: {working_count}/5")
    
    # Check other issues
    print("\nKNOWN ISSUES:")
    
    # Google Drive
    google_creds = os.getenv("GOOGLE_CREDENTIALS_PATH")
    if google_creds:
        if os.path.exists(google_creds):
            print("✅ Google Drive credentials path exists")
        else:
            print("❌ Google Drive credentials file NOT FOUND at:", google_creds)
    
    # DeepSeek balance
    if results["deepseek"]["configured"] and not results["deepseek"]["working"]:
        if "balance" in str(results["deepseek"].get("error", "")).lower():
            print("⚠️  DeepSeek has insufficient balance")
    
    print("\nACTUAL FUNCTIONALITY:")
    if working_count >= 2:
        print("✅ Circle of Experts is FUNCTIONAL (multiple experts available)")
    elif working_count == 1:
        print("⚠️  Circle of Experts is PARTIALLY functional (only 1 expert)")
    else:
        print("❌ Circle of Experts is NOT functional (no working experts)")

if __name__ == "__main__":
    asyncio.run(verify_experts())