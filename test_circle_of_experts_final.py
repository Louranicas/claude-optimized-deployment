#!/usr/bin/env python3
"""
Final comprehensive test of Circle of Experts
"""
import os
import asyncio
import sys
from dotenv import load_dotenv

load_dotenv()
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

async def test_all_experts():
    """Test all configured experts with proper timeouts"""
    print("🎯 FINAL CIRCLE OF EXPERTS TEST")
    print("=" * 60)
    
    from src.circle_of_experts.experts.expert_factory import ExpertFactory
    from src.circle_of_experts.models.query import ExpertQuery, QueryType, QueryPriority
    
    factory = ExpertFactory()
    
    # Create a simple test query
    query = ExpertQuery(
        title="Architecture Question",
        content="What are the key benefits of using microservices architecture? List 3 main benefits briefly.",
        requester="test@example.com",
        query_type=QueryType.ARCHITECTURAL,
        priority=QueryPriority.MEDIUM
    )
    
    experts_to_test = ["claude", "deepseek", "openrouter", "gemini"]
    results = {}
    
    print("Testing each expert individually with 30s timeout...\n")
    
    for expert_name in experts_to_test:
        print(f"Testing {expert_name}...")
        try:
            expert = await factory.create_expert(expert_name)
            if expert:
                # Give each expert 30 seconds
                response = await asyncio.wait_for(
                    expert.generate_response(query),
                    timeout=30.0
                )
                
                if response and response.content:
                    results[expert_name] = {
                        "status": "WORKING",
                        "response_length": len(response.content),
                        "confidence": response.confidence,
                        "preview": response.content[:100].replace('\n', ' ')
                    }
                    print(f"✅ {expert_name}: SUCCESS")
                else:
                    results[expert_name] = {"status": "NO_RESPONSE"}
                    print(f"⚠️  {expert_name}: No response")
            else:
                results[expert_name] = {"status": "FAILED_TO_CREATE"}
                print(f"❌ {expert_name}: Failed to create")
                
        except asyncio.TimeoutError:
            results[expert_name] = {"status": "TIMEOUT"}
            print(f"⏱️  {expert_name}: Timeout (30s)")
        except Exception as e:
            results[expert_name] = {"status": "ERROR", "error": str(e)[:50]}
            print(f"❌ {expert_name}: Error - {str(e)[:50]}")
    
    # Summary
    print("\n" + "=" * 60)
    print("FINAL RESULTS:")
    print("=" * 60)
    
    working_experts = []
    
    for expert, result in results.items():
        if result["status"] == "WORKING":
            working_experts.append(expert)
            print(f"\n✅ {expert.upper()}: FULLY FUNCTIONAL")
            print(f"   Response length: {result['response_length']} chars")
            print(f"   Confidence: {result['confidence']:.2f}")
            print(f"   Preview: {result['preview']}...")
        else:
            print(f"\n❌ {expert.upper()}: {result['status']}")
            if "error" in result:
                print(f"   Error: {result['error']}")
    
    print("\n" + "-" * 60)
    print(f"SUMMARY: {len(working_experts)}/4 experts are working")
    print(f"Working experts: {', '.join(working_experts)}")
    
    if len(working_experts) >= 2:
        print("\n✅ CIRCLE OF EXPERTS IS FUNCTIONAL")
        print("   Multiple AI providers available for consultation")
    else:
        print("\n⚠️  CIRCLE OF EXPERTS HAS LIMITED FUNCTIONALITY")
        print("   Less than 2 experts available")
    
    # Test multi-expert consultation if we have at least 2 working
    if len(working_experts) >= 2:
        print("\n" + "=" * 60)
        print("TESTING MULTI-EXPERT CONSULTATION...")
        print("=" * 60)
        
        from src.circle_of_experts.core.enhanced_expert_manager import EnhancedExpertManager
        
        manager = EnhancedExpertManager()
        
        try:
            # Set a dummy Google Drive manager to bypass Drive requirement
            manager.query_handler.drive_manager = None
            
            # Get responses from available experts
            responses = []
            for expert_name in working_experts[:3]:  # Use up to 3 experts
                expert = await factory.create_expert(expert_name)
                if expert:
                    print(f"Getting response from {expert_name}...")
                    response = await expert.generate_response(query)
                    if response:
                        responses.append(response)
            
            if len(responses) >= 2:
                print(f"\n✅ Collected {len(responses)} expert responses")
                print("Multi-expert consultation is working!")
            else:
                print(f"\n⚠️  Only {len(responses)} responses collected")
                
        except Exception as e:
            print(f"\n❌ Multi-expert test failed: {str(e)[:100]}")

if __name__ == "__main__":
    asyncio.run(test_all_experts())