#!/usr/bin/env python3
"""
Test Circle of Experts directly without Google Drive
"""
import os
import asyncio
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add src to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

async def test_direct_expert_consultation():
    """Test direct expert consultation without Drive dependency"""
    print("🎯 Testing Circle of Experts (Direct Mode)...\n")
    
    try:
        from src.circle_of_experts.experts.expert_factory import ExpertFactory
        from src.circle_of_experts.models.query import ExpertQuery, QueryType, QueryPriority
        
        # Create factory
        factory = ExpertFactory()
        
        # Check available experts
        available_experts = []
        expert_instances = {}
        
        for expert_name in ["claude", "deepseek", "openrouter", "gemini"]:
            try:
                expert = await factory.create_expert(expert_name)
                if expert:
                    available_experts.append(expert_name)
                    expert_instances[expert_name] = expert
                    print(f"✅ {expert_name}: Ready")
                else:
                    print(f"❌ {expert_name}: Not available")
            except Exception as e:
                print(f"❌ {expert_name}: {str(e)[:50]}...")
        
        print(f"\n📊 Total experts available: {len(available_experts)}")
        
        if not available_experts:
            print("❌ No experts available. Please configure API keys.")
            return
        
        # Create a test query
        query = ExpertQuery(
            title="Multi-Expert Consultation Test",
            content="""Compare the trade-offs between microservices and monolithic architectures 
for a startup building a real-time collaboration platform. Consider:
1. Development speed
2. Operational complexity
3. Scalability requirements
4. Team size (5 developers)""",
            requester="test@example.com",
            query_type=QueryType.ARCHITECTURAL,
            priority=QueryPriority.HIGH
        )
        
        print(f"\n📤 Sending query to {len(available_experts)} experts...\n")
        
        # Collect responses from all available experts
        responses = []
        tasks = []
        
        for expert_name, expert in expert_instances.items():
            task = asyncio.create_task(expert.generate_response(query))
            tasks.append((expert_name, task))
        
        # Wait for all responses
        for expert_name, task in tasks:
            try:
                response = await asyncio.wait_for(task, timeout=30.0)
                if response:
                    responses.append(response)
                    print(f"✅ {expert_name}: Response received ({len(response.content)} chars)")
                    print(f"   Confidence: {response.confidence:.2f}")
                    print(f"   Preview: {response.content[:100]}...\n")
            except asyncio.TimeoutError:
                print(f"⏱️ {expert_name}: Timeout")
            except Exception as e:
                print(f"❌ {expert_name}: Error - {str(e)[:100]}")
        
        print(f"\n📊 Total responses collected: {len(responses)}")
        
        if responses:
            # Calculate simple aggregation
            avg_confidence = sum(r.confidence for r in responses) / len(responses)
            
            print("\n🔍 Aggregated Analysis:")
            print(f"Average Confidence: {avg_confidence:.2f}")
            
            # Extract common themes manually
            print("\n💡 Response Summary:")
            for i, response in enumerate(responses, 1):
                print(f"\n--- Expert {i} ({response.expert_type.value}) ---")
                # Show first 200 chars of each response
                print(f"{response.content[:200]}...")
                
            # Show recommendations if available
            print("\n🎯 Recommendations from experts:")
            for response in responses:
                if response.recommendations:
                    print(f"\nFrom {response.expert_type.value}:")
                    for rec in response.recommendations[:2]:
                        print(f"  • {rec}")
                
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_direct_expert_consultation())