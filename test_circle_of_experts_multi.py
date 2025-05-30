#!/usr/bin/env python3
"""
Test Circle of Experts with multiple AI providers
"""
import os
import asyncio
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add src to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

async def test_multi_expert_consultation():
    """Test consultation with multiple experts"""
    print("Testing Circle of Experts with Multiple AI Providers...\n")
    
    try:
        from src.circle_of_experts.core.enhanced_expert_manager import EnhancedExpertManager
        from src.circle_of_experts.models.query import ExpertQuery, QueryType, QueryPriority
        
        # Create manager
        manager = EnhancedExpertManager()
        
        # Check available experts
        status = await manager.get_expert_status()
        print(f"✅ Expert Manager initialized")
        print(f"Total configured: {status['total_configured']}")
        print(f"Total available: {status['total_available']}")
        # Get available experts separately
        available_experts = await manager.get_available_experts()
        print(f"Available experts: {', '.join(available_experts)}\n")
        
        if status['total_available'] == 0:
            print("❌ No experts available. Please configure API keys.")
            return
            
        # Create a more complex query
        print("📤 Sending query to available experts...\n")
        
        result = await manager.consult_experts_with_ai(
            title="Architecture Design Question",
            content="""I'm building a real-time analytics system that needs to:
1. Process 100K events per second
2. Provide sub-second query latency
3. Handle both streaming and batch workloads
4. Scale horizontally

What architecture and technology stack would you recommend?""",
            requester="architect@example.com",
            query_type=QueryType.ARCHITECTURAL,
            priority=QueryPriority.HIGH,
            min_experts=1,
            max_experts=3,
            use_consensus=True
        )
        
        print("✅ Consultation complete!\n")
        
        # Display results
        print(f"Query ID: {result['query']['id']}")
        print(f"Status: {result['status']}")
        print(f"Total responses: {len(result['responses'])}")
        print(f"Consensus level: {result['aggregation']['consensus_level']}")
        print(f"Average confidence: {result['aggregation']['average_confidence']:.2f}\n")
        
        # Show each expert's response
        for i, response in enumerate(result['responses'], 1):
            print(f"--- Expert {i}: {response['expert_type']} ---")
            print(f"Confidence: {response['confidence']:.2f}")
            print(f"Response preview: {response['content'][:200]}...")
            print()
            
        # Show aggregated insights
        if result['aggregation']['common_themes']:
            print("🔍 Common Themes:")
            for theme in result['aggregation']['common_themes']:
                print(f"  - {theme}")
            print()
            
        if result['aggregation']['key_recommendations']:
            print("💡 Key Recommendations:")
            for rec in result['aggregation']['key_recommendations'][:5]:
                print(f"  - {rec}")
            print()
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

async def test_expert_health():
    """Test individual expert health checks"""
    print("\n=== Expert Health Check ===\n")
    
    try:
        from src.circle_of_experts.experts.expert_factory import ExpertFactory
        
        factory = ExpertFactory()
        
        # Test each configured expert
        experts_to_test = ["claude", "deepseek", "openrouter", "gemini"]
        
        for expert_name in experts_to_test:
            try:
                expert = await factory.create_expert(expert_name)
                if expert:
                    print(f"✅ {expert_name}: Available")
                else:
                    print(f"❌ {expert_name}: Not configured")
            except Exception as e:
                print(f"❌ {expert_name}: Error - {str(e)[:50]}...")
                
    except Exception as e:
        print(f"❌ Health check failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_multi_expert_consultation())
    asyncio.run(test_expert_health())