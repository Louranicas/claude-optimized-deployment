#!/usr/bin/env python3
"""
Simple test of Circle of Experts without Google Drive dependency
"""
import os
import asyncio
import sys

# Add src to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set DeepSeek API key
os.environ['DEEPSEEK_API_KEY'] = os.getenv('DEEPSEEK_API_KEY', 'mock-api-key-for-testing')
os.environ['LOG_LEVEL'] = 'INFO'

async def test_simple_query():
    """Test a simple query using OpenRouter"""
    print("Testing Circle of Experts with DeepSeek...\n")
    
    try:
        from src.circle_of_experts.experts.expert_factory import ExpertFactory
        from src.circle_of_experts.experts.commercial_experts import DeepSeekExpertClient
        from src.circle_of_experts.models.query import ExpertQuery, QueryType, QueryPriority
        from src.circle_of_experts.models.response import ExpertResponse, ExpertType
        
        # Create DeepSeek expert directly
        factory = ExpertFactory()
        expert = await factory.create_expert("deepseek")
        
        if expert:
            print("✅ DeepSeek expert created successfully!")
            
            # Create a simple query
            query = ExpertQuery(
                title="Math Question",
                content="What is 15 + 27? Please provide just the answer.",
                requester="test@example.com",
                query_type=QueryType.GENERAL,
                priority=QueryPriority.MEDIUM
            )
            
            # Get response from expert
            print(f"\n📤 Sending query: {query.content}")
            
            response = await expert.generate_response(query)
            
            if response:
                print(f"\n✅ Response received!")
                print(f"Expert: {response.expert_type.value}")
                print(f"Response: {response.content}")
                print(f"Confidence: {response.confidence:.2f}")
                if response.metadata and 'model_used' in response.metadata:
                    print(f"Model: {response.metadata['model_used']}")
            else:
                print("❌ No response received")
                
        else:
            print("❌ Failed to create DeepSeek expert")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_simple_query())