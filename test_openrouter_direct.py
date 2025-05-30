#!/usr/bin/env python3
"""
Test OpenRouter API directly
"""
import os
import asyncio
import httpx
from dotenv import load_dotenv

load_dotenv()

async def test_openrouter_api():
    """Test OpenRouter API directly"""
    api_key = os.getenv("OPENROUTER_API_KEY")
    
    if not api_key:
        print("❌ No OpenRouter API key found")
        return
        
    print(f"🔍 Testing OpenRouter API...")
    print(f"API Key: {api_key[:20]}...")
    
    # Test direct API call
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost:3000",
        "X-Title": "Circle of Experts Test"
    }
    
    # Simple test message
    data = {
        "model": "openrouter/auto",  # Let OpenRouter choose the model
        "messages": [
            {"role": "user", "content": "What is 2+2? Just give the number."}
        ],
        "max_tokens": 50,
        "temperature": 0.7
    }
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            print("\n📤 Sending request to OpenRouter...")
            response = await client.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers=headers,
                json=data
            )
            
            print(f"Status: {response.status_code}")
            print(f"Response: {response.text[:200]}")
            
            if response.status_code == 200:
                result = response.json()
                content = result['choices'][0]['message']['content']
                model = result.get('model', 'unknown')
                print(f"\n✅ SUCCESS!")
                print(f"Model used: {model}")
                print(f"Response: {content}")
            else:
                print(f"\n❌ ERROR: {response.status_code}")
                print(f"Details: {response.text}")
                
    except Exception as e:
        print(f"\n❌ Exception: {type(e).__name__}: {str(e)}")

async def test_openrouter_expert():
    """Test OpenRouter through expert system"""
    print("\n\n🔍 Testing OpenRouter Expert Client...")
    
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    
    from src.circle_of_experts.experts.openrouter_expert import OpenRouterExpertClient
    from src.circle_of_experts.models.query import ExpertQuery, QueryType, QueryPriority
    
    api_key = os.getenv("OPENROUTER_API_KEY")
    
    try:
        # Create client with longer timeout
        client = OpenRouterExpertClient(api_key=api_key)
        
        # Check health
        print("Checking health...")
        health = await client.health_check()
        print(f"Health check: {'✅ Healthy' if health else '❌ Unhealthy'}")
        
        # Create test query
        query = ExpertQuery(
            title="Test",
            content="What is the capital of France? Give a one word answer.",
            requester="test@example.com",
            query_type=QueryType.GENERAL,
            priority=QueryPriority.LOW
        )
        
        print("\n📤 Sending query through expert client...")
        response = await asyncio.wait_for(
            client.generate_response(query),
            timeout=30.0
        )
        
        if response:
            print(f"\n✅ Response received!")
            print(f"Content: {response.content[:100]}...")
            print(f"Confidence: {response.confidence}")
            print(f"Model: {response.metadata.get('model_used', 'unknown')}")
        else:
            print("❌ No response received")
            
    except asyncio.TimeoutError:
        print("⏱️ Timeout after 30 seconds")
    except Exception as e:
        print(f"❌ Error: {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    print("=" * 60)
    print("OPENROUTER API TEST")
    print("=" * 60)
    
    # Test direct API
    asyncio.run(test_openrouter_api())
    
    # Test expert client
    asyncio.run(test_openrouter_expert())