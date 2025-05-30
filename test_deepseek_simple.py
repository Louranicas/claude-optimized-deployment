#!/usr/bin/env python3
"""Simple DeepSeek API test."""

import os
import asyncio
import aiohttp
import json
from pathlib import Path

def load_env():
    """Load environment variables from .env file."""
    env_file = Path(__file__).parent / '.env'
    if env_file.exists():
        with open(env_file) as f:
            for line in f:
                if line.strip() and not line.startswith('#') and '=' in line:
                    key, _, value = line.partition('=')
                    os.environ[key.strip()] = value.strip()

async def test_deepseek_api():
    """Test DeepSeek API directly."""
    print("🚀 Testing DeepSeek API Integration")
    print("=" * 40)
    
    # Load environment
    load_env()
    
    # Get API key
    api_key = os.getenv('DEEPSEEK_API_KEY')
    if not api_key:
        print("❌ DEEPSEEK_API_KEY not found in environment")
        return False
    
    print(f"✅ API Key found: {api_key[:8]}...")
    
    # Test API connection
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    test_payload = {
        "model": "deepseek-chat",
        "messages": [
            {
                "role": "system",
                "content": "You are a helpful AI assistant specialized in software architecture and development."
            },
            {
                "role": "user", 
                "content": "Hello! Can you briefly explain what makes DeepSeek models good for reasoning tasks?"
            }
        ],
        "max_tokens": 150,
        "temperature": 0.7
    }
    
    try:
        print("🔗 Testing API connection...")
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://api.deepseek.com/chat/completions",
                headers=headers,
                json=test_payload,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as resp:
                print(f"📡 Response status: {resp.status}")
                
                if resp.status == 200:
                    data = await resp.json()
                    
                    # Extract response details
                    content = data["choices"][0]["message"]["content"]
                    usage = data.get("usage", {})
                    
                    print("✅ DeepSeek API test successful!")
                    print(f"📝 Response: {content}")
                    print(f"📊 Token usage: {usage}")
                    
                    # Test if response is reasonable
                    if len(content) > 50 and "deepseek" in content.lower():
                        print("✅ Response quality looks good")
                        return True
                    else:
                        print("⚠️ Response received but quality unclear")
                        return True
                        
                else:
                    error_text = await resp.text()
                    print(f"❌ API error ({resp.status}): {error_text}")
                    return False
                    
    except asyncio.TimeoutError:
        print("❌ API request timed out")
        return False
    except Exception as e:
        print(f"❌ API connection error: {e}")
        return False

async def test_deepseek_models():
    """Test different DeepSeek models."""
    print("\n🧠 Testing DeepSeek Model Selection...")
    
    api_key = os.getenv('DEEPSEEK_API_KEY')
    if not api_key:
        return False
    
    models_to_test = ["deepseek-chat", "deepseek-coder"]
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    for model in models_to_test:
        print(f"🔍 Testing {model}...")
        
        test_payload = {
            "model": model,
            "messages": [{"role": "user", "content": "Hello"}],
            "max_tokens": 10
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://api.deepseek.com/chat/completions",
                    headers=headers,
                    json=test_payload,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        print(f"✅ {model} - Available")
                    else:
                        print(f"❌ {model} - Status {resp.status}")
        except Exception as e:
            print(f"❌ {model} - Error: {e}")
    
    return True

async def main():
    """Run all tests."""
    try:
        # Test basic API
        basic_test = await test_deepseek_api()
        
        if basic_test:
            # Test models
            await test_deepseek_models()
            
            print("\n" + "=" * 40)
            print("🎉 DeepSeek API integration successful!")
            print("✅ Ready to add to Circle of Experts")
        else:
            print("\n❌ DeepSeek API integration failed")
            
    except Exception as e:
        print(f"💥 Test error: {e}")

if __name__ == "__main__":
    asyncio.run(main())