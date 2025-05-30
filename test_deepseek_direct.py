#!/usr/bin/env python3
"""Direct test of DeepSeek integration without problematic imports."""

import os
import sys
from pathlib import Path

# Set up environment
env_file = Path(__file__).parent / '.env'
if env_file.exists():
    with open(env_file) as f:
        for line in f:
            if line.strip() and not line.startswith('#'):
                key, _, value = line.partition('=')
                os.environ[key.strip()] = value.strip()

def test_deepseek_key():
    """Test DeepSeek API key."""
    print("🔍 Testing DeepSeek API Key...")
    
    api_key = os.getenv('DEEPSEEK_API_KEY')
    if api_key:
        print(f"✅ DeepSeek API key found: {api_key[:8]}...")
        return True
    else:
        print("❌ DeepSeek API key not found")
        return False

def test_deepseek_client():
    """Test DeepSeek client directly."""
    print("\n🔧 Testing DeepSeek Client Creation...")
    
    try:
        # Add current directory to path
        current_dir = Path(__file__).parent
        sys.path.insert(0, str(current_dir))
        
        # Import just what we need
        sys.path.insert(0, str(current_dir / 'src' / 'circle_of_experts' / 'experts'))
        sys.path.insert(0, str(current_dir / 'src' / 'circle_of_experts' / 'models'))
        sys.path.insert(0, str(current_dir / 'src' / 'circle_of_experts' / 'utils'))
        
        # Import base dependencies first
        from response import ExpertResponse, ExpertType, ResponseStatus
        from query import ExpertQuery
        
        print("✅ Base models imported")
        
        # Import the base expert client
        from claude_expert import BaseExpertClient
        print("✅ Base expert client imported")
        
        # Now try to import DeepSeek directly
        api_key = os.getenv('DEEPSEEK_API_KEY')
        if not api_key:
            print("⚠️ No API key for actual client test")
            return True
        
        # Create a minimal DeepSeek test
        import aiohttp
        import asyncio
        import json
        
        async def test_deepseek_api():
            """Test DeepSeek API directly."""
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
            
            test_payload = {
                "model": "deepseek-chat",
                "messages": [{"role": "user", "content": "Hello, this is a test."}],
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
                            data = await resp.json()
                            content = data["choices"][0]["message"]["content"]
                            print(f"✅ DeepSeek API test successful")
                            print(f"📝 Response: {content}")
                            return True
                        else:
                            error_text = await resp.text()
                            print(f"❌ DeepSeek API error ({resp.status}): {error_text}")
                            return False
            except Exception as e:
                print(f"❌ DeepSeek API connection error: {e}")
                return False
        
        # Run the async test
        result = asyncio.run(test_deepseek_api())
        return result
        
    except Exception as e:
        print(f"❌ Error testing DeepSeek client: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run tests."""
    print("🚀 DeepSeek Direct Integration Test")
    print("=" * 40)
    
    # Test API key
    key_test = test_deepseek_key()
    
    if key_test:
        # Test API connection
        api_test = test_deepseek_client()
        
        if api_test:
            print("\n🎉 DeepSeek integration is working!")
            print("✅ API key configured")
            print("✅ API connection successful")
        else:
            print("\n⚠️ API key found but connection failed")
    else:
        print("\n❌ No API key found")

if __name__ == "__main__":
    main()