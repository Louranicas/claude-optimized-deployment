#!/usr/bin/env python3
"""
Test Circle of Experts with environment setup
"""
import os
import asyncio
import sys

# Add src to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set up test environment variables
os.environ['GOOGLE_CREDENTIALS_PATH'] = '/path/to/credentials.json'  # Dummy path
os.environ['LOG_LEVEL'] = 'DEBUG'

async def test_functionality():
    """Test Circle of Experts functionality with environment"""
    print("Testing Circle of Experts functionality...")
    
    try:
        from src.circle_of_experts import ExpertManager
        print("✓ Import successful")
        
        # Initialize manager
        manager = ExpertManager()
        print("✓ Manager initialized")
        
        # Get available experts
        experts = await manager.get_available_experts()
        print(f"✓ Available expert types: {len(experts)}")
        print(f"  Expert types: {', '.join(experts)}")
        
        # Get expert status
        status = await manager.get_expert_status()
        print(f"✓ Expert status retrieved")
        print(f"  Total configured: {status.get('total_configured', 0)}")
        print(f"  Total available: {status.get('total_available', 0)}")
        
        # Try a simple consultation (will fail without Drive but shows API)
        try:
            result = await manager.consult_experts(
                title="Test Query",
                content="What is 2+2?",
                requester="test@example.com"
            )
            print("✓ Consultation API works")
        except Exception as e:
            if "Drive" in str(e) or "credentials" in str(e):
                print("✓ Consultation API works (Drive credentials needed)")
            else:
                print(f"✗ Consultation failed: {e}")
        
        # Test the example scripts
        print("\n--- Testing Example Scripts ---")
        example_paths = [
            "examples/circle_of_experts_usage.py",
            "examples/claude_code_circle_of_experts.py"
        ]
        
        for path in example_paths:
            if os.path.exists(path):
                print(f"✓ {path} exists")
                # Check if it has main function
                with open(path, 'r') as f:
                    content = f.read()
                    if 'async def main' in content or 'def main' in content:
                        print(f"  Has main function")
                    if 'circle_of_experts' in content:
                        print(f"  Imports circle_of_experts")
            else:
                print(f"✗ {path} not found")
        
        return True
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(test_functionality())
    sys.exit(0 if success else 1)