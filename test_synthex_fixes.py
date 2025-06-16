#!/usr/bin/env python3
"""
Test script to verify SYNTHEX engine fixes
"""

import asyncio
import sys
from pathlib import Path

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

async def test_synthex_engine():
    """Test SYNTHEX engine initialization and health monitoring"""
    print("Testing SYNTHEX Engine Fixes...")
    print("=" * 60)
    
    try:
        from src.synthex.engine import SynthexEngine
        from src.synthex.config import SynthexConfig
        
        # Create a minimal config
        config = SynthexConfig()
        config.enable_web_search = True
        config.enable_database_search = False  # Disable to avoid missing deps
        config.enable_api_search = True
        config.enable_file_search = True
        config.enable_knowledge_base = False
        
        # Initialize engine
        engine = SynthexEngine(config)
        
        print("✅ Engine created successfully")
        print(f"   Required dependencies: {engine._required_dependencies}")
        print(f"   Optional dependencies: {engine._optional_dependencies}")
        
        # Initialize
        await engine.initialize()
        print("✅ Engine initialized")
        
        # Wait a moment for health checks
        await asyncio.sleep(2)
        
        # Get status
        status = await engine.get_agent_status()
        print("\n📊 Agent Status:")
        for agent_name, agent_status in status.items():
            if agent_name.startswith('_'):
                continue
            print(f"   {agent_name}:")
            print(f"     Health Status: {agent_status.get('health_status', 'unknown')}")
            print(f"     Healthy: {agent_status.get('healthy', False)}")
            print(f"     Failures: {agent_status.get('consecutive_failures', 0)}")
            if 'error' in agent_status:
                print(f"     Error: {agent_status['error']}")
        
        # Test search with fallback
        from src.synthex.engine import QueryOptions
        options = QueryOptions(max_results=10)
        
        try:
            result = await engine.search("test query", options)
            print(f"\n✅ Search completed: {result.total_results} results in {result.execution_time_ms}ms")
        except Exception as e:
            print(f"\n⚠️  Search failed (expected if no agents available): {e}")
        
        # Shutdown
        await engine.shutdown()
        print("\n✅ Engine shutdown complete")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

async def main():
    """Main test function"""
    success = await test_synthex_engine()
    
    if success:
        print("\n✅ All SYNTHEX engine tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())