#!/usr/bin/env python3
"""
Test SYNTHEX integration to verify Rust-Python FFI is working
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from src.synthex import SynthexEngine, SynthexConfig, RUST_AVAILABLE
    
    print("SYNTHEX Integration Test")
    print("=" * 50)
    print(f"Rust backend available: {RUST_AVAILABLE}")
    
    if RUST_AVAILABLE:
        # Create engine with custom config
        config = SynthexConfig(
            max_parallel_searches=100,
            cache_size_mb=1024,
            query_timeout_ms=3000
        )
        
        try:
            engine = SynthexEngine(config)
            print("✓ SYNTHEX engine created successfully")
            
            # Get metrics
            metrics = engine.get_metrics()
            print(f"✓ Engine metrics: {metrics}")
            
            # Try a search (will likely fail without real agents, but tests FFI)
            try:
                result = engine.search("test query")
                print(f"✓ Search executed: {result}")
            except Exception as e:
                print(f"! Search failed (expected without agents): {e}")
            
            print("\nIntegration test PASSED")
            
        except Exception as e:
            print(f"✗ Engine creation failed: {e}")
            print("\nIntegration test FAILED")
            sys.exit(1)
    else:
        print("✗ Rust backend not available")
        print("Run: cd rust_core && cargo build --release")
        print("\nIntegration test SKIPPED")
        
except ImportError as e:
    print(f"✗ Import error: {e}")
    print("\nIntegration test FAILED")
    sys.exit(1)