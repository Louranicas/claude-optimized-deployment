#!/usr/bin/env python3
"""
Circle of Experts with Rust Acceleration Example
================================================

This example demonstrates how to use the Rust-accelerated Circle of Experts
implementation for improved performance on large-scale consensus operations.

Key features demonstrated:
- Rust-powered parallel consensus computation
- High-performance similarity calculations
- Efficient pattern analysis and insight extraction
- Seamless Python integration with PyO3
"""

import asyncio
import time
from typing import List, Dict, Any
import os
import sys

# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.circle_of_experts import ExpertManager, Query, QueryType

# Try to import Rust acceleration (will be available after building)
try:
    import code_rust_core
    RUST_AVAILABLE = True
    print("✅ Rust acceleration available!")
except ImportError:
    RUST_AVAILABLE = False
    print("⚠️  Rust acceleration not available. Run 'make rust-build' to enable.")


async def compare_performance():
    """Compare performance between Python and Rust implementations."""
    
    # Initialize expert manager
    manager = ExpertManager()
    
    # Create a complex query that benefits from parallel processing
    query = Query(
        content="""
        Analyze the following aspects of implementing a high-performance 
        distributed system architecture:
        
        1. Consensus algorithms for distributed state management
        2. Network partition tolerance strategies
        3. Data consistency models (eventual vs strong)
        4. Performance optimization techniques
        5. Monitoring and observability patterns
        
        Provide detailed technical analysis with specific implementation
        recommendations, trade-offs, and real-world examples.
        """,
        query_type=QueryType.TECHNICAL_ANALYSIS,
        context={
            "domain": "distributed systems",
            "scale": "large",
            "requirements": ["high availability", "low latency", "fault tolerance"]
        }
    )
    
    # Get responses from multiple experts
    print("\n🤖 Consulting multiple AI experts...")
    start_time = time.time()
    
    responses = await manager.query_experts(
        query,
        expert_names=["claude", "gpt4", "gemini", "deepseek", "mixtral"]
    )
    
    query_time = time.time() - start_time
    print(f"✅ Received {len(responses)} expert responses in {query_time:.2f}s")
    
    if not responses:
        print("❌ No responses received. Check your API keys.")
        return
    
    # Test Python implementation
    print("\n🐍 Processing with Python implementation...")
    start_time = time.time()
    
    # Simulate Python consensus processing
    python_consensus = await process_consensus_python(responses)
    
    python_time = time.time() - start_time
    print(f"✅ Python processing completed in {python_time:.2f}s")
    
    # Test Rust implementation if available
    if RUST_AVAILABLE:
        print("\n🦀 Processing with Rust implementation...")
        start_time = time.time()
        
        rust_consensus = process_consensus_rust(responses)
        
        rust_time = time.time() - start_time
        print(f"✅ Rust processing completed in {rust_time:.2f}s")
        
        # Calculate speedup
        speedup = python_time / rust_time
        print(f"\n⚡ Rust speedup: {speedup:.2f}x faster")
        
        # Display Rust consensus results
        print("\n📊 Rust Consensus Results:")
        print(f"Confidence Score: {rust_consensus.confidence_score:.2%}")
        print(f"Key Insights: {len(rust_consensus.key_insights)}")
        for i, insight in enumerate(rust_consensus.key_insights[:3], 1):
            print(f"  {i}. {insight}")
        
        if rust_consensus.dissenting_opinions:
            print(f"\nDissenting Opinions: {len(rust_consensus.dissenting_opinions)}")
    
    # Display consensus
    print("\n📋 Final Consensus:")
    print("-" * 80)
    if RUST_AVAILABLE:
        print(rust_consensus.consensus_text[:500] + "...")
    else:
        print(python_consensus["text"][:500] + "...")


async def process_consensus_python(responses: List[Any]) -> Dict[str, Any]:
    """Simulate Python consensus processing (simplified)."""
    
    # Extract response contents
    contents = [r.content for r in responses]
    
    # Simple consensus: take highest confidence response
    highest_confidence_idx = max(
        range(len(responses)), 
        key=lambda i: responses[i].confidence
    )
    
    consensus_text = responses[highest_confidence_idx].content
    avg_confidence = sum(r.confidence for r in responses) / len(responses)
    
    return {
        "text": consensus_text,
        "confidence": avg_confidence,
        "insights": ["Python-based insight extraction"]
    }


def process_consensus_rust(responses: List[Any]) -> Any:
    """Process consensus using Rust acceleration."""
    
    # Convert responses to Rust format
    rust_responses = [
        {
            "expert_name": r.expert_name,
            "content": r.content,
            "confidence": r.confidence,
            "metadata": r.metadata,
            "timestamp": int(time.time())
        }
        for r in responses
    ]
    
    # Configure Rust processing
    config = code_rust_core.circle_of_experts.RustCircleConfig(
        min_consensus_threshold=0.7,
        enable_parallel_processing=True,
        similarity_algorithm="cosine"
    )
    
    # Process with Rust
    return code_rust_core.circle_of_experts.rust_process_expert_responses(
        rust_responses,
        config
    )


async def benchmark_similarity_algorithms():
    """Benchmark different similarity algorithms in Rust."""
    
    if not RUST_AVAILABLE:
        print("⚠️  Rust acceleration required for this benchmark")
        return
    
    print("\n📊 Benchmarking Similarity Algorithms:")
    print("-" * 50)
    
    text1 = "The quick brown fox jumps over the lazy dog" * 10
    text2 = "The fast brown fox leaps over the sleepy dog" * 10
    
    algorithms = ["cosine", "jaccard", "levenshtein"]
    
    for algo in algorithms:
        start = time.perf_counter()
        
        # Run similarity calculation 1000 times
        for _ in range(1000):
            similarity = code_rust_core.circle_of_experts.rust_compute_text_similarity(
                text1, text2, algo
            )
        
        elapsed = time.perf_counter() - start
        print(f"{algo.capitalize():12} - {elapsed:.3f}s (1000 iterations)")


async def main():
    """Run the Rust-accelerated Circle of Experts example."""
    
    print("🚀 Circle of Experts - Rust Acceleration Demo")
    print("=" * 50)
    
    # Check for required environment variables
    required_vars = ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"]
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        print(f"\n⚠️  Missing environment variables: {', '.join(missing_vars)}")
        print("Set these to enable full expert consultation.")
    
    # Run performance comparison
    await compare_performance()
    
    # Run similarity benchmarks if Rust is available
    if RUST_AVAILABLE:
        await benchmark_similarity_algorithms()
    
    print("\n✅ Demo completed!")
    
    if not RUST_AVAILABLE:
        print("\n💡 To enable Rust acceleration:")
        print("   1. Install Rust: https://rustup.rs/")
        print("   2. Run: make rust-build")
        print("   3. Re-run this example")


if __name__ == "__main__":
    asyncio.run(main())