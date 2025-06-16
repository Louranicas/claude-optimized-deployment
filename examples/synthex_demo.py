#!/usr/bin/env python3
"""
SYNTHEX Demo - High-speed AI-native search engine
"""

import asyncio
import json
import time
from datetime import datetime

from src.synthex import (
    SynthexEngine,
    SynthexMcpServer,
    SynthexConfig,
    WebSearchAgent,
    DatabaseSearchAgent,
    ApiSearchAgent,
)
from src.synthex.engine import QueryOptions


async def demo_basic_search():
    """Demonstrate basic search functionality"""
    print("\n=== SYNTHEX Basic Search Demo ===\n")
    
    # Create engine with default config
    engine = SynthexEngine()
    await engine.initialize()
    
    # Simple search
    query = "quantum computing applications"
    print(f"Searching for: {query}")
    
    start_time = time.time()
    result = await engine.search(query)
    elapsed = time.time() - start_time
    
    print(f"\nResults found: {result.total_results}")
    print(f"Execution time: {result.execution_time_ms}ms")
    print(f"Total time: {elapsed:.2f}s")
    
    # Display top results
    print("\nTop 5 results:")
    for i, item in enumerate(result.results[:5]):
        print(f"\n{i+1}. {item.get('title', 'Untitled')}")
        print(f"   Score: {item.get('score', 0):.3f}")
        print(f"   Source: {item.get('_agent', 'unknown')}")
        print(f"   Snippet: {item.get('snippet', '')[:100]}...")
    
    await engine.shutdown()


async def demo_parallel_search():
    """Demonstrate parallel search capabilities"""
    print("\n=== SYNTHEX Parallel Search Demo ===\n")
    
    engine = SynthexEngine()
    await engine.initialize()
    
    queries = [
        "machine learning optimization techniques",
        "distributed systems architecture",
        "blockchain consensus mechanisms",
        "natural language processing models",
        "computer vision algorithms",
    ]
    
    print(f"Executing {len(queries)} searches in parallel...")
    
    start_time = time.time()
    
    # Execute all searches in parallel
    tasks = [engine.search(q) for q in queries]
    results = await asyncio.gather(*tasks)
    
    elapsed = time.time() - start_time
    
    total_results = sum(r.total_results for r in results)
    avg_time = sum(r.execution_time_ms for r in results) / len(results)
    
    print(f"\nTotal results: {total_results}")
    print(f"Average execution time: {avg_time:.0f}ms")
    print(f"Total parallel time: {elapsed:.2f}s")
    print(f"Speedup factor: {len(queries):.1f}x")
    
    await engine.shutdown()


async def demo_filtered_search():
    """Demonstrate search with filters and options"""
    print("\n=== SYNTHEX Filtered Search Demo ===\n")
    
    engine = SynthexEngine()
    await engine.initialize()
    
    # Search with specific options
    options = QueryOptions(
        max_results=50,
        timeout_ms=3000,
        sources=["web", "knowledge_base"],
        filters={
            "language": "en",
            "date_range": "2024-01-01:2024-12-31"
        }
    )
    
    query = "AI safety research"
    print(f"Searching for: {query}")
    print(f"Options: {options}")
    
    result = await engine.search(query, options)
    
    print(f"\nResults: {result.total_results}")
    print(f"Sources searched: {result.metadata.get('sources_searched', [])}")
    
    await engine.shutdown()


async def demo_mcp_server():
    """Demonstrate MCP server integration"""
    print("\n=== SYNTHEX MCP Server Demo ===\n")
    
    # Create MCP server
    server = SynthexMcpServer(name="synthex_demo")
    
    # Start server
    await server.start()
    
    # Simulate MCP tool calls
    print("Available tools:")
    for tool in server.tools.values():
        print(f"- {tool.name}: {tool.description}")
    
    # Execute search through MCP
    print("\nExecuting search through MCP...")
    result = await server.tools["search"].handler({
        "query": "renewable energy innovations",
        "max_results": 10
    })
    
    print(f"Results: {result.get('total_results', 0)}")
    
    # Get agent status
    print("\nGetting agent status...")
    status = await server.tools["get_agent_status"].handler({})
    
    for agent, info in status.get("agents", {}).items():
        print(f"- {agent}: {'✓' if info['healthy'] else '✗'}")
    
    await server.stop()


async def demo_custom_agent():
    """Demonstrate custom agent registration"""
    print("\n=== SYNTHEX Custom Agent Demo ===\n")
    
    config = SynthexConfig()
    config.enable_api_search = True
    
    engine = SynthexEngine(config)
    await engine.initialize()
    
    # Create and configure API agent
    api_agent = ApiSearchAgent(config.api_config)
    
    # Register custom endpoint
    api_agent.register_endpoint(
        name="github",
        base_url="https://api.github.com",
        search_path="/search/repositories",
        query_param="q",
        extra_params={"sort": "stars", "order": "desc"},
        results_path="items",
        title_field="full_name",
        content_field="description",
        score_field="stargazers_count"
    )
    
    # Register agent with engine
    await engine.register_agent("github_api", api_agent)
    
    # Search using custom agent
    query = "rust async runtime"
    print(f"Searching GitHub for: {query}")
    
    options = QueryOptions(sources=["github_api"])
    result = await engine.search(query, options)
    
    print(f"\nFound {result.total_results} repositories")
    
    await engine.shutdown()


async def benchmark_performance():
    """Benchmark SYNTHEX performance"""
    print("\n=== SYNTHEX Performance Benchmark ===\n")
    
    engine = SynthexEngine()
    await engine.initialize()
    
    # Warm up
    await engine.search("test query")
    
    # Single query benchmark
    iterations = 10
    query = "artificial intelligence applications in healthcare"
    
    print(f"Running {iterations} iterations...")
    times = []
    
    for i in range(iterations):
        start = time.time()
        result = await engine.search(query)
        elapsed = time.time() - start
        times.append(elapsed)
        print(f"  Iteration {i+1}: {elapsed:.3f}s ({result.total_results} results)")
    
    avg_time = sum(times) / len(times)
    min_time = min(times)
    max_time = max(times)
    
    print(f"\nPerformance Summary:")
    print(f"  Average: {avg_time:.3f}s")
    print(f"  Min: {min_time:.3f}s")
    print(f"  Max: {max_time:.3f}s")
    print(f"  Queries/sec: {1/avg_time:.1f}")
    
    # Parallel benchmark
    print(f"\nParallel performance (100 concurrent queries)...")
    
    start = time.time()
    tasks = [engine.search(f"{query} {i}") for i in range(100)]
    results = await asyncio.gather(*tasks)
    elapsed = time.time() - start
    
    total_results = sum(r.total_results for r in results)
    
    print(f"  Total time: {elapsed:.2f}s")
    print(f"  Queries/sec: {100/elapsed:.1f}")
    print(f"  Total results: {total_results}")
    
    await engine.shutdown()


async def main():
    """Run all demos"""
    demos = [
        demo_basic_search,
        demo_parallel_search,
        demo_filtered_search,
        demo_mcp_server,
        demo_custom_agent,
        benchmark_performance,
    ]
    
    for demo in demos:
        try:
            await demo()
        except Exception as e:
            print(f"\n❌ Demo failed: {e}")
        
        # Pause between demos
        await asyncio.sleep(1)
    
    print("\n=== SYNTHEX Demo Complete ===")
    print("\nSYNTHEX is designed for AI agents, not humans.")
    print("It provides high-speed parallel search across multiple sources")
    print("with an AI-native interface optimized for synthetic beings.")


if __name__ == "__main__":
    asyncio.run(main())