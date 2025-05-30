"""
Example usage of the Circle of Experts feature.

Demonstrates how to submit queries and collect responses from multiple AI experts.
"""

import asyncio
import os
from pathlib import Path
from datetime import datetime

from src.circle_of_experts import (
    ExpertManager,
    QueryType,
    QueryPriority,
    ExpertType
)


async def basic_consultation_example():
    """Basic example of consulting the circle of experts."""
    print("=== Basic Consultation Example ===\n")
    
    # Initialize the Expert Manager
    # You'll need to set GOOGLE_CREDENTIALS_PATH environment variable
    # or pass the credentials_path parameter
    manager = ExpertManager(
        credentials_path=os.getenv("GOOGLE_CREDENTIALS_PATH"),
        log_level="INFO"
    )
    
    # Submit a technical query
    result = await manager.consult_experts(
        title="Python Performance Optimization",
        content="""
        I have a Python application that processes large CSV files (1GB+).
        The current implementation uses pandas but is quite slow.
        
        What are the best practices for optimizing this type of workload?
        Should I consider using Rust extensions? What about parallel processing?
        
        Please provide specific recommendations with code examples.
        """,
        requester="developer@example.com",
        query_type=QueryType.OPTIMIZATION,
        priority=QueryPriority.HIGH,
        tags=["python", "performance", "csv", "big-data"],
        min_experts=2,  # Consult at least 2 experts
        max_experts=4,  # Consult up to 4 experts
        expert_timeout=300.0  # Timeout per expert (5 minutes)
    )
    
    print(f"Query Status: {result['status']}")
    print(f"Query ID: {result['query']['id']}")
    
    if result['status'] == 'completed':
        print(f"\nReceived {len(result['responses'])} responses")
        print(f"Average Confidence: {result['aggregation']['average_confidence']}")
        print(f"Consensus Level: {result['aggregation']['consensus_level']}")
        
        print("\nCommon Recommendations:")
        for rec in result['aggregation']['common_recommendations']:
            print(f"  - {rec}")


async def code_review_example():
    """Example of submitting code for expert review."""
    print("\n=== Code Review Example ===\n")
    
    manager = ExpertManager()
    
    # Code to review
    code_sample = """
import pandas as pd
import numpy as np

def process_large_csv(filename):
    # Read entire file into memory
    df = pd.read_csv(filename)
    
    # Process each row
    results = []
    for index, row in df.iterrows():
        # Complex calculation
        result = row['value1'] * row['value2'] + np.sqrt(row['value3'])
        results.append(result)
    
    # Save results
    df['result'] = results
    df.to_csv('output.csv', index=False)
    
    return df
"""
    
    # Submit for review
    result = await manager.submit_code_review(
        code=code_sample,
        language="python",
        requester="developer@example.com",
        focus_areas=[
            "Performance optimization",
            "Memory efficiency",
            "Best practices",
            "Error handling"
        ],
        min_experts=2,
        max_experts=3
    )
    
    print(f"Code Review Status: {result['status']}")
    
    if result['status'] == 'completed':
        print(f"\nExperts who reviewed: {result['aggregation']['experts']}")
        print("\nKey recommendations:")
        for rec in result['aggregation']['all_recommendations'][:5]:
            print(f"  - {rec}")


async def architecture_review_example():
    """Example of architecture design review."""
    print("\n=== Architecture Review Example ===\n")
    
    manager = ExpertManager()
    
    # Submit architecture for review
    result = await manager.submit_architecture_review(
        system_description="""
        We're building a real-time data processing pipeline that needs to:
        - Ingest data from multiple sources (APIs, databases, files)
        - Process and transform data in real-time
        - Store processed data in a data warehouse
        - Provide real-time analytics dashboard
        
        Expected volume: 1M events per minute
        Latency requirement: < 5 seconds end-to-end
        """,
        requirements=[
            "High availability (99.9% uptime)",
            "Horizontal scalability",
            "Cost-effective for variable workloads",
            "Support for multiple data formats",
            "Real-time monitoring and alerting"
        ],
        constraints=[
            "Must use open-source technologies",
            "Deploy on Kubernetes",
            "Budget: $10k/month for infrastructure"
        ],
        existing_stack={
            "languages": ["Python", "Go"],
            "databases": ["PostgreSQL", "Redis"],
            "infrastructure": ["Kubernetes", "AWS"]
        },
        requester="architect@example.com",
        min_experts=2,
        max_experts=4
    )
    
    print(f"Architecture Review Status: {result['status']}")
    
    if result['status'] == 'completed':
        print(f"\nConsensus Score: {result['aggregation']['consensus_level']}")
        print("\nTop recommendations from experts:")
        for i, rec in enumerate(result['aggregation']['common_recommendations'][:5], 1):
            print(f"  {i}. {rec}")


async def async_query_example():
    """Example of submitting query without waiting for responses."""
    print("\n=== Async Query Example ===\n")
    
    manager = ExpertManager()
    
    # Submit query without waiting
    result = await manager.consult_experts(
        title="Machine Learning Model Selection",
        content="""
        We need to build a recommendation system for our e-commerce platform.
        
        Requirements:
        - Handle 100M products
        - Real-time recommendations
        - Personalization based on user behavior
        - Cold start handling for new users
        
        What ML approaches would you recommend?
        """,
        requester="ml-engineer@example.com",
        query_type=QueryType.RESEARCH,
        min_experts=1,
        max_experts=2
    )
    
    print(f"Query submitted with ID: {result['query']['id']}")
    print("Query is being processed by experts...")
    
    # Later, check for responses
    await asyncio.sleep(30)  # Wait a bit
    
    status = await manager.get_query_status(result['query']['id'])
    print(f"\nCurrent status: {status['status']}")
    print(f"Responses received: {status['response_count']}")


async def batch_query_example():
    """Example of submitting multiple queries in batch."""
    print("\n=== Batch Query Example ===\n")
    
    manager = ExpertManager()
    
    # Create multiple queries
    queries = []
    
    # Query 1: Security review
    query1 = await manager.query_handler.create_query(
        title="Security Best Practices for API",
        content="What are the essential security measures for a public REST API?",
        requester="security@example.com",
        query_type=QueryType.REVIEW,
        priority=QueryPriority.HIGH
    )
    queries.append(query1)
    
    # Query 2: Performance optimization
    query2 = await manager.query_handler.create_query(
        title="Database Query Optimization",
        content="How to optimize complex JOIN queries in PostgreSQL?",
        requester="dba@example.com",
        query_type=QueryType.OPTIMIZATION
    )
    queries.append(query2)
    
    # Query 3: Technology selection
    query3 = await manager.query_handler.create_query(
        title="Message Queue Selection",
        content="Kafka vs RabbitMQ vs Redis Streams for our use case?",
        requester="architect@example.com",
        query_type=QueryType.RESEARCH
    )
    queries.append(query3)
    
    # Submit all queries in batch
    file_mappings = await manager.query_handler.submit_batch(queries)
    
    print(f"Submitted {len(file_mappings)} queries successfully")
    for query_id, file_id in file_mappings.items():
        print(f"  Query {query_id[:8]}... -> File {file_id}")


async def main():
    """Run all examples."""
    try:
        # Make sure you have set up Google Drive credentials
        if not os.getenv("GOOGLE_CREDENTIALS_PATH"):
            print("WARNING: GOOGLE_CREDENTIALS_PATH not set.")
            print("Please set it to your Google service account credentials file.")
            print("Example: export GOOGLE_CREDENTIALS_PATH=/path/to/credentials.json")
            print()
        
        # Run examples
        await basic_consultation_example()
        await code_review_example()
        await architecture_review_example()
        await async_query_example()
        await batch_query_example()
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
