"""
Optimized Circle of Experts usage for Claude Code tool calls.

This example demonstrates the streamlined interface for AI consultations.
"""

import asyncio
import os
from typing import Dict, Any

from src.circle_of_experts import EnhancedExpertManager


async def claude_code_quick_consult():
    """
    Quick consultation optimized for Claude Code.
    
    Minimal configuration required - just pass the query.
    """
    print("=== Claude Code Quick Consultation ===\n")
    
    # Initialize with enhanced manager
    manager = EnhancedExpertManager()
    
    # Simple query - auto-detects type and configures experts
    result = await manager.quick_consult(
        content="""
How can I optimize this Python function for better performance?

```python
def process_large_list(data):
    result = []
    for item in data:
        if item % 2 == 0:
            result.append(item ** 2)
    return result
```

The function processes lists with millions of elements.
"""
    )
    
    print(f"Query ID: {result['query_id']}")
    print(f"Consulted {result['expert_count']} experts: {', '.join(result['experts'])}")
    print(f"Consensus Level: {result['consensus']}")
    print("\nTop Recommendations:")
    for i, rec in enumerate(result['recommendations'][:3], 1):
        print(f"{i}. {rec}")


async def check_expert_availability():
    """Check which experts are currently available."""
    print("\n=== Expert Availability Check ===\n")
    
    manager = EnhancedExpertManager()
    status = await manager.get_expert_status()
    
    print(f"Total Experts Configured: {status['total_configured']}")
    print(f"Currently Available: {status['total_available']}")
    print("\nBy Priority:")
    for priority, experts in status['by_priority'].items():
        if experts:
            print(f"  {priority}: {', '.join(experts)}")
    
    print(f"\nFree Experts: {', '.join(status['free_experts'])}")
    print(f"Paid Experts: {', '.join(status['paid_experts'])}")
    
    print("\nRecommendations:")
    for rec in status['recommended_setup']:
        print(f"  - {rec}")


async def cost_estimation_example():
    """Estimate costs before running a query."""
    print("\n=== Cost Estimation ===\n")
    
    manager = EnhancedExpertManager()
    
    query_content = """
    Design a microservices architecture for an e-commerce platform that needs to:
    - Handle 1M+ daily active users
    - Process payments securely
    - Manage inventory in real-time
    - Provide personalized recommendations
    - Support multiple currencies and languages
    
    Include technology stack recommendations and deployment strategy.
    """
    
    costs = await manager.estimate_query_cost(query_content, expert_count=3)
    
    print("Estimated Costs:")
    for expert, cost in costs['per_expert'].items():
        print(f"  {expert}: ${cost:.4f}")
    print(f"\nTotal Estimated Cost: ${costs['total_estimated']:.4f}")
    print(f"Estimated Tokens: {costs['tokens_estimated']}")


async def specialized_consultation():
    """
    Specialized consultation with specific expert configuration.
    
    Shows how to customize expert selection for specific needs.
    """
    print("\n=== Specialized Consultation ===\n")
    
    # Configure specific experts for code review
    code_experts = ["claude-opus", "gpt4-turbo", "ollama-codellama"]
    
    manager = EnhancedExpertManager(preferred_experts=code_experts)
    
    result = await manager.consult_experts_with_ai(
        title="Security Review: Authentication System",
        content="""
Please review this authentication implementation for security vulnerabilities:

```python
import hashlib
import secrets

class AuthSystem:
    def __init__(self):
        self.users = {}
        self.sessions = {}
    
    def register(self, username, password):
        # Hash password with salt
        salt = secrets.token_hex(16)
        pwd_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        self.users[username] = {
            'hash': pwd_hash,
            'salt': salt
        }
    
    def login(self, username, password):
        if username not in self.users:
            return None
        
        user = self.users[username]
        pwd_hash = hashlib.sha256((password + user['salt']).encode()).hexdigest()
        
        if pwd_hash == user['hash']:
            session_token = secrets.token_urlsafe(32)
            self.sessions[session_token] = username
            return session_token
        return None
```

Focus on:
1. Cryptographic security
2. Session management
3. Timing attacks
4. Best practices
""",
        requester="security_team",
        query_type="review",
        priority="high",
        tags=["security", "authentication", "code-review"],
        min_experts=3,  # Get at least 3 opinions for security
        max_experts=4,
        expert_timeout=180.0  # More time for detailed analysis
    )
    
    print(f"Security Review Complete!")
    print(f"Experts consulted: {result['expert_metadata']['experts_used']}")
    print(f"Consensus level: {result['expert_metadata']['consensus_level']}")
    print(f"\nKey findings:")
    
    # Show recommendations with high agreement
    for rec in result['aggregation']['common_recommendations'][:5]:
        print(f"  ⚠️  {rec}")


async def batch_consultation():
    """Process multiple queries efficiently."""
    print("\n=== Batch Consultation ===\n")
    
    manager = EnhancedExpertManager()
    
    queries = [
        {
            "content": "What's the best way to implement caching in a Python web app?",
            "tags": ["python", "caching", "performance"]
        },
        {
            "content": "Compare REST vs GraphQL for a mobile app backend",
            "tags": ["api", "architecture", "mobile"]
        },
        {
            "content": "How to implement rate limiting in a distributed system?",
            "tags": ["distributed", "security", "scalability"]
        }
    ]
    
    # Process queries in parallel
    tasks = []
    for query in queries:
        task = manager.quick_consult(
            content=query["content"],
            expert_count=2  # Fewer experts for batch processing
        )
        tasks.append(task)
    
    results = await asyncio.gather(*tasks)
    
    print(f"Processed {len(results)} queries in parallel")
    for i, result in enumerate(results):
        print(f"\nQuery {i+1}: {queries[i]['content'][:50]}...")
        print(f"  Consensus: {result['consensus']}")
        print(f"  Top recommendation: {result['recommendations'][0] if result['recommendations'] else 'None'}")


async def main():
    """Run all examples."""
    # Check environment
    if not os.getenv("GOOGLE_CREDENTIALS_PATH"):
        print("⚠️  WARNING: Google credentials not configured")
        print("Set GOOGLE_CREDENTIALS_PATH for full functionality\n")
    
    # Run examples
    await check_expert_availability()
    await cost_estimation_example()
    await claude_code_quick_consult()
    await specialized_consultation()
    await batch_consultation()


if __name__ == "__main__":
    # Set up any required environment variables here
    # os.environ["ANTHROPIC_API_KEY"] = "your-key"
    # os.environ["OPENAI_API_KEY"] = "your-key"
    
    asyncio.run(main())
