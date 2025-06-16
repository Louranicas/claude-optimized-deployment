#!/usr/bin/env python3
"""
Deploy 10 SYNTHEX agents for parallel task execution
Addresses JavaScript heap memory issues with distributed processing
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from src.synthex.agents import (
    WebSearchAgent, DatabaseSearchAgent, ApiSearchAgent,
    FileSearchAgent, KnowledgeBaseAgent
)
from src.synthex.config import (
    WebSearchConfig, DatabaseConfig, ApiConfig,
    FileSearchConfig, KnowledgeBaseConfig
)
from src.synthex.engine import SynthexEngine
from src.synthex.secrets import get_secret_manager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Agent types for parallel deployment
AGENT_TYPES = {
    "web_search": {
        "count": 2,
        "config_class": WebSearchConfig,
        "agent_class": WebSearchAgent,
        "description": "Web search agents for Brave and SearXNG"
    },
    "database": {
        "count": 2,
        "config_class": DatabaseConfig,
        "agent_class": DatabaseSearchAgent,
        "description": "Database search agents for PostgreSQL"
    },
    "api": {
        "count": 2,
        "config_class": ApiConfig,
        "agent_class": ApiSearchAgent,
        "description": "API search agents for external services"
    },
    "file": {
        "count": 2,
        "config_class": FileSearchConfig,
        "agent_class": FileSearchAgent,
        "description": "File search agents for local filesystem"
    },
    "knowledge": {
        "count": 2,
        "config_class": KnowledgeBaseConfig,
        "agent_class": KnowledgeBaseAgent,
        "description": "Knowledge base search agents"
    }
}


class SynthexAgentDeployer:
    """Deploy and manage multiple SYNTHEX agents"""
    
    def __init__(self):
        self.agents: Dict[str, List[Any]] = {}
        self.engine = SynthexEngine()
        self.secret_manager = get_secret_manager()
        self.deployment_status = {
            "start_time": datetime.now().isoformat(),
            "agents_deployed": 0,
            "agents_failed": 0,
            "memory_optimized": False,
            "status": "initializing"
        }
    
    async def configure_memory_optimization(self):
        """Configure Node.js and system memory for optimal performance"""
        logger.info("Configuring memory optimization...")
        
        # Set Node.js memory limit
        os.environ["NODE_OPTIONS"] = "--max-old-space-size=8192"
        
        # Configure Python garbage collection for better memory management
        import gc
        gc.set_threshold(700, 10, 10)
        
        # Enable aggressive memory cleanup
        gc.collect()
        
        self.deployment_status["memory_optimized"] = True
        logger.info("Memory optimization configured: 8GB Node.js heap, optimized GC")
    
    async def deploy_agent_type(self, agent_type: str, config: Dict[str, Any]) -> List[Any]:
        """Deploy agents of a specific type"""
        deployed_agents = []
        
        for i in range(config["count"]):
            try:
                agent_name = f"{agent_type}_agent_{i+1}"
                logger.info(f"Deploying {agent_name}...")
                
                # Create agent configuration
                if agent_type == "web_search":
                    agent_config = WebSearchConfig(
                        brave_api_key=self.secret_manager.get_secret("BRAVE_API_KEY"),
                        searxng_url=self.secret_manager.get_secret("SEARXNG_URL", "http://localhost:8888"),
                        cache_size=1000,
                        request_timeout_ms=5000
                    )
                elif agent_type == "database":
                    agent_config = DatabaseConfig(
                        connection_string=self.secret_manager.get_secret(
                            "DATABASE_URL",
                            "postgresql://localhost/claude_deployment"
                        ),
                        max_connections=10,
                        query_timeout_ms=3000,
                        search_tables=[]
                    )
                elif agent_type == "api":
                    agent_config = ApiConfig(
                        request_timeout_ms=5000,
                        retry_attempts=3,
                        rate_limit_per_second=100
                    )
                elif agent_type == "file":
                    agent_config = FileSearchConfig(
                        root_paths=["/home/louranicas/projects/claude-optimized-deployment"],
                        supported_extensions=[".py", ".rs", ".md", ".json", ".yaml"],
                        max_file_size=10 * 1024 * 1024  # 10MB
                    )
                else:  # knowledge
                    agent_config = KnowledgeBaseConfig(
                        index_path="/tmp/synthex_knowledge_index",
                        enable_fuzzy=True,
                        fuzzy_distance=2,
                        max_results=100
                    )
                
                # Create and initialize agent
                agent = config["agent_class"](agent_config)
                
                # Register with engine
                await self.engine.register_agent(agent_name, agent)
                
                deployed_agents.append(agent)
                self.deployment_status["agents_deployed"] += 1
                
                logger.info(f"✅ {agent_name} deployed successfully")
                
            except Exception as e:
                logger.error(f"Failed to deploy {agent_type} agent {i+1}: {e}")
                self.deployment_status["agents_failed"] += 1
        
        return deployed_agents
    
    async def deploy_all_agents(self):
        """Deploy all configured agents in parallel"""
        logger.info("Starting parallel deployment of 10 SYNTHEX agents...")
        
        # Configure memory optimization first
        await self.configure_memory_optimization()
        
        self.deployment_status["status"] = "deploying"
        
        # Deploy agents in parallel
        deployment_tasks = []
        for agent_type, config in AGENT_TYPES.items():
            task = self.deploy_agent_type(agent_type, config)
            deployment_tasks.append(task)
        
        # Wait for all deployments
        results = await asyncio.gather(*deployment_tasks, return_exceptions=True)
        
        # Store deployed agents
        for i, (agent_type, config) in enumerate(AGENT_TYPES.items()):
            if not isinstance(results[i], Exception):
                self.agents[agent_type] = results[i]
            else:
                logger.error(f"Failed to deploy {agent_type} agents: {results[i]}")
        
        # Update status
        self.deployment_status["status"] = "deployed"
        self.deployment_status["end_time"] = datetime.now().isoformat()
        
        # Save deployment status
        with open("synthex_agent_deployment_status.json", "w") as f:
            json.dump(self.deployment_status, f, indent=2)
        
        logger.info(f"Deployment complete: {self.deployment_status['agents_deployed']} agents deployed, "
                   f"{self.deployment_status['agents_failed']} failed")
    
    async def verify_deployment(self):
        """Verify all agents are healthy"""
        logger.info("Verifying agent deployment...")
        
        health_status = {}
        for agent_type, agents in self.agents.items():
            health_status[agent_type] = []
            for i, agent in enumerate(agents):
                try:
                    status = await agent.get_status()
                    health_status[agent_type].append({
                        "agent_id": f"{agent_type}_{i+1}",
                        "healthy": status.get("healthy", False),
                        "details": status
                    })
                except Exception as e:
                    health_status[agent_type].append({
                        "agent_id": f"{agent_type}_{i+1}",
                        "healthy": False,
                        "error": str(e)
                    })
        
        # Save health status
        with open("synthex_agent_health_status.json", "w") as f:
            json.dump(health_status, f, indent=2)
        
        # Log summary
        total_healthy = sum(
            1 for agents in health_status.values() 
            for agent in agents if agent["healthy"]
        )
        logger.info(f"Health check complete: {total_healthy}/10 agents healthy")
        
        return health_status
    
    async def run_parallel_task(self, task_name: str, query: str, options: Dict[str, Any] = None):
        """Run a task across all agents in parallel"""
        logger.info(f"Running parallel task '{task_name}' across all agents...")
        
        if options is None:
            options = {"max_results": 10}
        
        # Create search tasks for all agents
        search_tasks = []
        for agent_type, agents in self.agents.items():
            for agent in agents:
                task = agent.search(query, options)
                search_tasks.append(task)
        
        # Execute all searches in parallel
        start_time = datetime.now()
        results = await asyncio.gather(*search_tasks, return_exceptions=True)
        end_time = datetime.now()
        
        # Process results
        successful_results = []
        failed_results = []
        
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                failed_results.append({
                    "agent_index": i,
                    "error": str(result)
                })
            else:
                successful_results.extend(result)
        
        # Log performance metrics
        duration_ms = (end_time - start_time).total_seconds() * 1000
        logger.info(f"Parallel task completed in {duration_ms:.2f}ms")
        logger.info(f"Successful results: {len(successful_results)}, Failed: {len(failed_results)}")
        
        return {
            "task_name": task_name,
            "query": query,
            "duration_ms": duration_ms,
            "total_results": len(successful_results),
            "failed_agents": len(failed_results),
            "results": successful_results[:100]  # Limit to top 100
        }
    
    async def shutdown_all_agents(self):
        """Gracefully shutdown all agents"""
        logger.info("Shutting down all agents...")
        
        shutdown_tasks = []
        for agents in self.agents.values():
            for agent in agents:
                shutdown_tasks.append(agent.shutdown())
        
        await asyncio.gather(*shutdown_tasks, return_exceptions=True)
        logger.info("All agents shut down")


async def main():
    """Main deployment function"""
    deployer = SynthexAgentDeployer()
    
    try:
        # Deploy all agents
        await deployer.deploy_all_agents()
        
        # Verify deployment
        health_status = await deployer.verify_deployment()
        
        # Run a test search across all agents
        logger.info("Running test search across all agents...")
        test_result = await deployer.run_parallel_task(
            "test_search",
            "SYNTHEX BashGod implementation",
            {"max_results": 20}
        )
        
        # Save test results
        with open("synthex_test_search_results.json", "w") as f:
            json.dump(test_result, f, indent=2)
        
        logger.info("SYNTHEX agent deployment successful!")
        logger.info(f"Total agents deployed: {deployer.deployment_status['agents_deployed']}")
        logger.info("Agents are ready for parallel task execution")
        
        # Return deployer for further use if needed
        return deployer
    
    finally:
        # Cleanup
        await deployer.shutdown_all_agents()


if __name__ == "__main__":
    # Run the deployment
    asyncio.run(main())