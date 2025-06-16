"""
Cross-Instance Learning - Enable intelligence sharing between MCP servers
"""

import asyncio
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass
from datetime import datetime
import json
import aioredis
import numpy as np
from collections import defaultdict
import hashlib

from .models import Learning, Knowledge, SharedMemory, InstanceConnection


@dataclass
class InstanceInfo:
    """Information about an MCP instance"""
    name: str
    type: str  # development, devops, bash_god, quality
    capabilities: List[str]
    last_seen: datetime
    performance_score: float
    specializations: List[str]


@dataclass
class SharedLearning:
    """Learning shared between instances"""
    source_instance: str
    learning_type: str
    content: Dict[str, Any]
    relevance_scores: Dict[str, float]  # Instance -> relevance
    timestamp: datetime
    hash: str


class CrossInstanceLearning:
    """Manages cross-instance learning and knowledge sharing"""
    
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self.instances: Dict[str, InstanceInfo] = {}
        self.shared_memory = SharedMemory()
        self.redis_url = redis_url
        self.redis_client = None
        self.sync_protocol = SyncProtocol()
        self.relevance_calculator = RelevanceCalculator()
        self.knowledge_merger = KnowledgeMerger()
        
    async def initialize(self):
        """Initialize cross-instance communication"""
        self.redis_client = await aioredis.create_redis_pool(self.redis_url)
        await self._discover_instances()
        await self._establish_connections()
        
    async def register_instance(self, instance_info: InstanceInfo):
        """Register a new MCP instance"""
        self.instances[instance_info.name] = instance_info
        
        # Notify other instances
        await self._broadcast_instance_update(instance_info)
        
        # Share initial knowledge
        await self._share_initial_knowledge(instance_info.name)
        
    async def share_learning(self, source: str, learning: Learning):
        """Share learning from one instance to relevant others"""
        # Validate learning
        validated_learning = await self._validate_learning(learning)
        
        # Calculate relevance for each instance
        relevance_scores = await self.relevance_calculator.calculate(
            learning,
            self.instances
        )
        
        # Create shared learning object
        shared_learning = SharedLearning(
            source_instance=source,
            learning_type=learning.type,
            content=learning.to_dict(),
            relevance_scores=relevance_scores,
            timestamp=datetime.utcnow(),
            hash=self._hash_learning(learning)
        )
        
        # Store in shared memory
        await self.shared_memory.store(shared_learning)
        
        # Broadcast to relevant instances
        await self._broadcast_learning(shared_learning)
        
        # Update knowledge graph
        await self._update_cross_instance_knowledge(source, validated_learning)
        
    async def query_cross_instance_knowledge(self, query: str, context: Dict) -> Knowledge:
        """Query knowledge across all instances"""
        # Collect relevant knowledge from all instances
        instance_knowledge = {}
        
        tasks = []
        for instance_name, instance_info in self.instances.items():
            if self._is_instance_relevant_for_query(instance_info, query, context):
                tasks.append(self._query_instance(instance_name, query, context))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, (instance_name, _) in enumerate(
            [(name, info) for name, info in self.instances.items() 
             if self._is_instance_relevant_for_query(info, query, context)]
        ):
            if not isinstance(results[i], Exception):
                instance_knowledge[instance_name] = results[i]
        
        # Merge knowledge from all instances
        merged_knowledge = await self.knowledge_merger.merge(instance_knowledge)
        
        return merged_knowledge
    
    async def get_instance_specialization_insights(self) -> Dict[str, Any]:
        """Get insights about instance specializations"""
        insights = {
            "instance_profiles": {},
            "collaboration_patterns": [],
            "performance_rankings": {},
            "recommended_routing": {}
        }
        
        # Analyze each instance
        for name, info in self.instances.items():
            insights["instance_profiles"][name] = {
                "type": info.type,
                "specializations": info.specializations,
                "performance_score": info.performance_score,
                "capabilities": info.capabilities
            }
        
        # Find collaboration patterns
        collab_patterns = await self._analyze_collaboration_patterns()
        insights["collaboration_patterns"] = collab_patterns
        
        # Rank instances by performance
        insights["performance_rankings"] = self._rank_instances_by_performance()
        
        # Generate routing recommendations
        insights["recommended_routing"] = await self._generate_routing_recommendations()
        
        return insights
    
    async def synchronize_models(self):
        """Synchronize models across instances"""
        # Get model states from all instances
        model_states = {}
        
        for instance_name in self.instances:
            state = await self._get_model_state(instance_name)
            model_states[instance_name] = state
        
        # Find best performing models
        best_models = self._identify_best_models(model_states)
        
        # Distribute best models to other instances
        for model_type, (best_instance, model_state) in best_models.items():
            await self._distribute_model(model_type, best_instance, model_state)
    
    async def _validate_learning(self, learning: Learning) -> Learning:
        """Validate and sanitize learning before sharing"""
        # Check for sensitive information
        if self._contains_sensitive_info(learning):
            learning = self._sanitize_learning(learning)
        
        # Validate structure
        if not self._is_valid_structure(learning):
            raise ValueError("Invalid learning structure")
        
        # Add metadata
        learning.metadata["validated_at"] = datetime.utcnow()
        learning.metadata["validation_version"] = "1.0"
        
        return learning
    
    def _hash_learning(self, learning: Learning) -> str:
        """Generate hash for learning deduplication"""
        content = json.dumps(learning.to_dict(), sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()
    
    async def _broadcast_learning(self, shared_learning: SharedLearning):
        """Broadcast learning to relevant instances"""
        # Use Redis pub/sub for broadcasting
        channel = "cross_instance_learning"
        
        message = {
            "type": "new_learning",
            "learning": shared_learning.to_dict()
        }
        
        await self.redis_client.publish(channel, json.dumps(message))
        
        # Also send directly to highly relevant instances
        for instance_name, relevance in shared_learning.relevance_scores.items():
            if relevance > 0.8:  # High relevance threshold
                await self._send_direct_learning(instance_name, shared_learning)
    
    async def _update_cross_instance_knowledge(self, source: str, learning: Learning):
        """Update the cross-instance knowledge graph"""
        # Extract knowledge entities
        entities = self._extract_entities(learning)
        
        # Update relationships
        relationships = self._extract_relationships(learning)
        
        # Store in knowledge graph
        await self.shared_memory.update_knowledge_graph(
            source,
            entities,
            relationships
        )
    
    def _is_instance_relevant_for_query(self, instance: InstanceInfo, 
                                       query: str, context: Dict) -> bool:
        """Check if an instance is relevant for a query"""
        # Check capabilities match
        required_capabilities = self._extract_required_capabilities(query, context)
        if not any(cap in instance.capabilities for cap in required_capabilities):
            return False
        
        # Check specialization match
        query_domain = self._extract_query_domain(query)
        if query_domain and query_domain not in instance.specializations:
            return False
        
        # Check performance threshold
        if instance.performance_score < 0.5:
            return False
        
        return True
    
    async def _query_instance(self, instance_name: str, query: str, 
                            context: Dict) -> Knowledge:
        """Query a specific instance for knowledge"""
        # Send query to instance
        connection = await self._get_instance_connection(instance_name)
        
        response = await connection.query({
            "query": query,
            "context": context,
            "requester": "cross_instance_learning"
        })
        
        return Knowledge.from_dict(response)
    
    async def _analyze_collaboration_patterns(self) -> List[Dict]:
        """Analyze how instances collaborate"""
        patterns = []
        
        # Analyze shared learning history
        learning_history = await self.shared_memory.get_learning_history()
        
        # Find frequent collaboration pairs
        collaboration_counts = defaultdict(int)
        for learning in learning_history:
            source = learning.source_instance
            for target, relevance in learning.relevance_scores.items():
                if relevance > 0.7:
                    pair = tuple(sorted([source, target]))
                    collaboration_counts[pair] += 1
        
        # Extract patterns
        for (inst1, inst2), count in collaboration_counts.items():
            if count > 10:  # Significant collaboration
                patterns.append({
                    "instances": [inst1, inst2],
                    "collaboration_count": count,
                    "type": self._determine_collaboration_type(inst1, inst2)
                })
        
        return patterns
    
    def _rank_instances_by_performance(self) -> Dict[str, List[str]]:
        """Rank instances by performance in different categories"""
        rankings = {
            "overall": [],
            "speed": [],
            "accuracy": [],
            "reliability": []
        }
        
        # Sort by overall performance
        sorted_instances = sorted(
            self.instances.items(),
            key=lambda x: x[1].performance_score,
            reverse=True
        )
        rankings["overall"] = [name for name, _ in sorted_instances]
        
        # TODO: Add specific performance metrics
        rankings["speed"] = rankings["overall"]  # Placeholder
        rankings["accuracy"] = rankings["overall"]  # Placeholder
        rankings["reliability"] = rankings["overall"]  # Placeholder
        
        return rankings
    
    async def _generate_routing_recommendations(self) -> Dict[str, str]:
        """Generate recommendations for task routing"""
        recommendations = {}
        
        # Analyze instance specializations and performance
        for task_type in ["development", "deployment", "testing", "monitoring"]:
            best_instance = self._find_best_instance_for_task(task_type)
            recommendations[task_type] = best_instance
        
        return recommendations
    
    def _find_best_instance_for_task(self, task_type: str) -> str:
        """Find the best instance for a specific task type"""
        best_score = 0
        best_instance = None
        
        for name, info in self.instances.items():
            # Calculate suitability score
            score = 0
            
            # Check if task type matches instance type
            if task_type.lower() in info.type.lower():
                score += 0.5
            
            # Check specializations
            if task_type in info.specializations:
                score += 0.3
            
            # Consider performance
            score += info.performance_score * 0.2
            
            if score > best_score:
                best_score = score
                best_instance = name
        
        return best_instance or "default"
    
    async def _discover_instances(self):
        """Discover available MCP instances"""
        # Query Redis for registered instances
        instances_data = await self.redis_client.get("mcp_instances")
        
        if instances_data:
            instances = json.loads(instances_data)
            for instance_data in instances:
                instance_info = InstanceInfo(**instance_data)
                self.instances[instance_info.name] = instance_info
    
    async def _establish_connections(self):
        """Establish connections to all instances"""
        for instance_name in self.instances:
            await self._create_instance_connection(instance_name)
    
    async def _create_instance_connection(self, instance_name: str):
        """Create connection to a specific instance"""
        # Implementation depends on communication protocol
        pass
    
    async def _get_instance_connection(self, instance_name: str) -> InstanceConnection:
        """Get connection to a specific instance"""
        # Return existing connection or create new one
        pass
    
    async def _broadcast_instance_update(self, instance_info: InstanceInfo):
        """Broadcast instance update to all instances"""
        message = {
            "type": "instance_update",
            "instance": instance_info.to_dict()
        }
        
        await self.redis_client.publish("instance_updates", json.dumps(message))
    
    async def _share_initial_knowledge(self, instance_name: str):
        """Share initial knowledge with a new instance"""
        # Get recent learnings
        recent_learnings = await self.shared_memory.get_recent_learnings(100)
        
        # Filter relevant learnings
        relevant_learnings = []
        for learning in recent_learnings:
            relevance = await self.relevance_calculator.calculate_single(
                learning,
                self.instances[instance_name]
            )
            if relevance > 0.5:
                relevant_learnings.append(learning)
        
        # Send to new instance
        if relevant_learnings:
            await self._send_bulk_learnings(instance_name, relevant_learnings)
    
    async def _send_direct_learning(self, instance_name: str, 
                                  shared_learning: SharedLearning):
        """Send learning directly to an instance"""
        connection = await self._get_instance_connection(instance_name)
        await connection.send_learning(shared_learning)
    
    async def _send_bulk_learnings(self, instance_name: str, 
                                 learnings: List[SharedLearning]):
        """Send multiple learnings to an instance"""
        connection = await self._get_instance_connection(instance_name)
        await connection.send_bulk_learnings(learnings)
    
    def _contains_sensitive_info(self, learning: Learning) -> bool:
        """Check if learning contains sensitive information"""
        # Implementation for sensitive info detection
        return False
    
    def _sanitize_learning(self, learning: Learning) -> Learning:
        """Sanitize learning to remove sensitive information"""
        # Implementation for sanitization
        return learning
    
    def _is_valid_structure(self, learning: Learning) -> bool:
        """Validate learning structure"""
        # Check required fields
        if not hasattr(learning, 'type') or not hasattr(learning, 'content'):
            return False
        
        # Check content structure
        if not isinstance(learning.content, dict):
            return False
        
        return True
    
    def _extract_entities(self, learning: Learning) -> List[Dict]:
        """Extract knowledge entities from learning"""
        # Implementation for entity extraction
        return []
    
    def _extract_relationships(self, learning: Learning) -> List[Dict]:
        """Extract relationships from learning"""
        # Implementation for relationship extraction
        return []
    
    def _extract_required_capabilities(self, query: str, context: Dict) -> List[str]:
        """Extract required capabilities from query"""
        # Simple keyword-based extraction
        capabilities = []
        
        keywords = {
            "deploy": ["deployment", "kubernetes", "docker"],
            "test": ["testing", "quality", "validation"],
            "develop": ["development", "coding", "implementation"],
            "monitor": ["monitoring", "observability", "metrics"]
        }
        
        for keyword, caps in keywords.items():
            if keyword in query.lower():
                capabilities.extend(caps)
        
        return capabilities
    
    def _extract_query_domain(self, query: str) -> Optional[str]:
        """Extract domain from query"""
        domains = ["infrastructure", "security", "performance", "quality", "development"]
        
        for domain in domains:
            if domain in query.lower():
                return domain
        
        return None
    
    def _determine_collaboration_type(self, inst1: str, inst2: str) -> str:
        """Determine the type of collaboration between instances"""
        info1 = self.instances.get(inst1)
        info2 = self.instances.get(inst2)
        
        if not info1 or not info2:
            return "unknown"
        
        # Check for complementary types
        if info1.type != info2.type:
            return "complementary"
        
        # Check for shared specializations
        shared_specs = set(info1.specializations) & set(info2.specializations)
        if shared_specs:
            return "specialized"
        
        return "general"
    
    async def _get_model_state(self, instance_name: str) -> Dict:
        """Get model state from an instance"""
        connection = await self._get_instance_connection(instance_name)
        return await connection.get_model_state()
    
    def _identify_best_models(self, model_states: Dict[str, Dict]) -> Dict[str, Tuple[str, Dict]]:
        """Identify best performing models across instances"""
        best_models = {}
        
        # Group by model type
        models_by_type = defaultdict(list)
        for instance, state in model_states.items():
            for model_type, model_info in state.items():
                models_by_type[model_type].append((instance, model_info))
        
        # Find best for each type
        for model_type, models in models_by_type.items():
            best = max(models, key=lambda x: x[1].get("performance", 0))
            best_models[model_type] = best
        
        return best_models
    
    async def _distribute_model(self, model_type: str, source_instance: str, 
                              model_state: Dict):
        """Distribute a model to other instances"""
        for instance_name in self.instances:
            if instance_name != source_instance:
                connection = await self._get_instance_connection(instance_name)
                await connection.update_model(model_type, model_state)


class SyncProtocol:
    """Protocol for synchronizing learning across instances"""
    
    def __init__(self):
        self.version = "1.0"
        self.sync_interval = 60  # seconds
        
    async def sync(self, local_state: Dict, remote_state: Dict) -> Dict:
        """Synchronize states between instances"""
        # Merge states with conflict resolution
        merged_state = {}
        
        # Add all keys from both states
        all_keys = set(local_state.keys()) | set(remote_state.keys())
        
        for key in all_keys:
            local_value = local_state.get(key)
            remote_value = remote_state.get(key)
            
            # Conflict resolution
            if local_value and remote_value:
                # Use newer value
                if hasattr(local_value, "timestamp") and hasattr(remote_value, "timestamp"):
                    merged_state[key] = local_value if local_value.timestamp > remote_value.timestamp else remote_value
                else:
                    # Default to remote value
                    merged_state[key] = remote_value
            else:
                merged_state[key] = local_value or remote_value
        
        return merged_state


class RelevanceCalculator:
    """Calculate relevance of learning for different instances"""
    
    async def calculate(self, learning: Learning, 
                       instances: Dict[str, InstanceInfo]) -> Dict[str, float]:
        """Calculate relevance scores for all instances"""
        relevance_scores = {}
        
        for instance_name, instance_info in instances.items():
            score = await self.calculate_single(learning, instance_info)
            relevance_scores[instance_name] = score
        
        return relevance_scores
    
    async def calculate_single(self, learning: Learning, 
                             instance: InstanceInfo) -> float:
        """Calculate relevance for a single instance"""
        score = 0.0
        
        # Type matching
        if learning.type in instance.capabilities:
            score += 0.3
        
        # Specialization matching
        learning_domains = self._extract_domains(learning)
        matching_domains = set(learning_domains) & set(instance.specializations)
        if matching_domains:
            score += 0.4 * (len(matching_domains) / len(learning_domains))
        
        # Performance consideration
        score += 0.2 * instance.performance_score
        
        # Temporal relevance (newer is more relevant)
        age_hours = (datetime.utcnow() - learning.timestamp).total_seconds() / 3600
        temporal_score = max(0, 1 - (age_hours / 168))  # Decay over a week
        score += 0.1 * temporal_score
        
        return min(1.0, score)
    
    def _extract_domains(self, learning: Learning) -> List[str]:
        """Extract domains from learning"""
        domains = []
        
        # Extract from content
        if hasattr(learning, "content"):
            content_str = str(learning.content).lower()
            
            domain_keywords = {
                "infrastructure": ["docker", "kubernetes", "deployment"],
                "security": ["auth", "encryption", "vulnerability"],
                "performance": ["optimization", "speed", "latency"],
                "quality": ["test", "validation", "coverage"]
            }
            
            for domain, keywords in domain_keywords.items():
                if any(keyword in content_str for keyword in keywords):
                    domains.append(domain)
        
        return domains


class KnowledgeMerger:
    """Merge knowledge from multiple instances"""
    
    async def merge(self, instance_knowledge: Dict[str, Knowledge]) -> Knowledge:
        """Merge knowledge from multiple instances"""
        if not instance_knowledge:
            return Knowledge()
        
        # Start with first instance's knowledge
        merged = list(instance_knowledge.values())[0]
        
        # Merge other instances
        for instance_name, knowledge in list(instance_knowledge.items())[1:]:
            merged = await self._merge_two(merged, knowledge, instance_name)
        
        # Deduplicate and optimize
        merged = self._deduplicate_knowledge(merged)
        
        return merged
    
    async def _merge_two(self, knowledge1: Knowledge, knowledge2: Knowledge, 
                        source: str) -> Knowledge:
        """Merge two knowledge objects"""
        merged = Knowledge()
        
        # Merge nodes
        merged.nodes = knowledge1.nodes + knowledge2.nodes
        
        # Merge relationships
        merged.relationships = knowledge1.relationships + knowledge2.relationships
        
        # Merge embeddings
        merged.embeddings = np.vstack([knowledge1.embeddings, knowledge2.embeddings])
        
        # Merge insights with source tracking
        merged.insights = knowledge1.insights.copy()
        for insight in knowledge2.insights:
            insight["source"] = source
            merged.insights.append(insight)
        
        return merged
    
    def _deduplicate_knowledge(self, knowledge: Knowledge) -> Knowledge:
        """Remove duplicate information from merged knowledge"""
        # Deduplicate nodes
        seen_nodes = set()
        unique_nodes = []
        for node in knowledge.nodes:
            node_id = node.get("id") or str(node)
            if node_id not in seen_nodes:
                seen_nodes.add(node_id)
                unique_nodes.append(node)
        knowledge.nodes = unique_nodes
        
        # Deduplicate relationships
        seen_rels = set()
        unique_rels = []
        for rel in knowledge.relationships:
            rel_id = f"{rel.get('source')}_{rel.get('target')}_{rel.get('type')}"
            if rel_id not in seen_rels:
                seen_rels.add(rel_id)
                unique_rels.append(rel)
        knowledge.relationships = unique_rels
        
        return knowledge