"""
Models - Data models for the learning system
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Union
from datetime import datetime
import numpy as np
import networkx as nx


@dataclass
class Interaction:
    """Represents an interaction with the system"""
    id: str
    type: str  # command, query, response, event
    source: str  # Which MCP instance
    content: Dict[str, Any]
    context: 'Context'
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Optional attributes for different interaction types
    sequence: Optional[List[Any]] = None
    time_series: Optional[np.ndarray] = None
    entities: Optional[List['Entity']] = None
    relationships: Optional[List['Relationship']] = None
    values: Optional[np.ndarray] = None
    distribution: Optional[Dict[str, float]] = None
    coordinates: Optional[np.ndarray] = None
    high_dim_data: Optional[np.ndarray] = None


@dataclass
class Context:
    """Context information for predictions and learning"""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    state: Dict[str, Any] = field(default_factory=dict)
    user_attributes: Dict[str, Any] = field(default_factory=dict)
    environment: Dict[str, Any] = field(default_factory=dict)
    entity_id: Optional[str] = None
    previous_prediction: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Features:
    """Multi-modal features extracted from interactions"""
    temporal: np.ndarray
    relational: Union[nx.Graph, np.ndarray]
    statistical: np.ndarray
    spatial: np.ndarray
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Pattern:
    """Base pattern class"""
    id: str
    type: str
    confidence: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "confidence": self.confidence,
            "metadata": self.metadata
        }


@dataclass
class Patterns:
    """Collection of patterns from different analyzers"""
    temporal: List[Any] = field(default_factory=list)
    structural: List[Any] = field(default_factory=list)
    anomalies: List[Any] = field(default_factory=list)
    clusters: List[Any] = field(default_factory=list)
    meta_patterns: List[Dict[str, Any]] = field(default_factory=list)
    correlations: List[Dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.5
    
    @property
    def sequences(self):
        """Alias for temporal patterns"""
        return self.temporal
    
    @property
    def structures(self):
        """Alias for structural patterns"""
        return self.structural


@dataclass
class Knowledge:
    """Knowledge representation"""
    nodes: List[Dict[str, Any]] = field(default_factory=list)
    relationships: List[Dict[str, Any]] = field(default_factory=list)
    embeddings: np.ndarray = field(default_factory=lambda: np.array([]))
    insights: List[Dict[str, Any]] = field(default_factory=list)
    cross_instance_insights: Optional[List[Dict[str, Any]]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Knowledge':
        """Create Knowledge from dictionary"""
        return cls(
            nodes=data.get("nodes", []),
            relationships=data.get("relationships", []),
            embeddings=np.array(data.get("embeddings", [])),
            insights=data.get("insights", []),
            cross_instance_insights=data.get("cross_instance_insights"),
            metadata=data.get("metadata", {})
        )


@dataclass
class Learning:
    """Learning outcome from processing an interaction"""
    type: str
    patterns: Optional[Patterns] = None
    predictions: Optional['Prediction'] = None
    optimization: Optional[Dict[str, Any]] = None
    source_interaction: Optional[Interaction] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    cross_instance_relevance: float = 0.5
    metadata: Dict[str, Any] = field(default_factory=dict)
    content: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "type": self.type,
            "patterns": self.patterns.__dict__ if self.patterns else None,
            "predictions": self.predictions.__dict__ if self.predictions else None,
            "optimization": self.optimization,
            "timestamp": self.timestamp.isoformat(),
            "cross_instance_relevance": self.cross_instance_relevance,
            "metadata": self.metadata,
            "content": self.content
        }
    
    def calculate_accuracy(self) -> float:
        """Calculate accuracy metric"""
        if self.predictions and hasattr(self.predictions, 'confidence'):
            return self.predictions.confidence
        return 0.5
    
    def calculate_precision(self) -> float:
        """Calculate precision metric"""
        # Simplified calculation
        return self.calculate_accuracy() * 0.95
    
    def calculate_recall(self) -> float:
        """Calculate recall metric"""
        # Simplified calculation
        return self.calculate_accuracy() * 0.9
    
    def calculate_f1_score(self) -> float:
        """Calculate F1 score"""
        precision = self.calculate_precision()
        recall = self.calculate_recall()
        
        if precision + recall == 0:
            return 0.0
        
        return 2 * (precision * recall) / (precision + recall)


@dataclass
class Prediction:
    """Prediction output"""
    output: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5
    model: str = "unknown"
    timestamp: datetime = field(default_factory=datetime.utcnow)
    temporal_adjustment: Optional[Dict[str, Any]] = None
    causal_factors: Optional[Dict[str, Any]] = None
    probability_distribution: Optional[Dict[str, Any]] = None
    model_contributions: Optional[Dict[str, float]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Entity:
    """Entity in the system"""
    id: str
    type: str
    attributes: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "attributes": self.attributes
        }


@dataclass
class Relationship:
    """Relationship between entities"""
    source: str
    target: str
    type: str
    attributes: Dict[str, Any] = field(default_factory=dict)
    weight: float = 1.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "type": self.type,
            "attributes": self.attributes,
            "weight": self.weight
        }


class KnowledgeGraph:
    """Knowledge graph implementation"""
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self.node_embeddings = {}
        self.edge_embeddings = {}
        
    def update_from_patterns(self, patterns: Patterns):
        """Update graph from patterns"""
        # Add nodes from patterns
        for i, pattern in enumerate(patterns.temporal):
            node_id = f"temporal_{i}"
            self.graph.add_node(node_id, type="temporal", pattern=pattern)
        
        for i, pattern in enumerate(patterns.structural):
            node_id = f"structural_{i}"
            self.graph.add_node(node_id, type="structural", pattern=pattern)
        
        # Add relationships between patterns
        for correlation in patterns.correlations:
            if "source" in correlation and "target" in correlation:
                self.graph.add_edge(
                    correlation["source"],
                    correlation["target"],
                    type=correlation.get("type", "correlation"),
                    weight=correlation.get("strength", 0.5)
                )
    
    def node_count(self) -> int:
        """Get number of nodes"""
        return self.graph.number_of_nodes()
    
    def edge_count(self) -> int:
        """Get number of edges"""
        return self.graph.number_of_edges()
    
    def connected_components_count(self) -> int:
        """Get number of connected components"""
        return nx.number_weakly_connected_components(self.graph)
    
    def density(self) -> float:
        """Calculate graph density"""
        if self.node_count() < 2:
            return 0.0
        return nx.density(self.graph)
    
    def average_degree(self) -> float:
        """Calculate average degree"""
        if self.node_count() == 0:
            return 0.0
        
        total_degree = sum(dict(self.graph.degree()).values())
        return total_degree / self.node_count()
    
    def get_node_features(self, node_id: str) -> List[float]:
        """Get features for a specific node"""
        features = []
        
        if node_id in self.graph:
            # Degree features
            features.append(self.graph.in_degree(node_id))
            features.append(self.graph.out_degree(node_id))
            
            # Centrality features
            try:
                degree_centrality = nx.degree_centrality(self.graph).get(node_id, 0)
                features.append(degree_centrality)
            except:
                features.append(0.0)
            
            # Embedding features
            if node_id in self.node_embeddings:
                features.extend(self.node_embeddings[node_id][:7])  # First 7 embedding dims
            else:
                features.extend([0.0] * 7)
        else:
            features = [0.0] * 10
        
        return features
    
    def get_direct_causes(self, entity_id: str) -> List[Dict[str, Any]]:
        """Get direct causes of an entity"""
        causes = []
        
        if entity_id in self.graph:
            for predecessor in self.graph.predecessors(entity_id):
                edge_data = self.graph[predecessor][entity_id]
                if edge_data.get("type") in ["causes", "influences", "affects"]:
                    causes.append({
                        "source": predecessor,
                        "target": entity_id,
                        "type": edge_data.get("type"),
                        "weight": edge_data.get("weight", 1.0)
                    })
        
        return causes
    
    def get_indirect_causes(self, entity_id: str, max_depth: int = 2) -> List[Dict[str, Any]]:
        """Get indirect causes up to max_depth"""
        indirect_causes = []
        visited = set()
        
        def traverse(node, depth, path):
            if depth > max_depth or node in visited:
                return
            
            visited.add(node)
            
            for predecessor in self.graph.predecessors(node):
                if predecessor not in path:  # Avoid cycles
                    edge_data = self.graph[predecessor][node]
                    if edge_data.get("type") in ["causes", "influences", "affects"]:
                        if depth > 1:  # Only indirect causes
                            indirect_causes.append({
                                "source": predecessor,
                                "target": entity_id,
                                "path": path + [node],
                                "depth": depth,
                                "type": edge_data.get("type"),
                                "weight": edge_data.get("weight", 1.0) * (0.8 ** depth)
                            })
                        
                        traverse(predecessor, depth + 1, path + [node])
        
        if entity_id in self.graph:
            traverse(entity_id, 1, [])
        
        return indirect_causes
    
    def get_confounders(self, entity_id: str) -> List[Dict[str, Any]]:
        """Get potential confounders"""
        confounders = []
        
        if entity_id not in self.graph:
            return confounders
        
        # Find nodes that influence both the entity and its effects
        entity_effects = list(self.graph.successors(entity_id))
        entity_causes = list(self.graph.predecessors(entity_id))
        
        for cause in entity_causes:
            cause_effects = set(self.graph.successors(cause))
            
            # Check if this cause also affects the entity's effects
            common_effects = cause_effects.intersection(entity_effects)
            
            if common_effects:
                confounders.append({
                    "confounder": cause,
                    "entity": entity_id,
                    "common_effects": list(common_effects),
                    "strength": len(common_effects) / len(entity_effects) if entity_effects else 0
                })
        
        return confounders
    
    def get_causal_strength(self, source: str, target: str) -> float:
        """Get causal strength between two nodes"""
        if self.graph.has_edge(source, target):
            edge_data = self.graph[source][target]
            base_weight = edge_data.get("weight", 1.0)
            
            # Adjust based on path redundancy
            try:
                num_paths = len(list(nx.all_simple_paths(
                    self.graph, source, target, cutoff=3
                )))
                
                # More paths indicate stronger causal relationship
                strength = base_weight * (1 + np.log1p(num_paths) / 10)
                
                return min(1.0, strength)
            except:
                return base_weight
        
        return 0.0


class SharedMemory:
    """Shared memory for cross-instance learning"""
    
    def __init__(self):
        self.memory = {}
        self.learning_history = []
        self.knowledge_graph = KnowledgeGraph()
        
    async def store(self, learning: 'SharedLearning'):
        """Store learning in shared memory"""
        # Store by hash for deduplication
        self.memory[learning.hash] = learning
        
        # Add to history
        self.learning_history.append(learning)
        
        # Keep history size manageable
        if len(self.learning_history) > 10000:
            self.learning_history = self.learning_history[-10000:]
    
    async def get_learning_history(self) -> List['SharedLearning']:
        """Get learning history"""
        return self.learning_history.copy()
    
    async def get_recent_learnings(self, count: int) -> List['SharedLearning']:
        """Get recent learnings"""
        return self.learning_history[-count:]
    
    async def update_knowledge_graph(self, source: str, entities: List[Dict], 
                                   relationships: List[Dict]):
        """Update the shared knowledge graph"""
        # Add source attribution to entities
        for entity in entities:
            entity_id = f"{source}_{entity['id']}"
            self.knowledge_graph.graph.add_node(
                entity_id,
                source=source,
                **entity
            )
        
        # Add relationships
        for rel in relationships:
            source_id = f"{source}_{rel['source']}"
            target_id = f"{source}_{rel['target']}"
            
            self.knowledge_graph.graph.add_edge(
                source_id,
                target_id,
                source=source,
                **rel
            )


class InstanceConnection:
    """Connection to an MCP instance"""
    
    def __init__(self, instance_name: str, connection_url: str):
        self.instance_name = instance_name
        self.connection_url = connection_url
        self.is_connected = False
        
    async def send_learning(self, learning: 'SharedLearning'):
        """Send learning to instance"""
        # Implementation would send via appropriate protocol
        pass
    
    async def send_bulk_learnings(self, learnings: List['SharedLearning']):
        """Send multiple learnings"""
        # Implementation would batch send
        pass
    
    async def query(self, query_data: Dict[str, Any]) -> Dict[str, Any]:
        """Query the instance"""
        # Implementation would send query and await response
        return {}
    
    async def get_model_state(self) -> Dict[str, Any]:
        """Get model state from instance"""
        # Implementation would request model state
        return {}
    
    async def update_model(self, model_type: str, model_state: Dict[str, Any]):
        """Update model on instance"""
        # Implementation would send model update
        pass