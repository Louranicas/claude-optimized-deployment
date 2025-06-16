// Knowledge Graph - Semantic relationship management
use super::*;

use petgraph::graph::{Graph, NodeIndex};
use petgraph::algo::{dijkstra, page_rank};
use petgraph::visit::EdgeRef;
use std::collections::{HashMap, HashSet};
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use parking_lot::RwLock;

/// Entity in the knowledge graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entity {
    pub id: String,
    pub entity_type: EntityType,
    pub label: String,
    pub properties: HashMap<String, serde_json::Value>,
    pub embeddings: Option<Vec<f32>>,
    pub confidence: f64,
    pub last_updated: u64,
}

/// Entity types in the knowledge graph
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntityType {
    Concept,
    Person,
    Organization,
    Location,
    Event,
    Document,
    Topic,
    Custom(String),
}

/// Relationship between entities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relationship {
    pub id: String,
    pub rel_type: RelationshipType,
    pub properties: HashMap<String, serde_json::Value>,
    pub confidence: f64,
    pub weight: f64,
}

/// Relationship types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RelationshipType {
    RelatedTo,
    PartOf,
    Contains,
    References,
    DerivedFrom,
    ConflictsWith,
    Supports,
    Custom(String),
}

/// Knowledge graph implementation
pub struct KnowledgeGraph {
    graph: Arc<RwLock<Graph<Entity, Relationship>>>,
    entity_index: Arc<RwLock<HashMap<String, NodeIndex>>>,
    type_index: Arc<RwLock<HashMap<EntityType, HashSet<NodeIndex>>>>,
    embeddings_index: Arc<RwLock<HashMap<String, Vec<f32>>>>,
    statistics: Arc<RwLock<GraphStatistics>>,
}

/// Graph statistics
#[derive(Default)]
struct GraphStatistics {
    total_entities: usize,
    total_relationships: usize,
    entity_types: HashMap<EntityType, usize>,
    relationship_types: HashMap<RelationshipType, usize>,
    last_update: u64,
}

impl KnowledgeGraph {
    /// Create new knowledge graph
    pub fn new() -> Self {
        Self {
            graph: Arc::new(RwLock::new(Graph::new())),
            entity_index: Arc::new(RwLock::new(HashMap::new())),
            type_index: Arc::new(RwLock::new(HashMap::new())),
            embeddings_index: Arc::new(RwLock::new(HashMap::new())),
            statistics: Arc::new(RwLock::new(GraphStatistics::default())),
        }
    }
    
    /// Add entity to the graph
    pub fn add_entity(&self, entity: Entity) -> Result<NodeIndex> {
        let mut graph = self.graph.write();
        let mut entity_index = self.entity_index.write();
        let mut type_index = self.type_index.write();
        
        // Check if entity already exists
        if let Some(&existing_idx) = entity_index.get(&entity.id) {
            // Update existing entity
            if let Some(node) = graph.node_weight_mut(existing_idx) {
                *node = entity.clone();
            }
            return Ok(existing_idx);
        }
        
        // Add new entity
        let idx = graph.add_node(entity.clone());
        entity_index.insert(entity.id.clone(), idx);
        
        // Update type index
        type_index
            .entry(entity.entity_type.clone())
            .or_insert_with(HashSet::new)
            .insert(idx);
        
        // Update embeddings if present
        if let Some(embeddings) = entity.embeddings {
            self.embeddings_index.write().insert(entity.id.clone(), embeddings);
        }
        
        // Update statistics
        let mut stats = self.statistics.write();
        stats.total_entities += 1;
        *stats.entity_types.entry(entity.entity_type).or_insert(0) += 1;
        stats.last_update = chrono::Utc::now().timestamp_millis() as u64;
        
        Ok(idx)
    }
    
    /// Add relationship between entities
    pub fn add_relationship(
        &self,
        from_id: &str,
        to_id: &str,
        relationship: Relationship,
    ) -> Result<()> {
        let entity_index = self.entity_index.read();
        
        let from_idx = entity_index.get(from_id)
            .ok_or_else(|| format!("Entity not found: {}", from_id))?;
        let to_idx = entity_index.get(to_id)
            .ok_or_else(|| format!("Entity not found: {}", to_id))?;
        
        let mut graph = self.graph.write();
        graph.add_edge(*from_idx, *to_idx, relationship.clone());
        
        // Update statistics
        let mut stats = self.statistics.write();
        stats.total_relationships += 1;
        *stats.relationship_types.entry(relationship.rel_type).or_insert(0) += 1;
        stats.last_update = chrono::Utc::now().timestamp_millis() as u64;
        
        Ok(())
    }
    
    /// Query entities by type
    pub fn query_by_type(&self, entity_type: &EntityType) -> Vec<Entity> {
        let graph = self.graph.read();
        let type_index = self.type_index.read();
        
        if let Some(indices) = type_index.get(entity_type) {
            indices
                .iter()
                .filter_map(|&idx| graph.node_weight(idx).cloned())
                .collect()
        } else {
            vec![]
        }
    }
    
    /// Find related entities
    pub fn find_related(&self, entity_id: &str, max_depth: usize) -> Vec<(Entity, f64)> {
        let entity_index = self.entity_index.read();
        let graph = self.graph.read();
        
        let start_idx = match entity_index.get(entity_id) {
            Some(&idx) => idx,
            None => return vec![],
        };
        
        // Use Dijkstra to find nearby nodes
        let distances = dijkstra(&*graph, start_idx, None, |edge| edge.weight().weight);
        
        let mut related: Vec<_> = distances
            .into_iter()
            .filter(|(_, dist)| *dist <= max_depth as f64)
            .filter_map(|(idx, dist)| {
                graph.node_weight(idx).map(|entity| (entity.clone(), dist))
            })
            .collect();
        
        // Sort by distance
        related.sort_by(|a, b| a.1.partial_cmp(&b.1).expect("Unexpected None/Error"));
        
        related
    }
    
    /// Calculate entity importance using PageRank
    pub fn calculate_importance(&self) -> HashMap<String, f64> {
        let graph = self.graph.read();
        let entity_index = self.entity_index.read();
        
        // Create reverse index
        let mut idx_to_id = HashMap::new();
        for (id, &idx) in entity_index.iter() {
            idx_to_id.insert(idx, id.clone());
        }
        
        // Calculate PageRank
        let scores = page_rank(&*graph, 0.85, 50);
        
        // Map scores back to entity IDs
        scores
            .into_iter()
            .filter_map(|(idx, score)| {
                idx_to_id.get(&idx).map(|id| (id.clone(), score))
            })
            .collect()
    }
    
    /// Find shortest path between entities
    pub fn find_path(&self, from_id: &str, to_id: &str) -> Option<Vec<Entity>> {
        let entity_index = self.entity_index.read();
        let graph = self.graph.read();
        
        let from_idx = entity_index.get(from_id)?;
        let to_idx = entity_index.get(to_id)?;
        
        // Find shortest path
        let path = petgraph::algo::astar(
            &*graph,
            *from_idx,
            |idx| idx == *to_idx,
            |edge| edge.weight().weight,
            |_| 0.0,
        );
        
        path.map(|(_, path)| {
            path.into_iter()
                .filter_map(|idx| graph.node_weight(idx).cloned())
                .collect()
        })
    }
    
    /// Update from search results
    pub fn update_from_results(&mut self, results: &SearchResult) -> Result<()> {
        for group in &results.results {
            // Create topic entity for the group
            let topic_entity = Entity {
                id: format!("topic_{}", uuid::Uuid::new_v4()),
                entity_type: EntityType::Topic,
                label: group.category.clone(),
                properties: HashMap::new(),
                embeddings: None,
                confidence: group.relevance,
                last_updated: chrono::Utc::now().timestamp_millis() as u64,
            };
            
            let topic_idx = self.add_entity(topic_entity)?;
            
            // Add documents as entities
            for item in &group.items {
                let doc_entity = Entity {
                    id: item.id.clone(),
                    entity_type: EntityType::Document,
                    label: item.title.clone(),
                    properties: item.metadata.clone(),
                    embeddings: None,
                    confidence: item.score,
                    last_updated: chrono::Utc::now().timestamp_millis() as u64,
                };
                
                self.add_entity(doc_entity)?;
                
                // Link document to topic
                self.add_relationship(
                    &item.id,
                    &format!("topic_{}", topic_idx.index()),
                    Relationship {
                        id: uuid::Uuid::new_v4().to_string(),
                        rel_type: RelationshipType::PartOf,
                        properties: HashMap::new(),
                        confidence: 0.8,
                        weight: 1.0,
                    },
                )?;
            }
        }
        
        Ok(())
    }
    
    /// Get graph statistics
    pub fn get_statistics(&self) -> GraphStatistics {
        self.statistics.read().clone()
    }
    
    /// Export graph to JSON
    pub fn export_to_json(&self) -> Result<serde_json::Value> {
        let graph = self.graph.read();
        
        let nodes: Vec<_> = graph
            .node_indices()
            .filter_map(|idx| graph.node_weight(idx))
            .cloned()
            .collect();
        
        let edges: Vec<_> = graph
            .edge_indices()
            .filter_map(|idx| {
                let edge = graph.edge_weight(idx)?;
                let (from, to) = graph.edge_endpoints(idx)?;
                
                Some(serde_json::json!({
                    "from": graph.node_weight(from)?.id,
                    "to": graph.node_weight(to)?.id,
                    "relationship": edge,
                }))
            })
            .collect();
        
        Ok(serde_json::json!({
            "nodes": nodes,
            "edges": edges,
            "statistics": *self.statistics.read(),
        }))
    }
    
    /// Search using embeddings similarity
    pub fn search_by_similarity(&self, query_embedding: &[f32], top_k: usize) -> Vec<(Entity, f64)> {
        let graph = self.graph.read();
        let embeddings_index = self.embeddings_index.read();
        
        let mut similarities: Vec<_> = embeddings_index
            .iter()
            .filter_map(|(id, embedding)| {
                let similarity = self.cosine_similarity(query_embedding, embedding);
                
                self.entity_index.read().get(id).and_then(|&idx| {
                    graph.node_weight(idx).map(|entity| (entity.clone(), similarity))
                })
            })
            .collect();
        
        // Sort by similarity (descending)
        similarities.sort_by(|a, b| b.1.partial_cmp(&a.1).expect("Unexpected None/Error"));
        similarities.truncate(top_k);
        
        similarities
    }
    
    /// Calculate cosine similarity between embeddings
    fn cosine_similarity(&self, a: &[f32], b: &[f32]) -> f64 {
        if a.len() != b.len() {
            return 0.0;
        }
        
        let dot_product: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
        
        if norm_a == 0.0 || norm_b == 0.0 {
            0.0
        } else {
            (dot_product / (norm_a * norm_b)) as f64
        }
    }
}

// Implement Clone for GraphStatistics
impl Clone for GraphStatistics {
    fn clone(&self) -> Self {
        Self {
            total_entities: self.total_entities,
            total_relationships: self.total_relationships,
            entity_types: self.entity_types.clone(),
            relationship_types: self.relationship_types.clone(),
            last_update: self.last_update,
        }
    }
}

// External dependencies
use petgraph;
use parking_lot;