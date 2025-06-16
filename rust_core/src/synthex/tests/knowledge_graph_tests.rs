//! Tests for SYNTHEX knowledge graph functionality

#[cfg(test)]
mod tests {
    use crate::synthex::knowledge_graph::{
        KnowledgeGraph, Node, Edge, GraphQuery, GraphTraversal
    };
    use std::collections::HashMap;
    
    #[tokio::test]
    async fn test_graph_creation() {
        let mut graph = KnowledgeGraph::new();
        
        // Add nodes
        let node1 = Node {
            id: "doc1".to_string(),
            content: "Rust programming language".to_string(),
            node_type: "document".to_string(),
            metadata: HashMap::new(),
        };
        
        let node2 = Node {
            id: "doc2".to_string(),
            content: "Systems programming".to_string(),
            node_type: "concept".to_string(),
            metadata: HashMap::new(),
        };
        
        graph.add_node(node1.clone()).await.unwrap();
        graph.add_node(node2.clone()).await.unwrap();
        
        assert_eq!(graph.node_count(), 2);
    }
    
    #[tokio::test]
    async fn test_edge_creation() {
        let mut graph = KnowledgeGraph::new();
        
        // Add nodes
        graph.add_node(Node {
            id: "rust".to_string(),
            content: "Rust language".to_string(),
            node_type: "language".to_string(),
            metadata: HashMap::new(),
        }).await.unwrap();
        
        graph.add_node(Node {
            id: "memory_safety".to_string(),
            content: "Memory safety concept".to_string(),
            node_type: "concept".to_string(),
            metadata: HashMap::new(),
        }).await.unwrap();
        
        // Create edge
        let edge = Edge {
            from: "rust".to_string(),
            to: "memory_safety".to_string(),
            edge_type: "provides".to_string(),
            weight: 0.9,
            metadata: HashMap::new(),
        };
        
        graph.add_edge(edge).await.unwrap();
        
        let edges = graph.get_edges_from("rust").await;
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].to, "memory_safety");
    }
    
    #[tokio::test]
    async fn test_graph_traversal() {
        let mut graph = KnowledgeGraph::new();
        
        // Create a small knowledge network
        let nodes = vec![
            ("rust", "Rust programming", "language"),
            ("cpp", "C++ programming", "language"),
            ("python", "Python programming", "language"),
            ("performance", "High performance", "attribute"),
            ("safety", "Memory safety", "attribute"),
            ("ease", "Ease of use", "attribute"),
        ];
        
        for (id, content, node_type) in nodes {
            graph.add_node(Node {
                id: id.to_string(),
                content: content.to_string(),
                node_type: node_type.to_string(),
                metadata: HashMap::new(),
            }).await.unwrap();
        }
        
        // Create relationships
        let edges = vec![
            ("rust", "performance", "has", 0.9),
            ("rust", "safety", "has", 1.0),
            ("cpp", "performance", "has", 1.0),
            ("python", "ease", "has", 0.9),
            ("python", "performance", "has", 0.3),
        ];
        
        for (from, to, edge_type, weight) in edges {
            graph.add_edge(Edge {
                from: from.to_string(),
                to: to.to_string(),
                edge_type: edge_type.to_string(),
                weight,
                metadata: HashMap::new(),
            }).await.unwrap();
        }
        
        // Test BFS traversal
        let traversal = GraphTraversal::bfs(&graph, "rust", 2).await;
        assert!(traversal.visited.contains("performance"));
        assert!(traversal.visited.contains("safety"));
        
        // Test DFS traversal
        let traversal = GraphTraversal::dfs(&graph, "python", 2).await;
        assert!(traversal.visited.contains("ease"));
        assert!(traversal.visited.contains("performance"));
    }
    
    #[tokio::test]
    async fn test_graph_queries() {
        let mut graph = create_test_graph().await;
        
        // Find nodes by type
        let languages = graph.find_nodes_by_type("language").await;
        assert_eq!(languages.len(), 3);
        
        // Find connected nodes
        let rust_connections = graph.get_connected_nodes("rust", 1).await;
        assert!(rust_connections.len() >= 2);
        
        // Find path between nodes
        let path = graph.find_shortest_path("rust", "ease").await;
        assert!(path.is_some());
        let path = path.unwrap();
        assert!(path.len() <= 4); // Should find indirect connection
    }
    
    #[tokio::test]
    async fn test_semantic_search() {
        let mut graph = create_test_graph().await;
        
        // Add embeddings to nodes (simplified)
        graph.compute_embeddings().await.unwrap();
        
        // Semantic search
        let results = graph.semantic_search("memory safe systems programming", 5).await;
        
        assert!(!results.is_empty());
        // Rust should rank high for this query
        assert!(results.iter().any(|r| r.0.id == "rust"));
        assert!(results[0].1 > 0.5); // Good relevance score
    }
    
    #[tokio::test]
    async fn test_graph_clustering() {
        let mut graph = create_test_graph().await;
        
        // Detect communities/clusters
        let clusters = graph.detect_communities().await;
        
        assert!(clusters.len() >= 2);
        
        // Languages should cluster with their attributes
        let rust_cluster = clusters.iter()
            .find(|c| c.nodes.contains(&"rust".to_string()))
            .expect("Rust cluster not found");
            
        assert!(rust_cluster.nodes.contains(&"safety".to_string()));
        assert!(rust_cluster.nodes.contains(&"performance".to_string()));
    }
    
    #[tokio::test]
    async fn test_graph_analytics() {
        let graph = create_test_graph().await;
        
        // Compute centrality metrics
        let centrality = graph.compute_centrality().await;
        
        // Performance should be central (connected to multiple languages)
        let perf_centrality = centrality.get("performance").expect("Performance not found");
        assert!(*perf_centrality > 0.5);
        
        // Compute PageRank
        let pagerank = graph.compute_pagerank(0.85, 100).await;
        assert!(!pagerank.is_empty());
        
        // Important nodes should have higher PageRank
        let rust_rank = pagerank.get("rust").expect("Rust not found");
        assert!(*rust_rank > 0.1);
    }
    
    #[tokio::test]
    async fn test_graph_updates() {
        let mut graph = KnowledgeGraph::new();
        
        // Add initial node
        let node = Node {
            id: "test".to_string(),
            content: "Initial content".to_string(),
            node_type: "test".to_string(),
            metadata: HashMap::new(),
        };
        
        graph.add_node(node).await.unwrap();
        
        // Update node
        let updated_node = Node {
            id: "test".to_string(),
            content: "Updated content".to_string(),
            node_type: "test".to_string(),
            metadata: HashMap::new(),
        };
        
        graph.update_node(updated_node).await.unwrap();
        
        let retrieved = graph.get_node("test").await.unwrap();
        assert_eq!(retrieved.content, "Updated content");
    }
    
    #[tokio::test]
    async fn test_graph_persistence() {
        let mut graph = create_test_graph().await;
        
        // Save to file
        let temp_file = tempfile::NamedTempFile::new().unwrap();
        graph.save_to_file(temp_file.path()).await.unwrap();
        
        // Load from file
        let loaded_graph = KnowledgeGraph::load_from_file(temp_file.path()).await.unwrap();
        
        assert_eq!(loaded_graph.node_count(), graph.node_count());
        assert_eq!(loaded_graph.edge_count(), graph.edge_count());
    }
    
    #[tokio::test]
    async fn test_graph_merge() {
        let mut graph1 = KnowledgeGraph::new();
        let mut graph2 = KnowledgeGraph::new();
        
        // Add different nodes to each graph
        graph1.add_node(Node {
            id: "node1".to_string(),
            content: "Graph 1 node".to_string(),
            node_type: "test".to_string(),
            metadata: HashMap::new(),
        }).await.unwrap();
        
        graph2.add_node(Node {
            id: "node2".to_string(),
            content: "Graph 2 node".to_string(),
            node_type: "test".to_string(),
            metadata: HashMap::new(),
        }).await.unwrap();
        
        // Merge graphs
        graph1.merge(graph2).await.unwrap();
        
        assert_eq!(graph1.node_count(), 2);
        assert!(graph1.get_node("node1").await.is_ok());
        assert!(graph1.get_node("node2").await.is_ok());
    }
    
    #[tokio::test]
    async fn test_graph_reasoning() {
        let mut graph = create_test_graph().await;
        
        // Add reasoning rules
        graph.add_rule("transitive_performance", |g, from, to| {
            // If A has performance and B is similar to A, then B likely has performance
            Box::pin(async move {
                if let Some(edges) = g.get_edges_from(from).await.get(0) {
                    if edges.edge_type == "has" && edges.to == "performance" {
                        if g.similarity(from, to).await > 0.7 {
                            return Some(0.8); // Inferred confidence
                        }
                    }
                }
                None
            })
        }).await;
        
        // Test inference
        let inference = graph.infer_relationship("cpp", "performance").await;
        assert!(inference.is_some());
        assert!(inference.unwrap() > 0.5);
    }
}

// Helper function to create a test graph
async fn create_test_graph() -> KnowledgeGraph {
    let mut graph = KnowledgeGraph::new();
    
    // Add programming languages
    let languages = vec![
        ("rust", "Rust programming language with memory safety", "language"),
        ("cpp", "C++ systems programming language", "language"),
        ("python", "Python high-level programming language", "language"),
    ];
    
    // Add attributes
    let attributes = vec![
        ("performance", "High performance computing capability", "attribute"),
        ("safety", "Memory safety and thread safety", "attribute"),
        ("ease", "Ease of use and learning", "attribute"),
        ("systems", "Systems programming capability", "attribute"),
    ];
    
    // Add all nodes
    for (id, content, node_type) in languages.iter().chain(attributes.iter()) {
        graph.add_node(Node {
            id: id.to_string(),
            content: content.to_string(),
            node_type: node_type.to_string(),
            metadata: HashMap::new(),
        }).await.unwrap();
    }
    
    // Create relationships
    let relationships = vec![
        ("rust", "performance", "has", 0.9),
        ("rust", "safety", "has", 1.0),
        ("rust", "systems", "has", 1.0),
        ("cpp", "performance", "has", 1.0),
        ("cpp", "systems", "has", 1.0),
        ("python", "ease", "has", 0.9),
        ("python", "performance", "has", 0.3),
    ];
    
    for (from, to, edge_type, weight) in relationships {
        graph.add_edge(Edge {
            from: from.to_string(),
            to: to.to_string(),
            edge_type: edge_type.to_string(),
            weight,
            metadata: HashMap::new(),
        }).await.unwrap();
    }
    
    graph
}