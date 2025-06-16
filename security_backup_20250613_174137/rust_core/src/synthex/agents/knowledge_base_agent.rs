// Knowledge Base Agent - Semantic search over knowledge base
use super::*;
use tantivy::{
    collector::TopDocs,
    query::QueryParser,
    schema::{self, IndexRecordOption},
    Index, IndexReader, IndexWriter, ReloadPolicy,
};
use std::path::Path;

/// Knowledge base search agent
pub struct KnowledgeBaseAgent {
    index: Index,
    reader: IndexReader,
    config: Arc<KnowledgeBaseConfig>,
    metrics: Arc<RwLock<AgentMetrics>>,
}

/// Knowledge base configuration
#[derive(Clone)]
pub struct KnowledgeBaseConfig {
    pub index_path: String,
    pub max_results: usize,
    pub enable_fuzzy: bool,
    pub fuzzy_distance: u8,
}

impl Default for KnowledgeBaseConfig {
    fn default() -> Self {
        Self {
            index_path: "./knowledge_base_index".to_string(),
            max_results: 100,
            enable_fuzzy: true,
            fuzzy_distance: 2,
        }
    }
}

impl KnowledgeBaseAgent {
    pub fn new(config: KnowledgeBaseConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let index = if Path::new(&config.index_path).exists() {
            Index::open_in_dir(&config.index_path)?
        } else {
            // Create new index
            std::fs::create_dir_all(&config.index_path)?;
            let schema = Self::build_schema();
            Index::create_in_dir(&config.index_path, schema)?
        };
        
        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::OnCommit)
            .try_into()?;
        
        Ok(Self {
            index,
            reader,
            config: Arc::new(config),
            metrics: Arc::new(RwLock::new(AgentMetrics::default())),
        })
    }
    
    /// Build the schema for the knowledge base
    fn build_schema() -> schema::Schema {
        let mut schema_builder = schema::Schema::builder();
        
        schema_builder.add_text_field(
            "id",
            schema::STRING | schema::STORED,
        );
        
        schema_builder.add_text_field(
            "title",
            schema::TEXT | schema::STORED,
        );
        
        schema_builder.add_text_field(
            "content",
            schema::TEXT | schema::STORED,
        );
        
        schema_builder.add_u64_field(
            "timestamp",
            schema::STORED | schema::INDEXED,
        );
        
        schema_builder.add_text_field(
            "category",
            schema::STRING | schema::STORED | schema::INDEXED,
        );
        
        schema_builder.add_text_field(
            "tags",
            schema::TEXT | schema::STORED,
        );
        
        schema_builder.build()
    }
    
    /// Add document to knowledge base
    pub async fn add_document(
        &self,
        id: &str,
        title: &str,
        content: &str,
        category: &str,
        tags: Vec<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut writer: IndexWriter = self.index.writer(50_000_000)?;
        let schema = self.index.schema();
        
        let id_field = schema.get_field("id").unwrap();
        let title_field = schema.get_field("title").unwrap();
        let content_field = schema.get_field("content").unwrap();
        let timestamp_field = schema.get_field("timestamp").unwrap();
        let category_field = schema.get_field("category").unwrap();
        let tags_field = schema.get_field("tags").unwrap();
        
        let mut doc = tantivy::Document::new();
        doc.add_text(id_field, id);
        doc.add_text(title_field, title);
        doc.add_text(content_field, content);
        doc.add_u64(timestamp_field, chrono::Utc::now().timestamp() as u64);
        doc.add_text(category_field, category);
        doc.add_text(tags_field, tags.join(" "));
        
        writer.add_document(doc)?;
        writer.commit()?;
        
        Ok(())
    }
    
    /// Search the knowledge base
    async fn search_knowledge_base(
        &self,
        query: &str,
        options: &SearchOptions,
    ) -> Result<Vec<RawResult>, Box<dyn std::error::Error>> {
        let searcher = self.reader.searcher();
        let schema = self.index.schema();
        
        let title_field = schema.get_field("title").unwrap();
        let content_field = schema.get_field("content").unwrap();
        let tags_field = schema.get_field("tags").unwrap();
        
        let query_parser = QueryParser::for_index(
            &self.index,
            vec![title_field, content_field, tags_field],
        );
        
        let query = if self.config.enable_fuzzy {
            // Add fuzzy search
            let fuzzy_query = format!("{}~{}", query, self.config.fuzzy_distance);
            query_parser.parse_query(&fuzzy_query)?
        } else {
            query_parser.parse_query(query)?
        };
        
        let top_docs = searcher.search(&query, &TopDocs::with_limit(options.max_results))?;
        
        let mut results = Vec::new();
        for (score, doc_address) in top_docs {
            let retrieved_doc = searcher.doc(doc_address)?;
            let result = self.doc_to_result(&retrieved_doc, score, query)?;
            results.push(result);
        }
        
        Ok(results)
    }
    
    /// Convert Tantivy document to RawResult
    fn doc_to_result(
        &self,
        doc: &tantivy::Document,
        score: f32,
        query: &str,
    ) -> Result<RawResult, Box<dyn std::error::Error>> {
        let schema = self.index.schema();
        
        let id = doc.get_first(schema.get_field("id").unwrap())
            .and_then(|v| v.as_text())
            .unwrap_or("unknown");
        
        let title = doc.get_first(schema.get_field("title").unwrap())
            .and_then(|v| v.as_text())
            .unwrap_or("");
        
        let content = doc.get_first(schema.get_field("content").unwrap())
            .and_then(|v| v.as_text())
            .unwrap_or("");
        
        let category = doc.get_first(schema.get_field("category").unwrap())
            .and_then(|v| v.as_text())
            .unwrap_or("general");
        
        let timestamp = doc.get_first(schema.get_field("timestamp").unwrap())
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        
        let mut metadata = HashMap::new();
        metadata.insert("source".to_string(), json!("knowledge_base"));
        metadata.insert("id".to_string(), json!(id));
        metadata.insert("category".to_string(), json!(category));
        metadata.insert("query".to_string(), json!(query));
        
        Ok(RawResult {
            content: format!("{}\n\n{}", title, content),
            metadata,
            score: score as f64,
            timestamp: timestamp * 1000, // Convert to milliseconds
        })
    }
}

#[async_trait]
impl SearchAgent for KnowledgeBaseAgent {
    fn name(&self) -> &str {
        "knowledge_base"
    }
    
    fn supported_queries(&self) -> Vec<QueryType> {
        vec![QueryType::FullText, QueryType::Fuzzy, QueryType::Semantic]
    }
    
    async fn search(
        &self,
        query: &str,
        options: SearchOptions,
    ) -> Result<Vec<RawResult>, Box<dyn std::error::Error>> {
        let start = std::time::Instant::now();
        
        // Update metrics
        {
            let mut metrics = self.metrics.write();
            metrics.total_searches += 1;
        }
        
        let results = self.search_knowledge_base(query, &options).await;
        
        // Update metrics
        match &results {
            Ok(_) => {
                let mut metrics = self.metrics.write();
                metrics.successful_searches += 1;
                let elapsed = start.elapsed().as_millis() as u64;
                metrics.avg_latency_ms = (metrics.avg_latency_ms * (metrics.successful_searches - 1) 
                    + elapsed) / metrics.successful_searches;
            }
            Err(_) => {
                let mut metrics = self.metrics.write();
                metrics.failed_searches += 1;
            }
        }
        
        results
    }
    
    async fn health_check(&self) -> Result<HealthStatus, Box<dyn std::error::Error>> {
        let start = std::time::Instant::now();
        
        // Try a simple search
        let searcher = self.reader.searcher();
        let schema = self.index.schema();
        let content_field = schema.get_field("content").unwrap();
        
        let query_parser = QueryParser::for_index(&self.index, vec![content_field]);
        let query = query_parser.parse_query("test")?;
        
        let _top_docs = searcher.search(&query, &TopDocs::with_limit(1))?;
        
        let latency_ms = start.elapsed().as_millis() as u64;
        
        let metrics = self.metrics.read();
        let error_rate = if metrics.total_searches > 0 {
            metrics.failed_searches as f64 / metrics.total_searches as f64
        } else {
            0.0
        };
        
        Ok(HealthStatus {
            healthy: true,
            latency_ms,
            error_rate,
            last_check: chrono::Utc::now().timestamp_millis() as u64,
        })
    }
    
    fn get_metrics(&self) -> AgentMetrics {
        self.metrics.read().clone()
    }
}