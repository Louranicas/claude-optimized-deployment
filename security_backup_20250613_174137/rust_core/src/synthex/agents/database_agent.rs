// Database Search Agent - High-speed database queries
use super::*;
use sqlx::{Pool, Postgres, Row};
use sqlx::postgres::{PgPoolOptions, PgRow};
use std::time::Duration;
use serde_json::json;

/// Database search agent
pub struct DatabaseSearchAgent {
    pool: Pool<Postgres>,
    config: Arc<DatabaseConfig>,
    metrics: Arc<RwLock<AgentMetrics>>,
    query_builder: QueryBuilder,
}

/// Database configuration
#[derive(Clone)]
pub struct DatabaseConfig {
    pub connection_string: String,
    pub max_connections: u32,
    pub connection_timeout: Duration,
    pub query_timeout: Duration,
    pub enable_query_cache: bool,
    pub search_tables: Vec<TableConfig>,
}

/// Table search configuration
#[derive(Clone)]
pub struct TableConfig {
    pub name: String,
    pub search_columns: Vec<String>,
    pub id_column: String,
    pub timestamp_column: Option<String>,
    pub score_expression: Option<String>,
}

/// SQL query builder for search
struct QueryBuilder {
    tables: Vec<TableConfig>,
}

impl QueryBuilder {
    fn new(tables: Vec<TableConfig>) -> Self {
        Self { tables }
    }
    
    /// Build full-text search query
    fn build_search_query(&self, query: &str, table: &TableConfig, limit: usize) -> String {
        let search_columns = table.search_columns.join(" || ' ' || ");
        let score_expr = table.score_expression.as_deref()
            .unwrap_or("ts_rank(to_tsvector('english', search_text), query)");
        
        format!(
            r#"
            WITH search_query AS (
                SELECT plainto_tsquery('english', $1) AS query
            ),
            search_results AS (
                SELECT 
                    {id_column} as id,
                    {search_columns} as search_text,
                    {score_expr} as score,
                    {timestamp_expr}
                FROM {table_name}, search_query
                WHERE to_tsvector('english', {search_columns}) @@ query
                ORDER BY score DESC
                LIMIT {limit}
            )
            SELECT * FROM search_results
            "#,
            id_column = table.id_column,
            search_columns = search_columns,
            score_expr = score_expr,
            timestamp_expr = table.timestamp_column.as_deref()
                .map(|col| format!("{} as timestamp", col))
                .unwrap_or("NOW() as timestamp".to_string()),
            table_name = table.name,
            limit = limit
        )
    }
    
    /// Build semantic search query using embeddings
    fn build_semantic_query(&self, embedding: &[f32], table: &str, limit: usize) -> String {
        format!(
            r#"
            SELECT 
                id,
                content,
                1 - (embedding <=> $1::vector) as score,
                created_at as timestamp
            FROM {table}_embeddings
            ORDER BY embedding <=> $1::vector
            LIMIT {limit}
            "#,
            table = table,
            limit = limit
        )
    }
}

impl DatabaseSearchAgent {
    pub async fn new(config: DatabaseConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .connect_timeout(config.connection_timeout)
            .connect(&config.connection_string)
            .await?;
        
        let query_builder = QueryBuilder::new(config.search_tables.clone());
        
        Ok(Self {
            pool,
            config: Arc::new(config),
            metrics: Arc::new(RwLock::new(AgentMetrics::default())),
            query_builder,
        })
    }
    
    /// Execute full-text search
    async fn search_fulltext(
        &self,
        query: &str,
        options: &SearchOptions,
    ) -> Result<Vec<RawResult>, Box<dyn std::error::Error>> {
        let mut all_results = Vec::new();
        
        for table in &self.config.search_tables {
            let sql = self.query_builder.build_search_query(query, table, options.max_results);
            
            let rows = sqlx::query(&sql)
                .bind(query)
                .fetch_all(&self.pool)
                .await?;
            
            for row in rows {
                let result = self.row_to_result(row, &table.name)?;
                all_results.push(result);
            }
        }
        
        // Sort by score
        all_results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        all_results.truncate(options.max_results);
        
        Ok(all_results)
    }
    
    /// Execute structured query
    async fn search_structured(
        &self,
        query: &str,
        options: &SearchOptions,
    ) -> Result<Vec<RawResult>, Box<dyn std::error::Error>> {
        // Parse structured query (simplified example)
        let parts: Vec<&str> = query.split_whitespace().collect();
        if parts.len() < 3 {
            return Err("Invalid structured query format".into());
        }
        
        let field = parts[0];
        let operator = parts[1];
        let value = parts[2..].join(" ");
        
        let sql = format!(
            "SELECT * FROM documents WHERE {} {} $1 LIMIT $2",
            field, operator
        );
        
        let rows = sqlx::query(&sql)
            .bind(&value)
            .bind(options.max_results as i64)
            .fetch_all(&self.pool)
            .await?;
        
        let mut results = Vec::new();
        for row in rows {
            results.push(self.row_to_result(row, "documents")?);
        }
        
        Ok(results)
    }
    
    /// Convert database row to RawResult
    fn row_to_result(&self, row: PgRow, table_name: &str) -> Result<RawResult, Box<dyn std::error::Error>> {
        let mut metadata = HashMap::new();
        metadata.insert("source".to_string(), json!("database"));
        metadata.insert("table".to_string(), json!(table_name));
        
        // Extract common fields
        let id: i64 = row.try_get("id").unwrap_or(0);
        let search_text: String = row.try_get("search_text").unwrap_or_default();
        let score: f64 = row.try_get("score").unwrap_or(0.5);
        let timestamp: chrono::DateTime<chrono::Utc> = row.try_get("timestamp")
            .unwrap_or_else(|_| chrono::Utc::now());
        
        metadata.insert("id".to_string(), json!(id));
        
        Ok(RawResult {
            content: search_text,
            metadata,
            score,
            timestamp: timestamp.timestamp_millis() as u64,
        })
    }
    
    /// Run parallel queries
    async fn run_parallel_queries(
        &self,
        queries: Vec<String>,
        options: &SearchOptions,
    ) -> Result<Vec<RawResult>, Box<dyn std::error::Error>> {
        use futures::future::join_all;
        
        let futures: Vec<_> = queries
            .into_iter()
            .map(|query| {
                let pool = self.pool.clone();
                let limit = options.max_results;
                async move {
                    sqlx::query(&query)
                        .bind(limit as i64)
                        .fetch_all(&pool)
                        .await
                }
            })
            .collect();
        
        let results = join_all(futures).await;
        let mut all_rows = Vec::new();
        
        for result in results {
            match result {
                Ok(rows) => {
                    for row in rows {
                        if let Ok(raw_result) = self.row_to_result(row, "multi_table") {
                            all_rows.push(raw_result);
                        }
                    }
                }
                Err(e) => eprintln!("Query failed: {}", e),
            }
        }
        
        Ok(all_rows)
    }
}

#[async_trait]
impl SearchAgent for DatabaseSearchAgent {
    fn name(&self) -> &str {
        "database"
    }
    
    fn supported_queries(&self) -> Vec<QueryType> {
        vec![
            QueryType::FullText,
            QueryType::Structured,
            QueryType::Semantic,
        ]
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
        
        // Determine query type and execute
        let results = if query.contains(" WHERE ") || query.contains(" = ") {
            self.search_structured(query, &options).await
        } else {
            self.search_fulltext(query, &options).await
        };
        
        // Update metrics based on result
        match &results {
            Ok(res) => {
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
        
        // Simple health check query
        let row = sqlx::query("SELECT 1 as health")
            .fetch_one(&self.pool)
            .await?;
        
        let health: i32 = row.get("health");
        let latency_ms = start.elapsed().as_millis() as u64;
        
        let metrics = self.metrics.read();
        let error_rate = if metrics.total_searches > 0 {
            metrics.failed_searches as f64 / metrics.total_searches as f64
        } else {
            0.0
        };
        
        Ok(HealthStatus {
            healthy: health == 1,
            latency_ms,
            error_rate,
            last_check: chrono::Utc::now().timestamp_millis() as u64,
        })
    }
    
    fn get_metrics(&self) -> AgentMetrics {
        self.metrics.read().clone()
    }
}

// Extension trait for pgvector support
trait VectorExt {
    fn build_vector_query(&self, embedding: &[f32], limit: usize) -> String;
}

impl VectorExt for QueryBuilder {
    fn build_vector_query(&self, embedding: &[f32], limit: usize) -> String {
        let embedding_str = embedding.iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join(",");
        
        format!(
            r#"
            SELECT 
                id,
                content,
                1 - (embedding <=> '[{}]'::vector) as score,
                created_at as timestamp
            FROM embeddings
            ORDER BY embedding <=> '[{}]'::vector
            LIMIT {}
            "#,
            embedding_str, embedding_str, limit
        )
    }
}