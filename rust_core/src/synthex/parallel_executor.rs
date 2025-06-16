// Parallel Executor - High-performance concurrent search execution
use super::*;
use crate::synthex::query::SubQuery;
use crate::synthex::query_parser::{ExecutionPlan, ExecutionStrategy};

use tokio::sync::{Semaphore, mpsc};
use tokio::time::{timeout, Duration};
use std::sync::Arc;
use dashmap::DashMap;
use futures::stream::{FuturesUnordered, StreamExt};
use crossbeam::queue::ArrayQueue;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Raw search results before aggregation
#[derive(Debug, Clone)]
pub struct RawSearchResults {
    pub sub_query_id: String,
    pub results: Vec<agents::RawResult>,
    pub execution_time_ms: u64,
    pub source: String,
    pub errors: Vec<SearchError>,
}

/// Individual raw result
#[derive(Debug, Clone)]
pub struct RawResult {
    pub content: String,
    pub metadata: HashMap<String, serde_json::Value>,
    pub score: f64,
    pub timestamp: u64,
}

/// Search error information
#[derive(Debug, Clone)]
pub struct SearchError {
    pub source: String,
    pub error_type: String,
    pub message: String,
    pub recoverable: bool,
}

/// Connection pool for reusing HTTP connections
struct ConnectionPool {
    pools: DashMap<String, Arc<ArrayQueue<reqwest::Client>>>,
    max_connections_per_host: usize,
}

impl ConnectionPool {
    fn new(max_connections_per_host: usize) -> Self {
        Self {
            pools: DashMap::new(),
            max_connections_per_host,
        }
    }
    
    async fn get_connection(&self, host: &str) -> Option<reqwest::Client> {
        if let Some(pool) = self.pools.get(host) {
            pool.pop()
        } else {
            None
        }
    }
    
    fn return_connection(&self, host: &str, conn: reqwest::Client) {
        self.pools
            .entry(host.to_string())
            .or_insert_with(|| Arc::new(ArrayQueue::new(self.max_connections_per_host)))
            .push(conn)
            .ok();
    }
}

/// High-performance parallel executor
pub struct ParallelExecutor {
    config: Arc<SynthexConfig>,
    semaphore: Arc<Semaphore>,
    connection_pool: Arc<ConnectionPool>,
    metrics: Arc<ExecutorMetrics>,
    work_stealer: Arc<WorkStealer>,
}

/// Executor metrics for monitoring
struct ExecutorMetrics {
    total_queries: AtomicU64,
    active_queries: AtomicUsize,
    failed_queries: AtomicU64,
    total_execution_time: AtomicU64,
}

impl ExecutorMetrics {
    fn new() -> Self {
        Self {
            total_queries: AtomicU64::new(0),
            active_queries: AtomicUsize::new(0),
            failed_queries: AtomicU64::new(0),
            total_execution_time: AtomicU64::new(0),
        }
    }
}

/// Work-stealing scheduler for load balancing
struct WorkStealer {
    queues: Vec<Arc<ArrayQueue<SubQuery>>>,
    worker_count: usize,
}

impl WorkStealer {
    fn new(worker_count: usize) -> Self {
        let queues = (0..worker_count)
            .map(|_| Arc::new(ArrayQueue::new(1000)))
            .collect();
        
        Self {
            queues,
            worker_count,
        }
    }
    
    fn submit(&self, query: SubQuery) -> Result<(), SubQuery> {
        // Try to find the least loaded queue
        let mut min_len = usize::MAX;
        let mut target_queue = 0;
        
        for (i, queue) in self.queues.iter().enumerate() {
            let len = queue.len();
            if len < min_len {
                min_len = len;
                target_queue = i;
            }
        }
        
        self.queues[target_queue].push(query)
    }
    
    fn steal(&self, worker_id: usize) -> Option<SubQuery> {
        // First check own queue
        if let Some(query) = self.queues[worker_id].pop() {
            return Some(query);
        }
        
        // Try to steal from other queues
        for i in 0..self.worker_count {
            if i != worker_id {
                if let Some(query) = self.queues[i].pop() {
                    return Some(query);
                }
            }
        }
        
        None
    }
}

impl ParallelExecutor {
    pub fn new(config: Arc<SynthexConfig>) -> Result<Self> {
        let worker_count = num_cpus::get() * 2; // Oversubscribe for I/O bound work
        
        Ok(Self {
            config: config.clone(),
            semaphore: Arc::new(Semaphore::new(config.max_parallel_searches)),
            connection_pool: Arc::new(ConnectionPool::new(config.connection_pool_size)),
            metrics: Arc::new(ExecutorMetrics::new()),
            work_stealer: Arc::new(WorkStealer::new(worker_count)),
        })
    }
    
    /// Execute search plan in parallel
    pub async fn execute(&self, plan: ExecutionPlan) -> Result<Vec<RawSearchResults>> {
        let start_time = std::time::Instant::now();
        
        // Update metrics
        self.metrics.total_queries.fetch_add(plan.sub_queries.len() as u64, Ordering::Relaxed);
        
        match plan.strategy {
            ExecutionStrategy::Parallel => self.execute_parallel(plan.sub_queries).await,
            ExecutionStrategy::Sequential => self.execute_sequential(plan.sub_queries).await,
            ExecutionStrategy::MapReduce => self.execute_map_reduce(plan.sub_queries).await,
            ExecutionStrategy::ScatterGather => self.execute_scatter_gather(plan.sub_queries).await,
            ExecutionStrategy::Custom(ref strategy) => self.execute_custom(strategy, plan.sub_queries).await,
        }
    }
    
    /// Execute queries in parallel
    async fn execute_parallel(&self, queries: Vec<SubQuery>) -> Result<Vec<RawSearchResults>> {
        let mut futures = FuturesUnordered::new();
        
        for query in queries {
            let permit = self.semaphore.clone().acquire_owned().await?;
            let executor = self.clone();
            
            futures.push(tokio::spawn(async move {
                let _permit = permit; // Hold permit until done
                executor.execute_single_query(query).await
            }));
        }
        
        let mut results = Vec::new();
        while let Some(result) = futures.next().await {
            match result {
                Ok(Ok(search_result)) => results.push(search_result),
                Ok(Err(e)) => eprintln!("Query execution error: {}", e),
                Err(e) => eprintln!("Task join error: {}", e),
            }
        }
        
        Ok(results)
    }
    
    /// Execute queries sequentially
    async fn execute_sequential(&self, queries: Vec<SubQuery>) -> Result<Vec<RawSearchResults>> {
        let mut results = Vec::new();
        
        for query in queries {
            let result = self.execute_single_query(query).await?;
            results.push(result);
        }
        
        Ok(results)
    }
    
    /// Execute with map-reduce pattern
    async fn execute_map_reduce(&self, queries: Vec<SubQuery>) -> Result<Vec<RawSearchResults>> {
        // Map phase - execute all queries
        let mapped_results = self.execute_parallel(queries).await?;
        
        // Reduce phase would be handled by aggregator
        Ok(mapped_results)
    }
    
    /// Execute with scatter-gather pattern
    async fn execute_scatter_gather(&self, queries: Vec<SubQuery>) -> Result<Vec<RawSearchResults>> {
        let (tx, mut rx) = mpsc::channel(queries.len());
        
        // Scatter phase - distribute queries to workers
        for (worker_id, query) in queries.into_iter().enumerate() {
            let tx = tx.clone();
            let executor = self.clone();
            
            tokio::spawn(async move {
                if let Ok(result) = executor.execute_single_query(query).await {
                    tx.send(result).await.ok();
                }
            });
        }
        
        drop(tx); // Close sender
        
        // Gather phase - collect results
        let mut results = Vec::new();
        while let Some(result) = rx.recv().await {
            results.push(result);
        }
        
        Ok(results)
    }
    
    /// Execute custom strategy
    async fn execute_custom(&self, strategy: &str, queries: Vec<SubQuery>) -> Result<Vec<RawSearchResults>> {
        // Placeholder for custom strategies
        match strategy {
            "priority" => self.execute_by_priority(queries).await,
            _ => self.execute_parallel(queries).await,
        }
    }
    
    /// Execute queries by priority
    async fn execute_by_priority(&self, mut queries: Vec<SubQuery>) -> Result<Vec<RawSearchResults>> {
        // Sort by priority (highest first)
        queries.sort_by(|a, b| b.priority.cmp(&a.priority));
        
        // Execute high priority queries first
        let high_priority: Vec<_> = queries.iter().filter(|q| q.priority > 80).cloned().collect();
        let low_priority: Vec<_> = queries.iter().filter(|q| q.priority <= 80).cloned().collect();
        
        let mut results = self.execute_parallel(high_priority).await?;
        results.extend(self.execute_parallel(low_priority).await?);
        
        Ok(results)
    }
    
    /// Execute a single query
    async fn execute_single_query(&self, query: SubQuery) -> Result<RawSearchResults> {
        let start_time = std::time::Instant::now();
        self.metrics.active_queries.fetch_add(1, Ordering::Relaxed);
        
        let mut results = Vec::new();
        let mut errors = Vec::new();
        
        // Execute query against each source
        for source in &query.sources {
            match self.search_source(source, &query.query).await {
                Ok(source_results) => results.extend(source_results),
                Err(e) => errors.push(SearchError {
                    source: source.clone(),
                    error_type: "search_error".to_string(),
                    message: e.to_string(),
                    recoverable: true,
                }),
            }
        }
        
        self.metrics.active_queries.fetch_sub(1, Ordering::Relaxed);
        let execution_time = start_time.elapsed().as_millis() as u64;
        self.metrics.total_execution_time.fetch_add(execution_time, Ordering::Relaxed);
        
        Ok(RawSearchResults {
            sub_query_id: query.id,
            results,
            execution_time_ms: execution_time,
            source: query.sources.join(","),
            errors,
        })
    }
    
    /// Search a specific source
    async fn search_source(&self, source: &str, query: &str) -> Result<Vec<agents::RawResult>> {
        // Placeholder implementation - would dispatch to appropriate search agent
        match source {
            "web" => self.search_web(query).await,
            "database" => self.search_database(query).await,
            "knowledge_base" => self.search_knowledge_base(query).await,
            "api" => self.search_api(query).await,
            _ => Ok(vec![]),
        }
    }
    
    /// Web search implementation
    async fn search_web(&self, query: &str) -> Result<Vec<agents::RawResult>> {
        // Simulate web search with timeout
        let search_future = async {
            // In production, would use real web search API
            tokio::time::sleep(Duration::from_millis(50)).await;
            
            vec![agents::RawResult {
                content: format!("Web result for: {}", query),
                metadata: HashMap::new(),
                score: 0.9,
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
            }]
        };
        
        match timeout(Duration::from_millis(self.config.query_timeout_ms), search_future).await {
            Ok(results) => Ok(results),
            Err(_) => Err(SynthexError::TimeoutError(self.config.query_timeout_ms)),
        }
    }
    
    /// Database search implementation
    async fn search_database(&self, query: &str) -> Result<Vec<agents::RawResult>> {
        // Simulate database query
        tokio::time::sleep(Duration::from_millis(20)).await;
        
        Ok(vec![agents::RawResult {
            content: format!("Database result for: {}", query),
            metadata: HashMap::new(),
            score: 0.95,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        }])
    }
    
    /// Knowledge base search
    async fn search_knowledge_base(&self, query: &str) -> Result<Vec<agents::RawResult>> {
        // Simulate KB search
        tokio::time::sleep(Duration::from_millis(10)).await;
        
        Ok(vec![agents::RawResult {
            content: format!("Knowledge base result for: {}", query),
            metadata: HashMap::new(),
            score: 0.85,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        }])
    }
    
    /// API search implementation
    async fn search_api(&self, query: &str) -> Result<Vec<agents::RawResult>> {
        // Simulate API call
        tokio::time::sleep(Duration::from_millis(30)).await;
        
        Ok(vec![agents::RawResult {
            content: format!("API result for: {}", query),
            metadata: HashMap::new(),
            score: 0.88,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        }])
    }
}

// Enable cloning for executor
impl Clone for ParallelExecutor {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            semaphore: self.semaphore.clone(),
            connection_pool: self.connection_pool.clone(),
            metrics: self.metrics.clone(),
            work_stealer: self.work_stealer.clone(),
        }
    }
}

// External dependencies
use chrono;
use hyper;
use num_cpus;