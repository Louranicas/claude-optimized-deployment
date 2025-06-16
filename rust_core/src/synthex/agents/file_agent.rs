use crate::synthex::Result;
// File Search Agent - Local file system search
use super::*;

use tokio::fs;
use walkdir::WalkDir;
use std::path::Path;
use grep::{regex::RegexMatcher, searcher::{Searcher, SearcherBuilder, Sink, SinkMatch}};
use std::collections::HashMap;
use serde_json::json;

// Helper macro for hashmaps
macro_rules! hashmap {
    ($($key:expr => $value:expr),* $(,)?) => {{
        let mut map = HashMap::new();
        $(map.insert($key, $value);)*
        map
    }};
}

/// File search agent for local file system
pub struct FileSearchAgent {
    config: Arc<FileSearchConfig>,
    metrics: Arc<RwLock<AgentMetrics>>,
}

/// File search configuration
#[derive(Clone)]
pub struct FileSearchConfig {
    pub root_paths: Vec<String>,
    pub exclude_patterns: Vec<String>,
    pub max_file_size: u64,
    pub supported_extensions: Vec<String>,
}

impl Default for FileSearchConfig {
    fn default() -> Self {
        Self {
            root_paths: vec![".".to_string()],
            exclude_patterns: vec![
                "node_modules".to_string(),
                ".git".to_string(),
                "target".to_string(),
                "dist".to_string(),
            ],
            max_file_size: 10 * 1024 * 1024, // 10MB
            supported_extensions: vec![
                "txt".to_string(), "md".to_string(), "rs".to_string(),
                "py".to_string(), "js".to_string(), "ts".to_string(),
                "json".to_string(), "yaml".to_string(), "toml".to_string(),
            ],
        }
    }
}

impl FileSearchAgent {
    pub fn new(config: FileSearchConfig) -> Self {
        Self {
            config: Arc::new(config),
            metrics: Arc::new(RwLock::new(AgentMetrics::default())),
        }
    }
    
    /// Search files using grep
    async fn search_files(
        &self,
        query: &str,
        options: &SearchOptions,
    ) -> Result<Vec<RawResult>> {
        let mut results = Vec::new();
        let matcher = RegexMatcher::new(query)?;
        let mut searcher = SearcherBuilder::new().build();
        
        for root_path in &self.config.root_paths {
            for entry in WalkDir::new(root_path)
                .into_iter()
                .filter_entry(|e| self.should_search(e.path()))
            {
                let entry = entry?;
                let path = entry.path();
                
                if path.is_file() {
                    match self.search_file(&mut searcher, &matcher, path, query).await {
                        Ok(mut file_results) => results.append(&mut file_results),
                        Err(e) => eprintln!("Error searching {}: {}", path.display(), e),
                    }
                }
                
                if results.len() >= options.max_results {
                    break;
                }
            }
        }
        
        results.truncate(options.max_results);
        Ok(results)
    }
    
    /// Check if path should be searched
    fn should_search(&self, path: &Path) -> bool {
        // Check exclude patterns
        let path_str = path.to_string_lossy();
        for pattern in &self.config.exclude_patterns {
            if path_str.contains(pattern) {
                return false;
            }
        }
        
        // Check extension
        if let Some(ext) = path.extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            self.config.supported_extensions.contains(&ext_str)
        } else {
            false
        }
    }
    
    /// Search individual file
    async fn search_file(
        &self,
        searcher: &mut Searcher,
        matcher: &RegexMatcher,
        path: &Path,
        query: &str,
    ) -> Result<Vec<RawResult>> {
        let content = fs::read(path).await?;
        
        // Check file size
        if content.len() > self.config.max_file_size as usize {
            return Ok(vec![]);
        }
        
        let mut matches = Vec::new();
        let mut match_sink = MatchSink::new(&mut matches);
        
        searcher.search_slice(matcher, &content, &mut match_sink)?;
        
        // Convert matches to results
        let results: Vec<RawResult> = matches
            .into_iter()
            .map(|m| {
                let line_content = String::from_utf8_lossy(&content[m.start..m.end]).to_string();
                
                RawResult {
                    content: format!("{}:{}: {}", path.display(), m.line_number, line_content),
                    metadata: hashmap!{
                        "source".to_string() => json!("file"),
                        "path".to_string() => json!(path.to_string_lossy()),
                        "line".to_string() => json!(m.line_number),
                        "query".to_string() => json!(query)
                    },
                    score: 0.9,
                    timestamp: chrono::Utc::now().timestamp_millis() as u64,
                }
            })
            .collect();
        
        Ok(results)
    }
}

/// Match information
struct Match {
    start: usize,
    end: usize,
    line_number: u64,
}

/// Custom sink for collecting matches
struct MatchSink<'a> {
    matches: &'a mut Vec<Match>,
}

impl<'a> MatchSink<'a> {
    fn new(matches: &'a mut Vec<Match>) -> Self {
        Self { matches }
    }
}

impl<'a> Sink for MatchSink<'a> {
    type Error = std::io::Error;
    
    fn matched(
        &mut self,
        _searcher: &Searcher,
        mat: &SinkMatch<'_>,
    ) -> std::result::Result<bool, Self::Error> {
        self.matches.push(Match {
            start: mat.absolute_byte_offset() as usize,
            end: (mat.absolute_byte_offset() + mat.bytes().len() as u64) as usize,
            line_number: mat.line_number().unwrap_or(0),
        });
        Ok(true)
    }
}

#[async_trait]
impl SearchAgent for FileSearchAgent {
    fn name(&self) -> &str {
        "file"
    }
    
    fn supported_queries(&self) -> Vec<QueryType> {
        vec![QueryType::FullText, QueryType::Regex]
    }
    
    async fn search(
        &self,
        query: &str,
        options: SearchOptions,
    ) -> Result<Vec<RawResult>> {
        let start = std::time::Instant::now();
        
        // Update metrics
        {
            let mut metrics = self.metrics.write();
            metrics.total_searches += 1;
        }
        
        let results = self.search_files(query, &options).await;
        
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
    
    async fn health_check(&self) -> Result<HealthStatus> {
        let start = std::time::Instant::now();
        
        // Check if root paths exist
        let mut all_exist = true;
        for path in &self.config.root_paths {
            if !Path::new(path).exists() {
                all_exist = false;
                break;
            }
        }
        
        let latency_ms = start.elapsed().as_millis() as u64;
        
        let metrics = self.metrics.read();
        let error_rate = if metrics.total_searches > 0 {
            metrics.failed_searches as f64 / metrics.total_searches as f64
        } else {
            0.0
        };
        
        Ok(HealthStatus {
            healthy: all_exist,
            latency_ms,
            error_rate,
            last_check: chrono::Utc::now().timestamp_millis() as u64,
        })
    }
    
    fn get_metrics(&self) -> AgentMetrics {
        // Use try_read to avoid blocking
        self.metrics.try_read().map(|m| m.clone()).unwrap_or_default()
    }
}
