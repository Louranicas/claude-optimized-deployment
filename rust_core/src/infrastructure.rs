// ============================================================================
// Infrastructure Module - High-Performance Infrastructure Operations
// ============================================================================

use pyo3::prelude::*;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{TcpStream, SocketAddr, IpAddr};
use std::time::Duration;
use std::sync::Arc;
use dashmap::DashMap;
use tracing::{info, debug, warn};

use crate::{CoreError, CoreResult};

/// Register infrastructure functions with Python module
pub fn register_module(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(scan_services_py, m)?)?;
    m.add_function(wrap_pyfunction!(parse_config_py, m)?)?;
    m.add_function(wrap_pyfunction!(analyze_logs_py, m)?)?;
    m.add_class::<ServiceScanner>()?;
    m.add_class::<ConfigParser>()?;
    m.add_class::<LogAnalyzer>()?;
    Ok(())
}

// ========================= Service Scanner =========================

#[pyclass]
#[derive(Clone)]
pub struct ServiceScanner {
    timeout_ms: u64,
    max_threads: usize,
    results_cache: Arc<DashMap<String, bool>>,
}

#[pymethods]
impl ServiceScanner {
    #[new]
    fn new(timeout_ms: Option<u64>, max_threads: Option<usize>) -> Self {
        Self {
            timeout_ms: timeout_ms.unwrap_or(1000),
            max_threads: max_threads.unwrap_or(100),
            results_cache: Arc::new(DashMap::new()),
        }
    }
    
    /// Scan multiple services in parallel
    fn scan_services(&self, _py: Python, targets: Vec<(String, u16)>) -> PyResult<Vec<bool>> {
        info!("Scanning {} services", targets.len());
        
        // Configure thread pool
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(self.max_threads)
            .build()
            .map_err(|e| CoreError::Infrastructure(format!("Thread pool error: {}", e)))?;
        
        // Scan in parallel
        let timeout = Duration::from_millis(self.timeout_ms);
        let cache = Arc::clone(&self.results_cache);
        
        let results = pool.install(|| {
            targets
                .par_iter()
                .map(|(host, port)| {
                    let key = format!("{}:{}", host, port);
                    
                    // Check cache first
                    if let Some(cached) = cache.get(&key) {
                        return *cached.value();
                    }
                    
                    // Perform scan
                    let addr = format!("{}:{}", host, port);
                    let is_up = match addr.parse::<SocketAddr>() {
                        Ok(socket_addr) => {
                            TcpStream::connect_timeout(&socket_addr, timeout).is_ok()
                        }
                        Err(_) => false,
                    };
                    
                    // Cache result
                    cache.insert(key, is_up);
                    is_up
                })
                .collect()
        });
        
        debug!("Scan complete: {} services checked", results.len());
        Ok(results)
    }
    
    /// Clear the results cache
    fn clear_cache(&self) {
        self.results_cache.clear();
        info!("Service scanner cache cleared");
    }
}

/// Python function for quick service scanning
#[pyfunction]
fn scan_services_py(_py: Python, services: Vec<(String, u16)>) -> PyResult<HashMap<String, bool>> {
    let scanner = ServiceScanner::new(Some(500), Some(50));
    let results = scanner.scan_services(_py, services.clone())?;
    
    let mut map = HashMap::new();
    for ((host, port), is_up) in services.into_iter().zip(results) {
        map.insert(format!("{}:{}", host, port), is_up);
    }
    
    Ok(map)
}

// ========================= Configuration Parser =========================

#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub name: String,
    pub replicas: u32,
    pub cpu_millicores: u32,
    pub memory_mb: u32,
    pub ports: Vec<u16>,
    pub environment: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InfrastructureConfig {
    pub services: HashMap<String, ServiceConfig>,
    pub global_settings: HashMap<String, serde_json::Value>,
}

#[pyclass]
pub struct ConfigParser {
    validated_configs: Arc<DashMap<String, InfrastructureConfig>>,
}

#[pymethods]
impl ConfigParser {
    #[new]
    fn new() -> Self {
        Self {
            validated_configs: Arc::new(DashMap::new()),
        }
    }
    
    /// Parse YAML configuration with validation
    fn parse_yaml(&self, yaml_content: &str) -> PyResult<String> {
        let config: InfrastructureConfig = serde_yaml::from_str(yaml_content)
            .map_err(|e| CoreError::Serialization(format!("YAML parse error: {}", e)))?;
        
        // Validate configuration
        self.validate_config(&config)?;
        
        // Cache validated config
        let config_id = uuid::Uuid::new_v4().to_string();
        self.validated_configs.insert(config_id.clone(), config);
        
        // Return as JSON
        let json = serde_json::to_string_pretty(
            &self.validated_configs.get(&config_id).unwrap().value()
        ).map_err(|e| CoreError::Serialization(format!("JSON serialize error: {}", e)))?;
        
        Ok(json)
    }
    
    /// Validate infrastructure configuration
    fn validate_config(&self, config: &InfrastructureConfig) -> CoreResult<()> {
        for (name, service) in &config.services {
            // Validate resources
            if service.cpu_millicores < 100 {
                return Err(CoreError::Infrastructure(
                    format!("Service {} has insufficient CPU: {}m", name, service.cpu_millicores)
                ));
            }
            
            if service.memory_mb < 128 {
                return Err(CoreError::Infrastructure(
                    format!("Service {} has insufficient memory: {}MB", name, service.memory_mb)
                ));
            }
            
            // Check for port conflicts
            let mut seen_ports = std::collections::HashSet::new();
            for port in &service.ports {
                if !seen_ports.insert(port) {
                    return Err(CoreError::Infrastructure(
                        format!("Port {} is duplicated in service {}", port, name)
                    ));
                }
            }
        }
        
        Ok(())
    }
}

/// Python function for quick config parsing
#[pyfunction]
fn parse_config_py(yaml_content: &str) -> PyResult<HashMap<String, serde_json::Value>> {
    let parser = ConfigParser::new();
    let json_str = parser.parse_yaml(yaml_content)?;
    let config: HashMap<String, serde_json::Value> = serde_json::from_str(&json_str)
        .map_err(|e| CoreError::Serialization(e.to_string()))?;
    Ok(config)
}

// ========================= Log Analyzer =========================

#[pyclass]
pub struct LogAnalyzer {
    patterns: HashMap<String, regex::Regex>,
    #[pyo3(get)]
    total_lines: usize,
    #[pyo3(get)]
    error_count: usize,
    #[pyo3(get)]
    warning_count: usize,
}

#[pymethods]
impl LogAnalyzer {
    #[new]
    fn new() -> Self {
        let mut patterns = HashMap::new();
        patterns.insert(
            "error".to_string(),
            regex::Regex::new(r"(?i)(error|exception|failed)").unwrap()
        );
        patterns.insert(
            "warning".to_string(),
            regex::Regex::new(r"(?i)(warn|warning|deprecated)").unwrap()
        );
        patterns.insert(
            "timestamp".to_string(),
            regex::Regex::new(r"\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}").unwrap()
        );
        
        Self {
            patterns,
            total_lines: 0,
            error_count: 0,
            warning_count: 0,
        }
    }
    
    /// Analyze logs at high speed using parallel processing
    fn analyze_logs(&mut self, _py: Python, log_content: &str) -> PyResult<HashMap<String, usize>> {
        let lines: Vec<&str> = log_content.lines().collect();
        self.total_lines = lines.len();
        
        info!("Analyzing {} log lines", self.total_lines);
        
        // Process in parallel chunks
        let error_pattern = self.patterns["error"].clone();
        let warning_pattern = self.patterns["warning"].clone();
        
        let (errors, warnings) = lines
            .par_chunks(1000)
            .map(|chunk| {
                let mut chunk_errors = 0;
                let mut chunk_warnings = 0;
                
                for line in chunk {
                    if error_pattern.is_match(line) {
                        chunk_errors += 1;
                    }
                    if warning_pattern.is_match(line) {
                        chunk_warnings += 1;
                    }
                }
                
                (chunk_errors, chunk_warnings)
            })
            .reduce(
                || (0, 0),
                |(e1, w1), (e2, w2)| (e1 + e2, w1 + w2)
            );
        
        self.error_count = errors;
        self.warning_count = warnings;
        
        let mut results = HashMap::new();
        results.insert("total_lines".to_string(), self.total_lines);
        results.insert("errors".to_string(), errors);
        results.insert("warnings".to_string(), warnings);
        
        // Pattern frequency analysis
        for (name, pattern) in &self.patterns {
            let count = lines
                .par_iter()
                .filter(|line| pattern.is_match(line))
                .count();
            results.insert(name.clone(), count);
        }
        
        debug!("Log analysis complete: {} errors, {} warnings", errors, warnings);
        Ok(results)
    }
    
    /// Extract time-based patterns
    fn analyze_temporal_patterns(&self, _py: Python, log_content: &str) -> PyResult<Vec<(String, usize)>> {
        let timestamp_pattern = &self.patterns["timestamp"];
        let mut hourly_counts: HashMap<String, usize> = HashMap::new();
        
        for line in log_content.lines() {
            if let Some(capture) = timestamp_pattern.find(line) {
                let timestamp_str = capture.as_str();
                if timestamp_str.len() >= 13 {
                    let hour = &timestamp_str[..13];
                    *hourly_counts.entry(hour.to_string()).or_insert(0) += 1;
                }
            }
        }
        
        let mut sorted: Vec<(String, usize)> = hourly_counts.into_iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        
        Ok(sorted)
    }
}

/// Python function for quick log analysis
#[pyfunction]
fn analyze_logs_py(_py: Python, log_content: &str) -> PyResult<HashMap<String, usize>> {
    let mut analyzer = LogAnalyzer::new();
    analyzer.analyze_logs(_py, log_content)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_service_scanner() {
        let scanner = ServiceScanner::new(Some(100), Some(4));
        Python::with_gil(|py| {
            let targets = vec![
                ("127.0.0.1".to_string(), 80),
                ("localhost".to_string(), 443),
            ];
            let results = scanner.scan_services(py, targets).unwrap();
            assert_eq!(results.len(), 2);
        });
    }
    
    #[test]
    fn test_config_parser() {
        let parser = ConfigParser::new();
        let yaml = r#"
services:
  web:
    name: web-service
    replicas: 3
    cpu_millicores: 500
    memory_mb: 1024
    ports: [8080, 8443]
    environment:
      ENV: production
global_settings:
  region: us-east-1
"#;
        let result = parser.parse_yaml(yaml).unwrap();
        assert!(result.contains("web-service"));
    }
    
    #[test]
    fn test_log_analyzer() {
        let mut analyzer = LogAnalyzer::new();
        let logs = "2024-01-01 10:00:00 ERROR: Something failed\n\
                   2024-01-01 10:01:00 WARNING: Deprecated function\n\
                   2024-01-01 10:02:00 INFO: All good";
        
        Python::with_gil(|py| {
            let results = analyzer.analyze_logs(py, logs).unwrap();
            assert_eq!(results["errors"], 1);
            assert_eq!(results["warnings"], 1);
            assert_eq!(results["total_lines"], 3);
        });
    }
}
