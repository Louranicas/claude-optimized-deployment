# Python-Rust Integration for Infrastructure
**Purpose**: Rust extensions for performance-critical infrastructure operations  
**Context**: Adapted for CODE project infrastructure components

---

## 🚀 Infrastructure-Specific Rust Extensions

### 1. Configuration Parser
```rust
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
struct ServiceConfig {
    name: String,
    replicas: u32,
    cpu_millicores: u32,
    memory_mb: u32,
    ports: Vec<u16>,
    environment: HashMap<String, String>,
}

#[pyfunction]
fn parse_infrastructure_config(yaml_content: &str) -> PyResult<String> {
    // Parse YAML using serde
    let config: InfrastructureConfig = serde_yaml::from_str(yaml_content)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(
            format!("Failed to parse config: {}", e)
        ))?;
    
    // Validate configuration
    validate_config(&config)?;
    
    // Return as JSON for Python consumption
    serde_json::to_string(&config)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            format!("Failed to serialize config: {}", e)
        ))
}
```

### 2. Parallel Infrastructure Scanner
```rust
use rayon::prelude::*;
use std::net::{TcpStream, SocketAddr};
use std::time::Duration;

#[pyclass]
struct InfrastructureScanner {
    timeout_ms: u64,
    max_threads: usize,
}

#[pymethods]
impl InfrastructureScanner {
    #[new]
    fn new(timeout_ms: Option<u64>, max_threads: Option<usize>) -> Self {
        Self {
            timeout_ms: timeout_ms.unwrap_or(1000),
            max_threads: max_threads.unwrap_or(100),
        }
    }
    
    /// Scan multiple hosts and ports in parallel
    fn scan_services(&self, py: Python, targets: Vec<(String, u16)>) -> PyResult<Vec<bool>> {
        // Release GIL for parallel scanning
        py.allow_threads(|| {
            // Configure thread pool
            rayon::ThreadPoolBuilder::new()
                .num_threads(self.max_threads)
                .build()
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                    format!("Failed to create thread pool: {}", e)
                ))?
                .install(|| {
                    // Scan in parallel
                    let results: Vec<bool> = targets
                        .par_iter()
                        .map(|(host, port)| {
                            self.check_service(host, *port)
                        })
                        .collect();
                    
                    Ok(results)
                })
        })
    }
}
```

### 3. Log Analyzer
```rust
use regex::Regex;
use std::collections::HashMap;

#[pyclass]
struct LogAnalyzer {
    patterns: HashMap<String, Regex>,
}

#[pymethods]
impl LogAnalyzer {
    #[new]
    fn new() -> Self {
        let mut patterns = HashMap::new();
        patterns.insert(
            "error".to_string(),
            Regex::new(r"(?i)(error|exception|failed)").unwrap()
        );
        patterns.insert(
            "warning".to_string(),
            Regex::new(r"(?i)(warn|warning|deprecated)").unwrap()
        );
        
        Self { patterns }
    }
    
    /// Analyze logs using parallel processing
    fn analyze_logs(&mut self, _py: Python, log_content: &str) -> PyResult<HashMap<String, usize>> {
        let lines: Vec<&str> = log_content.lines().collect();
        
        // Process in parallel chunks for large logs
        let error_pattern = &self.patterns["error"];
        let warning_pattern = &self.patterns["warning"];
        
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
        
        let mut results = HashMap::new();
        results.insert("errors".to_string(), errors);
        results.insert("warnings".to_string(), warnings);
        results.insert("total_lines".to_string(), lines.len());
        
        Ok(results)
    }
}
```

### 4. Cryptographic Operations
```rust
use sha2::{Sha256, Sha512, Digest};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{SaltString, rand_core::OsRng};

#[pyfunction]
fn hash_passwords_batch(passwords: Vec<String>) -> PyResult<Vec<String>> {
    passwords
        .par_iter()
        .map(|password| {
            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            
            argon2
                .hash_password(password.as_bytes(), &salt)
                .map(|hash| hash.to_string())
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                    format!("Hashing failed: {}", e)
                ))
        })
        .collect()
}
```

## 🔧 Integration with Python Infrastructure Code

### Python Wrapper Example
```python
# infrastructure/fast_ops.py
import rust_infrastructure_lib

class FastInfrastructureOps:
    """Infrastructure operations with optional Rust acceleration."""
    
    def __init__(self):
        self.scanner = rust_infrastructure_lib.InfrastructureScanner(
            timeout_ms=500,
            max_threads=50
        )
        self.log_analyzer = rust_infrastructure_lib.LogAnalyzer()
    
    def scan_services(self, services: List[Tuple[str, int]]) -> Dict[str, bool]:
        """Scan multiple services in parallel.
        
        Benefits from Rust when scanning many services simultaneously.
        Network latency is still the primary bottleneck.
        """
        results = self.scanner.scan_services(services)
        return {
            f"{host}:{port}": is_up 
            for (host, port), is_up in zip(services, results)
        }
    
    def analyze_deployment_logs(self, log_file: str) -> Dict[str, Any]:
        """Analyze deployment logs for issues.
        
        Rust provides benefits for large log files (>10MB) through
        parallel regex matching.
        """
        with open(log_file, 'r') as f:
            content = f.read()
        
        stats = self.log_analyzer.analyze_logs(content)
        
        return {
            "stats": stats,
            "error_rate": stats["errors"] / stats["total_lines"] if stats["total_lines"] > 0 else 0
        }
```

### Performance Considerations
```python
# When Rust helps:
# - Parsing large configuration files (>1MB)
# - Scanning many services in parallel (>50)
# - Processing large log files (>10MB)
# - Batch cryptographic operations

# When Rust doesn't help much:
# - Small configurations (<100KB)
# - Few services (<10)
# - Network-bound operations
# - Database queries

# Example: Benchmark before optimizing
import time

def benchmark_config_parsing():
    with open("large_config.yaml") as f:
        content = f.read()
    
    # Python baseline
    start = time.time()
    python_config = yaml.safe_load(content)
    python_time = time.time() - start
    
    # Rust implementation
    start = time.time()
    rust_config = rust_infrastructure_lib.parse_config(content)
    rust_time = time.time() - start
    
    print(f"Python: {python_time:.3f}s")
    print(f"Rust: {rust_time:.3f}s")
    print(f"Improvement: {python_time/rust_time:.1f}x")
```

## 📦 Building and Distribution

### Cargo.toml for Infrastructure Library
```toml
[package]
name = "rust_infrastructure_lib"
version = "0.1.0"
edition = "2021"

[lib]
name = "rust_infrastructure_lib"
crate-type = ["cdylib"]

[dependencies]
pyo3 = { version = "0.21", features = ["extension-module"] }
rayon = "1.8"
serde = { version = "1.0", features = ["derive"] }
serde_yaml = "0.9"
serde_json = "1.0"
regex = "1.10"
sha2 = "0.10"
argon2 = "0.5"

[profile.release]
lto = true
codegen-units = 1
opt-level = 3
```

## 🎯 Best Practices for Infrastructure Rust Extensions

### 1. Profile First
```python
import cProfile
import pstats

# Find actual bottlenecks
cProfile.run('your_infrastructure_operation()', 'profile.stats')
stats = pstats.Stats('profile.stats')
stats.sort_stats('cumulative').print_stats(10)
```

### 2. Measure Real Improvements
```python
import statistics
import time

def benchmark_operation(func, data, runs=100):
    times = []
    for _ in range(runs):
        start = time.perf_counter()
        func(data)
        times.append(time.perf_counter() - start)
    
    return {
        'mean': statistics.mean(times),
        'median': statistics.median(times),
        'stdev': statistics.stdev(times) if len(times) > 1 else 0
    }
```

### 3. Consider Total System Performance
- Network latency often dominates infrastructure operations
- Database queries are rarely CPU-bound
- Measure end-to-end, not just the Rust portion
- Include serialization overhead in benchmarks

## 📊 Realistic Use Cases

### Service Discovery
- **Scenario**: Scan 100 services across network
- **Python**: Sequential scanning
- **Rust**: Parallel scanning with thread pool
- **Benefit**: Reduces total scan time when network latency permits
- **Limitation**: Still bound by network round-trip time

### Configuration Management
- **Scenario**: Parse 10MB YAML configuration
- **Python**: Standard YAML parser
- **Rust**: Optimized serde parser
- **Benefit**: Faster parsing for large files
- **Trade-off**: Development complexity

### Log Analysis
- **Scenario**: Process 1GB of logs daily
- **Python**: Sequential regex matching
- **Rust**: Parallel chunk processing
- **Benefit**: Better CPU utilization
- **Consideration**: Memory usage patterns

---

*Use Rust where profiling shows clear bottlenecks. Always measure in your specific environment.*