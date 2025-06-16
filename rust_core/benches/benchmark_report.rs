//! Benchmark Report Generator for MCP Manager
//!
//! Generates comprehensive performance reports from benchmark results.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct BenchmarkReport {
    pub metadata: ReportMetadata,
    pub system_info: SystemInfo,
    pub results: Vec<BenchmarkResult>,
    pub analysis: PerformanceAnalysis,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub title: String,
    pub version: String,
    pub generated_at: DateTime<Utc>,
    pub duration: std::time::Duration,
    pub git_commit: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SystemInfo {
    pub os: String,
    pub cpu: String,
    pub cpu_cores: usize,
    pub memory_gb: f64,
    pub rust_version: String,
    pub cargo_version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub name: String,
    pub group: String,
    pub function: String,
    pub throughput: Option<Throughput>,
    pub latency: LatencyMetrics,
    pub memory: Option<MemoryMetrics>,
    pub iterations: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Throughput {
    pub value: f64,
    pub unit: ThroughputUnit,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ThroughputUnit {
    ElementsPerSecond,
    BytesPerSecond,
    RequestsPerSecond,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LatencyMetrics {
    pub min_ns: u64,
    pub max_ns: u64,
    pub mean_ns: u64,
    pub median_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MemoryMetrics {
    pub allocated_bytes: u64,
    pub deallocated_bytes: u64,
    pub peak_usage_bytes: u64,
    pub leaks_detected: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PerformanceAnalysis {
    pub summary: PerformanceSummary,
    pub bottlenecks: Vec<Bottleneck>,
    pub trends: Vec<PerformanceTrend>,
    pub comparisons: Vec<Comparison>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PerformanceSummary {
    pub total_benchmarks: usize,
    pub passed: usize,
    pub failed: usize,
    pub performance_score: f64,
    pub efficiency_rating: EfficiencyRating,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum EfficiencyRating {
    Excellent,
    Good,
    Acceptable,
    NeedsImprovement,
    Poor,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Bottleneck {
    pub component: String,
    pub impact: ImpactLevel,
    pub description: String,
    pub suggested_fix: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ImpactLevel {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PerformanceTrend {
    pub metric: String,
    pub direction: TrendDirection,
    pub change_percentage: f64,
    pub baseline: f64,
    pub current: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TrendDirection {
    Improving,
    Stable,
    Degrading,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Comparison {
    pub benchmark: String,
    pub baseline_value: f64,
    pub current_value: f64,
    pub difference_percentage: f64,
    pub regression: bool,
}

impl BenchmarkReport {
    pub fn new() -> Self {
        Self {
            metadata: ReportMetadata {
                title: "MCP Manager Performance Report".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                generated_at: Utc::now(),
                duration: std::time::Duration::default(),
                git_commit: Self::get_git_commit(),
            },
            system_info: Self::collect_system_info(),
            results: Vec::new(),
            analysis: PerformanceAnalysis {
                summary: PerformanceSummary {
                    total_benchmarks: 0,
                    passed: 0,
                    failed: 0,
                    performance_score: 0.0,
                    efficiency_rating: EfficiencyRating::Good,
                },
                bottlenecks: Vec::new(),
                trends: Vec::new(),
                comparisons: Vec::new(),
            },
            recommendations: Vec::new(),
        }
    }

    fn get_git_commit() -> Option<String> {
        std::process::Command::new("git")
            .args(&["rev-parse", "HEAD"])
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|s| s.trim().to_string())
    }

    fn collect_system_info() -> SystemInfo {
        SystemInfo {
            os: std::env::consts::OS.to_string(),
            cpu: Self::get_cpu_info(),
            cpu_cores: num_cpus::get(),
            memory_gb: Self::get_memory_gb(),
            rust_version: Self::get_rust_version(),
            cargo_version: Self::get_cargo_version(),
        }
    }

    fn get_cpu_info() -> String {
        #[cfg(target_os = "linux")]
        {
            std::fs::read_to_string("/proc/cpuinfo")
                .ok()
                .and_then(|contents| {
                    contents
                        .lines()
                        .find(|line| line.starts_with("model name"))
                        .and_then(|line| line.split(':').nth(1))
                        .map(|s| s.trim().to_string())
                })
                .unwrap_or_else(|| "Unknown CPU".to_string())
        }
        #[cfg(not(target_os = "linux"))]
        {
            "Unknown CPU".to_string()
        }
    }

    fn get_memory_gb() -> f64 {
        #[cfg(target_os = "linux")]
        {
            std::fs::read_to_string("/proc/meminfo")
                .ok()
                .and_then(|contents| {
                    contents
                        .lines()
                        .find(|line| line.starts_with("MemTotal"))
                        .and_then(|line| {
                            line.split_whitespace()
                                .nth(1)
                                .and_then(|s| s.parse::<f64>().ok())
                        })
                })
                .map(|kb| kb / 1024.0 / 1024.0)
                .unwrap_or(0.0)
        }
        #[cfg(not(target_os = "linux"))]
        {
            0.0
        }
    }

    fn get_rust_version() -> String {
        std::process::Command::new("rustc")
            .arg("--version")
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "Unknown".to_string())
    }

    fn get_cargo_version() -> String {
        std::process::Command::new("cargo")
            .arg("--version")
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "Unknown".to_string())
    }

    pub fn add_result(&mut self, result: BenchmarkResult) {
        self.results.push(result);
        self.update_analysis();
    }

    fn update_analysis(&mut self) {
        self.analysis.summary.total_benchmarks = self.results.len();
        self.analysis.summary.passed = self
            .results
            .iter()
            .filter(|r| r.latency.mean_ns > 0)
            .count();
        self.analysis.summary.failed =
            self.analysis.summary.total_benchmarks - self.analysis.summary.passed;

        // Calculate performance score
        self.calculate_performance_score();

        // Identify bottlenecks
        self.identify_bottlenecks();

        // Generate recommendations
        self.generate_recommendations();
    }

    fn calculate_performance_score(&mut self) {
        let mut score = 100.0;

        // Deduct points for slow operations
        for result in &self.results {
            let latency_ms = result.latency.mean_ns as f64 / 1_000_000.0;

            // Define thresholds for different operations
            let threshold = match result.group.as_str() {
                "plugin_registry" => 1.0,   // 1ms for registry ops
                "request_handling" => 10.0, // 10ms for request handling
                "state_transfer" => 50.0,   // 50ms for state transfer
                "hot_reload" => 100.0,      // 100ms for hot reload
                _ => 5.0,                   // 5ms default
            };

            if latency_ms > threshold {
                let penalty = ((latency_ms - threshold) / threshold) * 10.0;
                score -= penalty.min(20.0);
            }
        }

        // Bonus for good throughput
        for result in &self.results {
            if let Some(throughput) = &result.throughput {
                match throughput.unit {
                    ThroughputUnit::RequestsPerSecond => {
                        if throughput.value > 10000.0 {
                            score += 5.0;
                        }
                    }
                    _ => {}
                }
            }
        }

        self.analysis.summary.performance_score = score.max(0.0).min(100.0);

        self.analysis.summary.efficiency_rating = match score {
            s if s >= 90.0 => EfficiencyRating::Excellent,
            s if s >= 75.0 => EfficiencyRating::Good,
            s if s >= 60.0 => EfficiencyRating::Acceptable,
            s if s >= 40.0 => EfficiencyRating::NeedsImprovement,
            _ => EfficiencyRating::Poor,
        };
    }

    fn identify_bottlenecks(&mut self) {
        self.analysis.bottlenecks.clear();

        // Find slowest operations
        let mut slow_ops: Vec<_> = self.results.iter().map(|r| (r, r.latency.p99_ns)).collect();
        slow_ops.sort_by_key(|(_, latency)| std::cmp::Reverse(*latency));

        for (result, latency) in slow_ops.iter().take(5) {
            let latency_ms = *latency as f64 / 1_000_000.0;

            if latency_ms > 100.0 {
                self.analysis.bottlenecks.push(Bottleneck {
                    component: result.name.clone(),
                    impact: ImpactLevel::Critical,
                    description: format!("P99 latency of {:.2}ms is too high", latency_ms),
                    suggested_fix: "Consider optimizing the operation or adding caching"
                        .to_string(),
                });
            } else if latency_ms > 50.0 {
                self.analysis.bottlenecks.push(Bottleneck {
                    component: result.name.clone(),
                    impact: ImpactLevel::High,
                    description: format!(
                        "P99 latency of {:.2}ms may impact user experience",
                        latency_ms
                    ),
                    suggested_fix: "Profile the operation to identify optimization opportunities"
                        .to_string(),
                });
            }
        }

        // Check for memory issues
        for result in &self.results {
            if let Some(memory) = &result.memory {
                if memory.leaks_detected {
                    self.analysis.bottlenecks.push(Bottleneck {
                        component: result.name.clone(),
                        impact: ImpactLevel::Critical,
                        description: "Memory leak detected".to_string(),
                        suggested_fix: "Fix memory management to prevent leaks".to_string(),
                    });
                }
            }
        }
    }

    fn generate_recommendations(&mut self) {
        self.recommendations.clear();

        // Based on performance score
        match self.analysis.summary.efficiency_rating {
            EfficiencyRating::Excellent => {
                self.recommendations.push(
                    "Excellent performance! Continue monitoring for regressions.".to_string(),
                );
            }
            EfficiencyRating::Good => {
                self.recommendations.push(
                    "Good performance overall. Focus on optimizing the slowest operations."
                        .to_string(),
                );
            }
            EfficiencyRating::Acceptable => {
                self.recommendations
                    .push("Performance is acceptable but has room for improvement.".to_string());
                self.recommendations.push(
                    "Consider implementing caching for frequently accessed data.".to_string(),
                );
            }
            EfficiencyRating::NeedsImprovement => {
                self.recommendations.push(
                    "Performance needs significant improvement to meet standards.".to_string(),
                );
                self.recommendations
                    .push("Profile the application to identify performance hotspots.".to_string());
                self.recommendations
                    .push("Consider architectural changes to improve scalability.".to_string());
            }
            EfficiencyRating::Poor => {
                self.recommendations.push(
                    "Critical performance issues detected. Immediate action required.".to_string(),
                );
                self.recommendations
                    .push("Conduct a thorough performance audit of all components.".to_string());
                self.recommendations.push(
                    "Consider rewriting performance-critical sections in more efficient algorithms.".to_string()
                );
            }
        }

        // Specific recommendations based on bottlenecks
        for bottleneck in &self.analysis.bottlenecks {
            match bottleneck.impact {
                ImpactLevel::Critical => {
                    self.recommendations.push(format!(
                        "CRITICAL: Fix {} immediately - {}",
                        bottleneck.component, bottleneck.suggested_fix
                    ));
                }
                ImpactLevel::High => {
                    self.recommendations.push(format!(
                        "HIGH PRIORITY: Optimize {} - {}",
                        bottleneck.component, bottleneck.suggested_fix
                    ));
                }
                _ => {}
            }
        }
    }

    pub fn generate_html_report(&self, path: &Path) -> std::io::Result<()> {
        let mut file = File::create(path)?;

        writeln!(file, "<!DOCTYPE html>")?;
        writeln!(file, "<html>")?;
        writeln!(file, "<head>")?;
        writeln!(file, "    <title>{}</title>", self.metadata.title)?;
        writeln!(file, "    <style>")?;
        writeln!(file, "{}", include_str!("report_style.css"))?;
        writeln!(file, "    </style>")?;
        writeln!(file, "</head>")?;
        writeln!(file, "<body>")?;

        // Header
        writeln!(file, "    <header>")?;
        writeln!(file, "        <h1>{}</h1>", self.metadata.title)?;
        writeln!(
            file,
            "        <p>Generated: {}</p>",
            self.metadata.generated_at
        )?;
        writeln!(
            file,
            "        <p>Version: {} | Commit: {}</p>",
            self.metadata.version,
            self.metadata
                .git_commit
                .as_ref()
                .unwrap_or(&"Unknown".to_string())
        )?;
        writeln!(file, "    </header>")?;

        // System Info
        writeln!(file, "    <section class='system-info'>")?;
        writeln!(file, "        <h2>System Information</h2>")?;
        writeln!(file, "        <table>")?;
        writeln!(
            file,
            "            <tr><td>OS:</td><td>{}</td></tr>",
            self.system_info.os
        )?;
        writeln!(
            file,
            "            <tr><td>CPU:</td><td>{}</td></tr>",
            self.system_info.cpu
        )?;
        writeln!(
            file,
            "            <tr><td>Cores:</td><td>{}</td></tr>",
            self.system_info.cpu_cores
        )?;
        writeln!(
            file,
            "            <tr><td>Memory:</td><td>{:.2} GB</td></tr>",
            self.system_info.memory_gb
        )?;
        writeln!(
            file,
            "            <tr><td>Rust:</td><td>{}</td></tr>",
            self.system_info.rust_version
        )?;
        writeln!(file, "        </table>")?;
        writeln!(file, "    </section>")?;

        // Summary
        writeln!(file, "    <section class='summary'>")?;
        writeln!(file, "        <h2>Performance Summary</h2>")?;
        writeln!(
            file,
            "        <div class='score-card rating-{:?}'>",
            self.analysis.summary.efficiency_rating
        )?;
        writeln!(file, "            <h3>Performance Score</h3>")?;
        writeln!(
            file,
            "            <div class='score'>{:.1}</div>",
            self.analysis.summary.performance_score
        )?;
        writeln!(
            file,
            "            <div class='rating'>{:?}</div>",
            self.analysis.summary.efficiency_rating
        )?;
        writeln!(file, "        </div>")?;
        writeln!(file, "        <div class='stats'>")?;
        writeln!(
            file,
            "            <p>Total Benchmarks: {}</p>",
            self.analysis.summary.total_benchmarks
        )?;
        writeln!(
            file,
            "            <p>Passed: {} | Failed: {}</p>",
            self.analysis.summary.passed, self.analysis.summary.failed
        )?;
        writeln!(file, "        </div>")?;
        writeln!(file, "    </section>")?;

        // Results Table
        writeln!(file, "    <section class='results'>")?;
        writeln!(file, "        <h2>Benchmark Results</h2>")?;
        writeln!(file, "        <table>")?;
        writeln!(file, "            <thead>")?;
        writeln!(file, "                <tr>")?;
        writeln!(file, "                    <th>Benchmark</th>")?;
        writeln!(file, "                    <th>Mean</th>")?;
        writeln!(file, "                    <th>Median</th>")?;
        writeln!(file, "                    <th>P95</th>")?;
        writeln!(file, "                    <th>P99</th>")?;
        writeln!(file, "                    <th>Throughput</th>")?;
        writeln!(file, "                </tr>")?;
        writeln!(file, "            </thead>")?;
        writeln!(file, "            <tbody>")?;

        for result in &self.results {
            writeln!(file, "                <tr>")?;
            writeln!(file, "                    <td>{}</td>", result.name)?;
            writeln!(
                file,
                "                    <td>{:.2} ms</td>",
                result.latency.mean_ns as f64 / 1_000_000.0
            )?;
            writeln!(
                file,
                "                    <td>{:.2} ms</td>",
                result.latency.median_ns as f64 / 1_000_000.0
            )?;
            writeln!(
                file,
                "                    <td>{:.2} ms</td>",
                result.latency.p95_ns as f64 / 1_000_000.0
            )?;
            writeln!(
                file,
                "                    <td>{:.2} ms</td>",
                result.latency.p99_ns as f64 / 1_000_000.0
            )?;
            writeln!(
                file,
                "                    <td>{}</td>",
                result
                    .throughput
                    .as_ref()
                    .map(|t| format!("{:.2} {:?}", t.value, t.unit))
                    .unwrap_or_else(|| "N/A".to_string())
            )?;
            writeln!(file, "                </tr>")?;
        }

        writeln!(file, "            </tbody>")?;
        writeln!(file, "        </table>")?;
        writeln!(file, "    </section>")?;

        // Bottlenecks
        if !self.analysis.bottlenecks.is_empty() {
            writeln!(file, "    <section class='bottlenecks'>")?;
            writeln!(file, "        <h2>Performance Bottlenecks</h2>")?;
            for bottleneck in &self.analysis.bottlenecks {
                writeln!(
                    file,
                    "        <div class='bottleneck impact-{:?}'>",
                    bottleneck.impact
                )?;
                writeln!(file, "            <h3>{}</h3>", bottleneck.component)?;
                writeln!(
                    file,
                    "            <p class='description'>{}</p>",
                    bottleneck.description
                )?;
                writeln!(
                    file,
                    "            <p class='fix'>Suggested Fix: {}</p>",
                    bottleneck.suggested_fix
                )?;
                writeln!(file, "        </div>")?;
            }
            writeln!(file, "    </section>")?;
        }

        // Recommendations
        writeln!(file, "    <section class='recommendations'>")?;
        writeln!(file, "        <h2>Recommendations</h2>")?;
        writeln!(file, "        <ul>")?;
        for rec in &self.recommendations {
            writeln!(file, "            <li>{}</li>", rec)?;
        }
        writeln!(file, "        </ul>")?;
        writeln!(file, "    </section>")?;

        writeln!(file, "</body>")?;
        writeln!(file, "</html>")?;

        Ok(())
    }

    pub fn generate_json_report(&self, path: &Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn generate_markdown_report(&self, path: &Path) -> std::io::Result<()> {
        let mut file = File::create(path)?;

        writeln!(file, "# {}", self.metadata.title)?;
        writeln!(file)?;
        writeln!(file, "Generated: {}", self.metadata.generated_at)?;
        writeln!(
            file,
            "Version: {} | Commit: {}",
            self.metadata.version,
            self.metadata
                .git_commit
                .as_ref()
                .unwrap_or(&"Unknown".to_string())
        )?;
        writeln!(file)?;

        writeln!(file, "## System Information")?;
        writeln!(file)?;
        writeln!(file, "| Property | Value |")?;
        writeln!(file, "|----------|-------|")?;
        writeln!(file, "| OS | {} |", self.system_info.os)?;
        writeln!(file, "| CPU | {} |", self.system_info.cpu)?;
        writeln!(file, "| Cores | {} |", self.system_info.cpu_cores)?;
        writeln!(file, "| Memory | {:.2} GB |", self.system_info.memory_gb)?;
        writeln!(file, "| Rust | {} |", self.system_info.rust_version)?;
        writeln!(file)?;

        writeln!(file, "## Performance Summary")?;
        writeln!(file)?;
        writeln!(
            file,
            "**Performance Score:** {:.1}/100",
            self.analysis.summary.performance_score
        )?;
        writeln!(
            file,
            "**Rating:** {:?}",
            self.analysis.summary.efficiency_rating
        )?;
        writeln!(file)?;
        writeln!(
            file,
            "- Total Benchmarks: {}",
            self.analysis.summary.total_benchmarks
        )?;
        writeln!(file, "- Passed: {}", self.analysis.summary.passed)?;
        writeln!(file, "- Failed: {}", self.analysis.summary.failed)?;
        writeln!(file)?;

        writeln!(file, "## Benchmark Results")?;
        writeln!(file)?;
        writeln!(
            file,
            "| Benchmark | Mean (ms) | Median (ms) | P95 (ms) | P99 (ms) | Throughput |"
        )?;
        writeln!(
            file,
            "|-----------|-----------|-------------|----------|----------|------------|"
        )?;

        for result in &self.results {
            writeln!(
                file,
                "| {} | {:.2} | {:.2} | {:.2} | {:.2} | {} |",
                result.name,
                result.latency.mean_ns as f64 / 1_000_000.0,
                result.latency.median_ns as f64 / 1_000_000.0,
                result.latency.p95_ns as f64 / 1_000_000.0,
                result.latency.p99_ns as f64 / 1_000_000.0,
                result
                    .throughput
                    .as_ref()
                    .map(|t| format!("{:.2} {:?}", t.value, t.unit))
                    .unwrap_or_else(|| "N/A".to_string())
            )?;
        }
        writeln!(file)?;

        if !self.analysis.bottlenecks.is_empty() {
            writeln!(file, "## Performance Bottlenecks")?;
            writeln!(file)?;

            for bottleneck in &self.analysis.bottlenecks {
                writeln!(
                    file,
                    "### {} ({:?})",
                    bottleneck.component, bottleneck.impact
                )?;
                writeln!(file)?;
                writeln!(file, "{}", bottleneck.description)?;
                writeln!(file)?;
                writeln!(file, "**Suggested Fix:** {}", bottleneck.suggested_fix)?;
                writeln!(file)?;
            }
        }

        writeln!(file, "## Recommendations")?;
        writeln!(file)?;
        for rec in &self.recommendations {
            writeln!(file, "- {}", rec)?;
        }

        Ok(())
    }
}
