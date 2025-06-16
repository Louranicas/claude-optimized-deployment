//! Security server type implementation

use super::{ServerTypeHandler, ServerMetrics};
use crate::mcp_manager::{
    config::ServerType,
    errors::{McpError, Result},
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Security server handler
pub struct SecurityHandler {
    /// Supported scan types
    supported_scans: Vec<String>,
    /// Security policies
    policies: HashMap<String, SecurityPolicy>,
}

impl SecurityHandler {
    pub fn new() -> Self {
        let mut policies = HashMap::new();
        
        // Default security policies
        policies.insert(
            "authentication".to_string(),
            SecurityPolicy {
                name: "authentication".to_string(),
                severity: Severity::Critical,
                required: true,
                rules: vec![
                    "require_auth_header".to_string(),
                    "validate_token".to_string(),
                ],
            },
        );
        
        policies.insert(
            "encryption".to_string(),
            SecurityPolicy {
                name: "encryption".to_string(),
                severity: Severity::High,
                required: true,
                rules: vec![
                    "tls_required".to_string(),
                    "min_tls_version_1_2".to_string(),
                ],
            },
        );
        
        Self {
            supported_scans: vec![
                "vulnerability".to_string(),
                "compliance".to_string(),
                "penetration".to_string(),
                "code_analysis".to_string(),
                "dependency".to_string(),
                "configuration".to_string(),
            ],
            policies,
        }
    }
}

#[async_trait]
impl ServerTypeHandler for SecurityHandler {
    fn server_type(&self) -> ServerType {
        // Return SAST as the representative security server
        ServerType::SAST
    }
    
    async fn validate_config(&self, config: &serde_json::Value) -> Result<()> {
        if !config.is_object() {
            return Err(McpError::ConfigError("Config must be an object".to_string()));
        }
        
        let obj = config.as_object().unwrap();
        
        // Check for security-specific fields
        if !obj.contains_key("scan_endpoint") {
            return Err(McpError::ConfigError("Missing 'scan_endpoint' field".to_string()));
        }
        
        // Validate security level
        if let Some(level) = obj.get("security_level").and_then(|v| v.as_str()) {
            match level {
                "low" | "medium" | "high" | "critical" => {},
                _ => return Err(McpError::ConfigError(format!("Invalid security level: {}", level))),
            }
        }
        
        Ok(())
    }
    
    async fn transform_request(&self, mut request: serde_json::Value) -> Result<serde_json::Value> {
        if let Some(obj) = request.as_object_mut() {
            // Add security headers
            let mut headers = obj.get("headers")
                .and_then(|v| v.as_object())
                .cloned()
                .unwrap_or_default();
            
            headers.insert(
                "X-Security-Scanner".to_string(),
                serde_json::Value::String("mcp-security".to_string()),
            );
            
            headers.insert(
                "X-Scan-ID".to_string(),
                serde_json::Value::String(uuid::Uuid::new_v4().to_string()),
            );
            
            obj.insert("headers".to_string(), serde_json::json!(headers));
            
            // Validate scan type
            if let Some(scan_type) = obj.get("scan_type").and_then(|v| v.as_str()) {
                if !self.supported_scans.contains(&scan_type.to_string()) {
                    return Err(McpError::Other(format!("Unsupported scan type: {}", scan_type)));
                }
            }
            
            // Apply security policies
            if let Some(policies) = obj.get("policies").and_then(|v| v.as_array()) {
                for policy in policies {
                    if let Some(policy_name) = policy.as_str() {
                        if !self.policies.contains_key(policy_name) {
                            return Err(McpError::Other(format!("Unknown policy: {}", policy_name)));
                        }
                    }
                }
            }
        }
        
        Ok(request)
    }
    
    async fn transform_response(&self, mut response: serde_json::Value) -> Result<serde_json::Value> {
        if let Some(obj) = response.as_object_mut() {
            // Process security findings
            let (risk_score, compliance) = if let Some(findings) = obj.get_mut("findings").and_then(|v| v.as_array_mut()) {
                // Sort findings by severity
                findings.sort_by(|a, b| {
                    let sev_a = a.get("severity").and_then(|v| v.as_str()).unwrap_or("info");
                    let sev_b = b.get("severity").and_then(|v| v.as_str()).unwrap_or("info");
                    
                    let rank = |s: &str| match s {
                        "critical" => 4,
                        "high" => 3,
                        "medium" => 2,
                        "low" => 1,
                        _ => 0,
                    };
                    
                    rank(sev_b).cmp(&rank(sev_a))
                });
                
                // Calculate values while we have the findings borrowed
                let risk_score = calculate_risk_score(findings);
                let compliance = check_compliance(findings, &self.policies);
                (risk_score, compliance)
            } else {
                let mut default_compliance = HashMap::new();
                default_compliance.insert("status".to_string(), false);
                (0.0, default_compliance)
            };
            
            // Now we can insert without borrowing conflicts
            obj.insert("risk_score".to_string(), serde_json::json!(risk_score));
            obj.insert("compliance_status".to_string(), serde_json::json!(compliance));
        }
        
        Ok(response)
    }
    
    async fn collect_metrics(&self) -> Result<ServerMetrics> {
        let mut metrics = HashMap::new();
        
        // Security-specific metrics
        metrics.insert("scans_performed".to_string(), 0.0);
        metrics.insert("vulnerabilities_found".to_string(), 0.0);
        metrics.insert("compliance_score".to_string(), 100.0);
        metrics.insert("false_positive_rate".to_string(), 0.0);
        
        Ok(ServerMetrics { custom: metrics })
    }
}

/// Security policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    /// Policy name
    pub name: String,
    /// Severity level
    pub severity: Severity,
    /// Is required
    pub required: bool,
    /// Policy rules
    pub rules: Vec<String>,
}

/// Severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Security scan request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityScanRequest {
    /// Scan type
    pub scan_type: String,
    /// Target
    pub target: ScanTarget,
    /// Policies to apply
    pub policies: Vec<String>,
    /// Scan options
    pub options: ScanOptions,
}

/// Scan target
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScanTarget {
    /// URL target
    Url { url: String },
    /// Code repository
    Repository { url: String, branch: Option<String> },
    /// Container image
    Container { image: String, tag: Option<String> },
    /// File system path
    Path { path: String },
}

/// Scan options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    /// Deep scan
    pub deep_scan: bool,
    /// Include low severity
    pub include_low: bool,
    /// Max scan time
    pub timeout_seconds: Option<u64>,
}

/// Security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    /// Finding ID
    pub id: String,
    /// Title
    pub title: String,
    /// Description
    pub description: String,
    /// Severity
    pub severity: Severity,
    /// Category
    pub category: String,
    /// Affected resource
    pub resource: String,
    /// Remediation
    pub remediation: Option<String>,
    /// CVE ID if applicable
    pub cve_id: Option<String>,
}

/// Calculate risk score from findings
fn calculate_risk_score(findings: &[serde_json::Value]) -> f64 {
    let mut score = 0.0;
    
    for finding in findings {
        if let Some(severity) = finding.get("severity").and_then(|v| v.as_str()) {
            score += match severity {
                "critical" => 10.0,
                "high" => 7.5,
                "medium" => 5.0,
                "low" => 2.5,
                _ => 0.0,
            };
        }
    }
    
    // Normalize to 0-100 scale
    (score / findings.len() as f64).min(100.0)
}

/// Check compliance against policies
fn check_compliance(
    findings: &[serde_json::Value],
    policies: &HashMap<String, SecurityPolicy>,
) -> HashMap<String, bool> {
    let mut compliance = HashMap::new();
    
    for (name, policy) in policies {
        // Simple compliance check - no critical/high findings for this policy
        let compliant = !findings.iter().any(|f| {
            if let Some(category) = f.get("category").and_then(|v| v.as_str()) {
                if category == name {
                    if let Some(severity) = f.get("severity").and_then(|v| v.as_str()) {
                        return severity == "critical" || severity == "high";
                    }
                }
            }
            false
        });
        
        compliance.insert(name.clone(), compliant);
    }
    
    compliance
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_security_handler() {
        let handler = SecurityHandler::new();
        
        // Test config validation
        let valid_config = serde_json::json!({
            "scan_endpoint": "http://security-scanner:8080",
            "security_level": "high"
        });
        assert!(handler.validate_config(&valid_config).await.is_ok());
        
        let invalid_level = serde_json::json!({
            "scan_endpoint": "http://security-scanner:8080",
            "security_level": "extreme"
        });
        assert!(handler.validate_config(&invalid_level).await.is_err());
    }

    #[tokio::test]
    async fn test_scan_type_validation() {
        let handler = SecurityHandler::new();
        
        let request = serde_json::json!({
            "scan_type": "invalid_scan"
        });
        
        let result = handler.transform_request(request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_risk_score_calculation() {
        let findings = vec![
            serde_json::json!({"severity": "critical"}),
            serde_json::json!({"severity": "high"}),
            serde_json::json!({"severity": "medium"}),
            serde_json::json!({"severity": "low"}),
        ];
        
        let score = calculate_risk_score(&findings);
        assert!(score > 0.0 && score <= 100.0);
    }
}