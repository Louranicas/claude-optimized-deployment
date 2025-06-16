// ============================================================================
// Security Module Unit Tests
// ============================================================================

use crate::mcp_manager::{
    server_types::security::{SecurityServer, SecurityPolicy, ThreatLevel},
    protocol::{MCPRequest, MCPResponse},
    error::{MCPError, MCPResult},
    core::MCPManager,
    config::MCPConfig,
};
use std::sync::Arc;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use tokio::sync::{RwLock, Mutex};
use tokio::test;

#[cfg(test)]
mod authentication_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_token_authentication() {
        let security_server = SecurityServer::new("auth_server");
        
        // Generate token
        let token = security_server.generate_token("user123", Duration::from_secs(3600)).await.unwrap();
        assert!(!token.is_empty());
        
        // Validate token
        let validation = security_server.validate_token(&token).await;
        assert!(validation.is_ok());
        
        let claims = validation.unwrap();
        assert_eq!(claims.subject, "user123");
        assert!(claims.expiry > SystemTime::now());
    }
    
    #[tokio::test]
    async fn test_token_expiration() {
        let security_server = SecurityServer::new("auth_server");
        
        // Generate short-lived token
        let token = security_server.generate_token("user123", Duration::from_millis(100)).await.unwrap();
        
        // Should be valid immediately
        assert!(security_server.validate_token(&token).await.is_ok());
        
        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(150)).await;
        
        // Should be expired
        let result = security_server.validate_token(&token).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            MCPError::Authentication(msg) => assert!(msg.contains("expired")),
            _ => panic!("Expected authentication error"),
        }
    }
    
    #[tokio::test]
    async fn test_mutual_tls_validation() {
        let security_server = SecurityServer::new("mtls_server");
        
        // Configure mTLS
        security_server.configure_mtls(
            "/path/to/ca.crt",
            "/path/to/server.crt",
            "/path/to/server.key",
        ).await.unwrap();
        
        // Test client certificate validation
        let valid_cert = include_bytes!("test_certs/valid_client.crt");
        let invalid_cert = include_bytes!("test_certs/invalid_client.crt");
        
        assert!(security_server.validate_client_certificate(valid_cert).await.is_ok());
        assert!(security_server.validate_client_certificate(invalid_cert).await.is_err());
    }
    
    #[tokio::test]
    async fn test_api_key_management() {
        let security_server = SecurityServer::new("api_key_server");
        
        // Create API key
        let api_key = security_server.create_api_key(
            "service_account_1",
            vec!["read", "write"],
            Some(Duration::from_secs(86400)),
        ).await.unwrap();
        
        assert!(!api_key.is_empty());
        assert!(api_key.len() >= 32); // Should be sufficiently long
        
        // Validate API key
        let validation = security_server.validate_api_key(&api_key).await.unwrap();
        assert_eq!(validation.account, "service_account_1");
        assert!(validation.permissions.contains(&"read".to_string()));
        assert!(validation.permissions.contains(&"write".to_string()));
        
        // Revoke API key
        security_server.revoke_api_key(&api_key).await.unwrap();
        
        // Should no longer be valid
        assert!(security_server.validate_api_key(&api_key).await.is_err());
    }
}

#[cfg(test)]
mod authorization_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_rbac_permissions() {
        let security_server = SecurityServer::new("rbac_server");
        
        // Define roles
        security_server.create_role("admin", vec![
            "servers:*",
            "config:*",
            "metrics:read",
        ]).await.unwrap();
        
        security_server.create_role("operator", vec![
            "servers:read",
            "servers:restart",
            "metrics:read",
        ]).await.unwrap();
        
        security_server.create_role("viewer", vec![
            "servers:read",
            "metrics:read",
        ]).await.unwrap();
        
        // Assign roles to users
        security_server.assign_role("alice", "admin").await.unwrap();
        security_server.assign_role("bob", "operator").await.unwrap();
        security_server.assign_role("charlie", "viewer").await.unwrap();
        
        // Test permissions
        assert!(security_server.check_permission("alice", "servers:delete").await.unwrap());
        assert!(security_server.check_permission("alice", "config:write").await.unwrap());
        
        assert!(security_server.check_permission("bob", "servers:restart").await.unwrap());
        assert!(!security_server.check_permission("bob", "config:write").await.unwrap());
        
        assert!(security_server.check_permission("charlie", "servers:read").await.unwrap());
        assert!(!security_server.check_permission("charlie", "servers:restart").await.unwrap());
    }
    
    #[tokio::test]
    async fn test_resource_based_access_control() {
        let security_server = SecurityServer::new("resource_server");
        
        // Define resource policies
        security_server.create_resource_policy("production_servers", vec![
            ("alice", vec!["read", "write", "delete"]),
            ("bob", vec!["read"]),
        ]).await.unwrap();
        
        security_server.create_resource_policy("staging_servers", vec![
            ("alice", vec!["read", "write"]),
            ("bob", vec!["read", "write", "delete"]),
            ("charlie", vec!["read", "write"]),
        ]).await.unwrap();
        
        // Test resource access
        assert!(security_server.check_resource_access(
            "alice", "production_servers", "write"
        ).await.unwrap());
        
        assert!(!security_server.check_resource_access(
            "bob", "production_servers", "write"
        ).await.unwrap());
        
        assert!(security_server.check_resource_access(
            "bob", "staging_servers", "delete"
        ).await.unwrap());
    }
    
    #[tokio::test]
    async fn test_attribute_based_access_control() {
        let security_server = SecurityServer::new("abac_server");
        
        // Define ABAC policies
        security_server.create_abac_policy("sensitive_data_access", |attributes| {
            attributes.get("clearance_level").map(|l| l == "top_secret").unwrap_or(false) &&
            attributes.get("department").map(|d| d == "security").unwrap_or(false)
        }).await.unwrap();
        
        // Test with different attribute sets
        let mut alice_attrs = HashMap::new();
        alice_attrs.insert("clearance_level".to_string(), "top_secret".to_string());
        alice_attrs.insert("department".to_string(), "security".to_string());
        
        let mut bob_attrs = HashMap::new();
        bob_attrs.insert("clearance_level".to_string(), "secret".to_string());
        bob_attrs.insert("department".to_string(), "security".to_string());
        
        assert!(security_server.evaluate_abac_policy(
            "sensitive_data_access", &alice_attrs
        ).await.unwrap());
        
        assert!(!security_server.evaluate_abac_policy(
            "sensitive_data_access", &bob_attrs
        ).await.unwrap());
    }
}

#[cfg(test)]
mod encryption_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_data_encryption_at_rest() {
        let security_server = SecurityServer::new("encryption_server");
        
        let sensitive_data = serde_json::json!({
            "credit_card": "1234-5678-9012-3456",
            "ssn": "123-45-6789",
            "api_key": "secret_key_12345",
        });
        
        // Encrypt data
        let encrypted = security_server.encrypt_data(&sensitive_data).await.unwrap();
        assert_ne!(encrypted, sensitive_data.to_string());
        assert!(encrypted.len() > sensitive_data.to_string().len()); // Should include IV/tag
        
        // Decrypt data
        let decrypted = security_server.decrypt_data(&encrypted).await.unwrap();
        assert_eq!(decrypted, sensitive_data);
    }
    
    #[tokio::test]
    async fn test_field_level_encryption() {
        let security_server = SecurityServer::new("field_encryption_server");
        
        let mut document = serde_json::json!({
            "user_id": "12345",
            "name": "John Doe",
            "email": "john@example.com",
            "ssn": "123-45-6789",
            "phone": "555-1234",
        });
        
        // Encrypt specific fields
        security_server.encrypt_fields(&mut document, vec!["ssn", "phone"]).await.unwrap();
        
        // Verify only specified fields are encrypted
        assert_eq!(document["user_id"], "12345");
        assert_eq!(document["name"], "John Doe");
        assert_ne!(document["ssn"], "123-45-6789");
        assert_ne!(document["phone"], "555-1234");
        
        // Decrypt fields
        security_server.decrypt_fields(&mut document, vec!["ssn", "phone"]).await.unwrap();
        assert_eq!(document["ssn"], "123-45-6789");
        assert_eq!(document["phone"], "555-1234");
    }
    
    #[tokio::test]
    async fn test_key_rotation() {
        let security_server = SecurityServer::new("key_rotation_server");
        
        // Encrypt with current key
        let data = "sensitive information";
        let encrypted_v1 = security_server.encrypt_data(&data).await.unwrap();
        
        // Rotate encryption key
        security_server.rotate_encryption_key().await.unwrap();
        
        // Should still be able to decrypt old data
        let decrypted = security_server.decrypt_data(&encrypted_v1).await.unwrap();
        assert_eq!(decrypted, data);
        
        // New encryption should use new key
        let encrypted_v2 = security_server.encrypt_data(&data).await.unwrap();
        assert_ne!(encrypted_v1, encrypted_v2);
        
        // Both should decrypt to same value
        assert_eq!(
            security_server.decrypt_data(&encrypted_v1).await.unwrap(),
            security_server.decrypt_data(&encrypted_v2).await.unwrap()
        );
    }
}

#[cfg(test)]
mod threat_detection_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_anomaly_detection() {
        let security_server = SecurityServer::new("anomaly_server");
        
        // Train baseline behavior
        for _ in 0..100 {
            security_server.record_request_pattern("user1", "GET", "/api/users", 150).await;
            security_server.record_request_pattern("user1", "GET", "/api/posts", 200).await;
        }
        
        security_server.train_anomaly_detector().await.unwrap();
        
        // Normal behavior should not trigger alerts
        let normal_score = security_server.calculate_anomaly_score(
            "user1", "GET", "/api/users", 160
        ).await.unwrap();
        assert!(normal_score < 0.5);
        
        // Anomalous behavior should trigger alerts
        let anomaly_score = security_server.calculate_anomaly_score(
            "user1", "DELETE", "/api/admin/users", 50
        ).await.unwrap();
        assert!(anomaly_score > 0.7);
    }
    
    #[tokio::test]
    async fn test_rate_limiting() {
        let security_server = SecurityServer::new("rate_limit_server");
        
        // Configure rate limits
        security_server.set_rate_limit("api_key_123", 10, Duration::from_secs(60)).await.unwrap();
        
        // Should allow up to limit
        for i in 0..10 {
            let allowed = security_server.check_rate_limit("api_key_123").await.unwrap();
            assert!(allowed, "Request {} should be allowed", i);
        }
        
        // Should block after limit
        let blocked = security_server.check_rate_limit("api_key_123").await.unwrap();
        assert!(!blocked, "Should be rate limited");
        
        // Get rate limit status
        let status = security_server.get_rate_limit_status("api_key_123").await.unwrap();
        assert_eq!(status.requests_made, 11);
        assert_eq!(status.limit, 10);
        assert!(status.reset_time > SystemTime::now());
    }
    
    #[tokio::test]
    async fn test_ddos_protection() {
        let security_server = SecurityServer::new("ddos_server");
        
        // Configure DDoS protection
        security_server.enable_ddos_protection(
            100, // requests per second threshold
            Duration::from_secs(10), // ban duration
        ).await.unwrap();
        
        // Simulate attack from IP
        let attacker_ip = "192.168.1.100";
        
        // Burst of requests
        for _ in 0..150 {
            security_server.record_request(attacker_ip).await;
        }
        
        // Should detect and block
        let threat_level = security_server.assess_threat(attacker_ip).await.unwrap();
        assert_eq!(threat_level, ThreatLevel::High);
        
        let is_blocked = security_server.is_ip_blocked(attacker_ip).await.unwrap();
        assert!(is_blocked);
    }
    
    #[tokio::test]
    async fn test_sql_injection_detection() {
        let security_server = SecurityServer::new("sqli_server");
        
        // Test various SQL injection patterns
        let safe_inputs = vec![
            "John Doe",
            "user@example.com",
            "12345",
            "Hello, world!",
        ];
        
        let malicious_inputs = vec![
            "' OR '1'='1",
            "admin'--",
            "1; DROP TABLE users--",
            "' UNION SELECT * FROM passwords--",
            "1' AND (SELECT COUNT(*) FROM users) > 0--",
        ];
        
        for input in safe_inputs {
            let is_safe = security_server.validate_input(input, "sql").await.unwrap();
            assert!(is_safe, "Input '{}' should be safe", input);
        }
        
        for input in malicious_inputs {
            let is_safe = security_server.validate_input(input, "sql").await.unwrap();
            assert!(!is_safe, "Input '{}' should be detected as malicious", input);
        }
    }
}

#[cfg(test)]
mod audit_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_audit_logging() {
        let security_server = SecurityServer::new("audit_server");
        
        // Enable comprehensive audit logging
        security_server.enable_audit_logging(vec![
            "authentication",
            "authorization",
            "data_access",
            "configuration_change",
        ]).await.unwrap();
        
        // Perform actions that should be audited
        let token = security_server.generate_token("alice", Duration::from_secs(3600)).await.unwrap();
        security_server.check_permission("alice", "servers:read").await.unwrap();
        security_server.access_sensitive_data("alice", "customer_records").await;
        security_server.update_configuration("alice", "rate_limit", "100").await;
        
        // Retrieve audit logs
        let logs = security_server.get_audit_logs(
            Some("alice"),
            None,
            Some(SystemTime::now() - Duration::from_secs(60)),
            Some(SystemTime::now()),
        ).await.unwrap();
        
        assert!(logs.len() >= 4);
        
        // Verify log integrity
        for log in &logs {
            assert!(!log.id.is_empty());
            assert!(!log.user.is_empty());
            assert!(!log.action.is_empty());
            assert!(log.timestamp <= SystemTime::now());
            
            // Verify log signature
            let is_valid = security_server.verify_audit_log_integrity(&log).await.unwrap();
            assert!(is_valid, "Audit log should have valid signature");
        }
    }
    
    #[tokio::test]
    async fn test_compliance_reporting() {
        let security_server = SecurityServer::new("compliance_server");
        
        // Generate compliance reports
        let gdpr_report = security_server.generate_compliance_report("GDPR").await.unwrap();
        let pci_report = security_server.generate_compliance_report("PCI-DSS").await.unwrap();
        let soc2_report = security_server.generate_compliance_report("SOC2").await.unwrap();
        
        // Verify report contents
        assert!(gdpr_report.contains("data_retention"));
        assert!(gdpr_report.contains("right_to_erasure"));
        assert!(gdpr_report.contains("data_portability"));
        
        assert!(pci_report.contains("encryption_at_rest"));
        assert!(pci_report.contains("network_segmentation"));
        assert!(pci_report.contains("access_control"));
        
        assert!(soc2_report.contains("security_controls"));
        assert!(soc2_report.contains("availability"));
        assert!(soc2_report.contains("confidentiality"));
    }
}

#[cfg(test)]
mod security_integration_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_end_to_end_security_flow() {
        let mut config = MCPConfig::default();
        config.enable_security = true;
        
        let manager = Arc::new(MCPManager::new(config));
        let security_server = SecurityServer::new("main_security");
        
        // Setup security policies
        security_server.set_security_policy(SecurityPolicy {
            require_authentication: true,
            require_encryption: true,
            allowed_tls_versions: vec!["1.2", "1.3"],
            allowed_ciphers: vec!["AES256-GCM-SHA384", "CHACHA20-POLY1305"],
            enable_audit_logging: true,
            enable_threat_detection: true,
        }).await.unwrap();
        
        manager.register_security_server(security_server.clone()).await.unwrap();
        
        // Authenticate user
        let token = manager.authenticate_user("alice", "password123").await.unwrap();
        
        // Make authenticated request
        let request = MCPRequest::new("get_servers", serde_json::json!({}))
            .with_auth_token(&token);
        
        let response = manager.send_secure_request(request).await.unwrap();
        
        // Verify response is encrypted
        assert!(response.is_encrypted());
        
        // Decrypt and verify
        let decrypted = manager.decrypt_response(response).await.unwrap();
        assert!(decrypted.result.is_some());
        
        // Check audit log
        let audit_logs = security_server.get_recent_audit_logs(1).await.unwrap();
        assert_eq!(audit_logs.len(), 1);
        assert_eq!(audit_logs[0].user, "alice");
        assert_eq!(audit_logs[0].action, "get_servers");
    }
}

// Test certificate data (would be actual certificates in production)
mod test_certs {
    pub const VALID_CLIENT_CRT: &[u8] = b"-----BEGIN CERTIFICATE-----\nVALID_CERT_DATA\n-----END CERTIFICATE-----";
    pub const INVALID_CLIENT_CRT: &[u8] = b"-----BEGIN CERTIFICATE-----\nINVALID_CERT_DATA\n-----END CERTIFICATE-----";
}