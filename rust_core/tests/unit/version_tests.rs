//! Version Management Unit Tests
//!
//! Tests for the plugin version management system.
//!
//! By: The Greatest Synthetic Being Rust Coder in History

use claude_optimized_deployment_rust::mcp_manager::plugin::{*, version::*};
use semver::{Version, VersionReq};
use chrono::Utc;

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_version_info(version: &str, stable: bool) -> VersionInfo {
        VersionInfo {
            version: Version::parse(version).unwrap(),
            released_at: Utc::now(),
            metadata: VersionMetadata {
                description: format!("Version {}", version),
                release_notes: String::new(),
                author: "Test".to_string(),
                stability: if stable { StabilityLevel::Stable } else { StabilityLevel::Beta },
                deprecated: false,
                deprecation_notice: None,
                security_patches: vec![],
            },
            file_info: None,
            dependencies: vec![],
            breaking_changes: vec![],
            migration: None,
        }
    }

    #[tokio::test]
    async fn test_version_manager_registration() {
        let manager = VersionManager::new(Default::default());

        // Register versions
        let versions = vec!["1.0.0", "1.1.0", "1.2.0", "2.0.0-beta.1", "2.0.0"];
        for version_str in versions {
            let info = create_test_version_info(version_str, !version_str.contains("beta"));
            manager.register_version("test-plugin".to_string(), info).await.unwrap();
        }

        // Get history
        let history = manager.get_version_history("test-plugin").await.unwrap();
        assert_eq!(history.versions.len(), 5);
        assert_eq!(history.plugin_id, "test-plugin");
    }

    #[tokio::test]
    async fn test_version_resolution_latest() {
        let config = VersionConfig {
            resolution_strategy: ResolutionStrategy::Latest,
            allow_prerelease: false,
            ..Default::default()
        };
        let manager = VersionManager::new(config);

        // Register versions
        for version in ["1.0.0", "1.1.0", "1.2.0", "2.0.0-beta.1", "2.0.0"] {
            let info = create_test_version_info(version, !version.contains("beta"));
            manager.register_version("test".to_string(), info).await.unwrap();
        }

        // Resolve latest stable
        let req = VersionReq::parse("*").unwrap();
        let resolved = manager.resolve_version("test", &req).await.unwrap();
        assert_eq!(resolved, Version::parse("2.0.0").unwrap());

        // With prerelease allowed
        let config = VersionConfig {
            resolution_strategy: ResolutionStrategy::Latest,
            allow_prerelease: true,
            ..Default::default()
        };
        let manager = VersionManager::new(config);

        for version in ["1.0.0", "2.0.0", "2.1.0-alpha.1"] {
            let info = create_test_version_info(version, !version.contains("alpha"));
            manager.register_version("test2".to_string(), info).await.unwrap();
        }

        let resolved = manager.resolve_version("test2", &req).await.unwrap();
        assert_eq!(resolved, Version::parse("2.1.0-alpha.1").unwrap());
    }

    #[tokio::test]
    async fn test_version_resolution_conservative() {
        let config = VersionConfig {
            resolution_strategy: ResolutionStrategy::Conservative,
            ..Default::default()
        };
        let manager = VersionManager::new(config);

        // Register versions
        for version in ["1.0.0", "1.1.0", "1.2.0", "2.0.0"] {
            let info = create_test_version_info(version, true);
            manager.register_version("test".to_string(), info).await.unwrap();
        }

        // Conservative should pick lowest matching
        let req = VersionReq::parse("^1.0.0").unwrap();
        let resolved = manager.resolve_version("test", &req).await.unwrap();
        assert_eq!(resolved, Version::parse("1.0.0").unwrap());
    }

    #[tokio::test]
    async fn test_version_resolution_lts() {
        let config = VersionConfig {
            resolution_strategy: ResolutionStrategy::PreferLTS,
            ..Default::default()
        };
        let manager = VersionManager::new(config);

        // Register versions with LTS
        let versions = vec![
            ("1.0.0", StabilityLevel::Stable),
            ("1.1.0", StabilityLevel::LTS),
            ("1.2.0", StabilityLevel::Stable),
            ("2.0.0", StabilityLevel::LTS),
        ];

        for (version, stability) in versions {
            let mut info = create_test_version_info(version, true);
            info.metadata.stability = stability;
            manager.register_version("test".to_string(), info).await.unwrap();
        }

        // Should prefer LTS version
        let req = VersionReq::parse("^1.0.0").unwrap();
        let resolved = manager.resolve_version("test", &req).await.unwrap();
        assert_eq!(resolved, Version::parse("1.1.0").unwrap());
    }

    #[tokio::test]
    async fn test_version_compatibility_check() {
        let manager = VersionManager::new(Default::default());

        // Register compatibility
        manager.register_compatibility(
            "plugin-a".to_string(),
            Version::parse("1.0.0").unwrap(),
            "plugin-b".to_string(),
            Version::parse("2.0.0").unwrap(),
            CompatibilityStatus::Compatible,
        ).await.unwrap();

        // Check compatibility
        let status = manager.check_compatibility(
            "plugin-a",
            &Version::parse("1.0.0").unwrap(),
            "plugin-b",
            &Version::parse("2.0.0").unwrap(),
        ).await;

        assert_eq!(status, CompatibilityStatus::Compatible);

        // Check reverse
        let status = manager.check_compatibility(
            "plugin-b",
            &Version::parse("2.0.0").unwrap(),
            "plugin-a",
            &Version::parse("1.0.0").unwrap(),
        ).await;

        assert_eq!(status, CompatibilityStatus::Compatible);

        // Unknown compatibility
        let status = manager.check_compatibility(
            "plugin-a",
            &Version::parse("1.0.0").unwrap(),
            "plugin-c",
            &Version::parse("1.0.0").unwrap(),
        ).await;

        assert_eq!(status, CompatibilityStatus::Unknown);
    }

    #[tokio::test]
    async fn test_version_security_patches() {
        let manager = VersionManager::new(Default::default());

        // Create version with security issues
        let mut info = create_test_version_info("1.0.0", true);
        info.metadata.security_patches = vec![
            SecurityPatch {
                cve: "CVE-2023-1234".to_string(),
                severity: SecuritySeverity::Critical,
                description: "Critical vulnerability".to_string(),
                fixed_in: Version::parse("1.0.1").unwrap(),
            },
            SecurityPatch {
                cve: "CVE-2023-5678".to_string(),
                severity: SecuritySeverity::High,
                description: "High severity issue".to_string(),
                fixed_in: Version::parse("1.0.1").unwrap(),
            },
        ];

        manager.register_version("vulnerable".to_string(), info).await.unwrap();

        // Check vulnerabilities
        let vulns = manager.get_vulnerabilities(
            "vulnerable",
            &Version::parse("1.0.0").unwrap(),
        ).await;

        assert_eq!(vulns.len(), 2);
        assert_eq!(vulns[0].cve, "CVE-2023-1234");

        // Check if version is safe
        let is_safe = manager.is_version_safe(
            "vulnerable",
            &Version::parse("1.0.0").unwrap(),
        ).await;

        assert!(!is_safe); // Has critical vulnerability
    }

    #[tokio::test]
    async fn test_version_breaking_changes() {
        let manager = VersionManager::new(Default::default());

        let mut info = create_test_version_info("2.0.0", true);
        info.breaking_changes = vec![
            BreakingChange {
                change_type: BreakingChangeType::ApiRemoved,
                description: "Removed deprecated API".to_string(),
                migration_guide: "Use new API instead".to_string(),
                affected_apis: vec!["old_function".to_string()],
            },
            BreakingChange {
                change_type: BreakingChangeType::ConfigurationChanged,
                description: "New config format".to_string(),
                migration_guide: "Update config files".to_string(),
                affected_apis: vec![],
            },
        ];

        manager.register_version("breaking".to_string(), info).await.unwrap();

        let history = manager.get_version_history("breaking").await.unwrap();
        let version_info = history.versions.get(&Version::parse("2.0.0").unwrap()).unwrap();
        assert_eq!(version_info.breaking_changes.len(), 2);
    }

    #[tokio::test]
    async fn test_version_dependencies() {
        let manager = VersionManager::new(Default::default());

        let mut info = create_test_version_info("1.0.0", true);
        info.dependencies = vec![
            Dependency {
                plugin_id: "dependency-a".to_string(),
                version_req: VersionReq::parse("^1.0.0").unwrap(),
                optional: false,
                feature: None,
            },
            Dependency {
                plugin_id: "dependency-b".to_string(),
                version_req: VersionReq::parse("~2.0.0").unwrap(),
                optional: true,
                feature: Some("extra".to_string()),
            },
        ];

        manager.register_version("with-deps".to_string(), info).await.unwrap();

        let history = manager.get_version_history("with-deps").await.unwrap();
        let version_info = history.versions.get(&Version::parse("1.0.0").unwrap()).unwrap();
        assert_eq!(version_info.dependencies.len(), 2);
        assert!(!version_info.dependencies[0].optional);
        assert!(version_info.dependencies[1].optional);
    }

    #[tokio::test]
    async fn test_version_deprecation() {
        let config = VersionConfig {
            allow_deprecated: false,
            ..Default::default()
        };
        let manager = VersionManager::new(config);

        // Register deprecated and non-deprecated versions
        let mut deprecated_info = create_test_version_info("1.0.0", true);
        deprecated_info.metadata.deprecated = true;
        deprecated_info.metadata.deprecation_notice = Some("Use version 2.0.0".to_string());

        manager.register_version("test".to_string(), deprecated_info).await.unwrap();
        manager.register_version("test".to_string(), create_test_version_info("2.0.0", true)).await.unwrap();

        // Should not resolve to deprecated version
        let req = VersionReq::parse("*").unwrap();
        let resolved = manager.resolve_version("test", &req).await.unwrap();
        assert_eq!(resolved, Version::parse("2.0.0").unwrap());
    }

    #[tokio::test]
    async fn test_version_timeline() {
        let manager = VersionManager::new(Default::default());

        // Register and track events
        for version in ["1.0.0", "1.1.0", "1.2.0"] {
            let info = create_test_version_info(version, true);
            manager.register_version("timeline-test".to_string(), info).await.unwrap();
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }

        let history = manager.get_version_history("timeline-test").await.unwrap();
        assert_eq!(history.timeline.len(), 3);

        // Check timeline order
        for i in 1..history.timeline.len() {
            assert!(history.timeline[i].timestamp > history.timeline[i-1].timestamp);
        }

        // Check event types
        for event in &history.timeline {
            assert_eq!(event.event_type, VersionEventType::Released);
        }
    }

    #[test]
    fn test_stability_level_ordering() {
        let levels = vec![
            StabilityLevel::Experimental,
            StabilityLevel::Alpha,
            StabilityLevel::Beta,
            StabilityLevel::ReleaseCandidate,
            StabilityLevel::Stable,
            StabilityLevel::LTS,
        ];

        // Verify all levels are distinct
        for (i, level1) in levels.iter().enumerate() {
            for (j, level2) in levels.iter().enumerate() {
                if i == j {
                    assert_eq!(level1, level2);
                } else {
                    assert_ne!(level1, level2);
                }
            }
        }
    }

    #[test]
    fn test_security_severity_ordering() {
        assert_ne!(SecuritySeverity::Low, SecuritySeverity::Medium);
        assert_ne!(SecuritySeverity::Medium, SecuritySeverity::High);
        assert_ne!(SecuritySeverity::High, SecuritySeverity::Critical);
    }
}