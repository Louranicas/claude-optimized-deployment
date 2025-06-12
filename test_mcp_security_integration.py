#!/usr/bin/env python3
"""Integration test for MCP Security Servers."""

import asyncio
import json
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch
import pytest

from src.mcp.security.sast_server import SASTMCPServer
from src.mcp.security.supply_chain_server import SupplyChainSecurityMCPServer
from src.mcp.security.scanner_server import SecurityScannerMCPServer


class TestMCPSecurityIntegration:
    """Test suite for MCP Security Server integration."""
    
    @pytest.fixture
    async def temp_project(self):
        """Create temporary project structure for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)
            
            # Create package.json for npm project
            package_json = {
                "name": "test-project",
                "version": "1.0.0",
                "dependencies": {
                    "express": "^4.18.0",
                    "lodash": "^4.17.21",
                    "moment": "^2.29.0"
                },
                "devDependencies": {
                    "mocha": "^10.0.0",
                    "chai": "^4.3.0"
                }
            }
            
            with open(project_path / "package.json", "w") as f:
                json.dump(package_json, f, indent=2)
            
            # Create requirements.txt for Python project
            requirements = [
                "django==3.2.0",
                "requests==2.25.1",
                "numpy==1.21.0",
                "flask==2.0.1"
            ]
            
            with open(project_path / "requirements.txt", "w") as f:
                f.write("\n".join(requirements))
            
            # Create sample Python code with vulnerabilities
            python_code = '''
import os
import subprocess
from django.conf import settings

# SQL Injection vulnerability
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = %s" % user_id
    cursor.execute(query)  # Vulnerable
    return cursor.fetchone()

# Command injection vulnerability
def backup_data(filename):
    cmd = "tar -czf backup.tar.gz " + filename
    os.system(cmd)  # Vulnerable

# Hardcoded secret
API_KEY = "sk_live_abcd1234567890"
DATABASE_URL = "postgresql://user:secret123@localhost/db"

# Weak crypto
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()  # Weak

# Eval vulnerability
def process_input(user_input):
    result = eval(user_input)  # Dangerous
    return result
'''
            
            with open(project_path / "app.py", "w") as f:
                f.write(python_code)
            
            # Create JavaScript code with vulnerabilities
            js_code = '''
const express = require('express');
const mysql = require('mysql');

const app = express();

// SQL Injection vulnerability
app.get('/user/:id', (req, res) => {
    const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
    connection.query(query, (err, results) => {  // Vulnerable
        res.json(results);
    });
});

// XSS vulnerability
app.get('/welcome', (req, res) => {
    res.send(`<h1>Welcome ${req.query.name}</h1>`);  // Vulnerable
});

// Hardcoded credentials
const dbConfig = {
    host: 'localhost',
    user: 'admin',
    password: 'admin123',  // Hardcoded
    database: 'myapp'
};

// Command injection
const { exec } = require('child_process');
app.post('/backup', (req, res) => {
    exec(`backup.sh ${req.body.filename}`, (err, stdout) => {  // Vulnerable
        res.send(stdout);
    });
});
'''
            
            with open(project_path / "server.js", "w") as f:
                f.write(js_code)
            
            yield project_path
    
    @pytest.mark.asyncio
    async def test_sast_server_comprehensive_scan(self, temp_project):
        """Test comprehensive SAST scanning across multiple languages."""
        server = SASTMCPServer()
        
        # Test Semgrep scan
        result = await server.call_tool("run_semgrep_scan", {
            "target_path": str(temp_project),
            "config": "security",
            "severity_filter": "WARNING"
        })
        
        assert result["scan_type"] == "semgrep"
        assert "findings" in result
        assert "stats" in result
        print(f"✓ Semgrep scan found {result['stats']['total']} issues")
        
        # Test pattern analysis
        result = await server.call_tool("analyze_code_patterns", {
            "target_path": str(temp_project),
            "language": "auto",
            "pattern_types": "injection,crypto,auth"
        })
        
        assert result["scan_type"] == "pattern_analysis"
        assert len(result["findings"]) > 0
        print(f"✓ Pattern analysis found {len(result['findings'])} security issues")
        
        # Test Python-specific Bandit scan
        result = await server.call_tool("run_bandit_scan", {
            "target_path": str(temp_project / "app.py"),
            "severity_level": "LOW",
            "confidence_level": "LOW"
        })
        
        assert result["scan_type"] == "bandit"
        print(f"✓ Bandit scan completed with {len(result['findings'])} findings")
        
        # Test secret detection
        result = await server.call_tool("detect_hardcoded_secrets", {
            "target_path": str(temp_project),
            "custom_patterns": '["sk_live_[a-zA-Z0-9]{24}"]'
        })
        
        assert result["scan_type"] == "secret_detection"
        assert len(result["findings"]) > 0
        print(f"✓ Secret detection found {len(result['findings'])} potential secrets")
        
        # Test dependency analysis
        result = await server.call_tool("analyze_dependencies", {
            "project_path": str(temp_project),
            "check_licenses": True,
            "check_outdated": True
        })
        
        assert result["scan_type"] == "dependency_analysis"
        print(f"✓ Dependency analysis completed")
    
    @pytest.mark.asyncio
    async def test_supply_chain_security_comprehensive(self, temp_project):
        """Test comprehensive supply chain security analysis."""
        server = SupplyChainSecurityMCPServer()
        
        # Test SBOM generation
        result = await server.call_tool("generate_sbom", {
            "project_path": str(temp_project),
            "format": "cyclonedx",
            "include_dev_deps": True
        })
        
        assert result["scan_type"] == "sbom_generation"
        assert result["sbom"] is not None
        assert result["stats"]["total_packages"] > 0
        print(f"✓ SBOM generated with {result['stats']['total_packages']} packages")
        
        # Test dependency confusion detection
        result = await server.call_tool("detect_dependency_confusion", {
            "project_path": str(temp_project),
            "check_internal_packages": True
        })
        
        assert result["scan_type"] == "dependency_confusion"
        assert "findings" in result
        print(f"✓ Dependency confusion check completed")
        
        # Test license compliance
        result = await server.call_tool("analyze_license_compliance", {
            "project_path": str(temp_project),
            "allowed_licenses": "MIT,Apache-2.0,BSD-3-Clause",
            "fail_on_violation": False
        })
        
        assert result["scan_type"] == "license_compliance"
        assert "compliance_status" in result
        print(f"✓ License compliance check: {result['compliance_status']['compliant']}")
        
        # Test package integrity verification
        result = await server.call_tool("verify_package_integrity", {
            "project_path": str(temp_project),
            "verify_signatures": True,
            "check_checksums": True
        })
        
        assert result["scan_type"] == "package_integrity"
        assert "integrity_assessment" in result
        print(f"✓ Package integrity check: {result['integrity_assessment']['integrity_score']}% verified")
        
        # Test transitive dependency analysis
        result = await server.call_tool("analyze_transitive_dependencies", {
            "project_path": str(temp_project),
            "max_depth": 3,
            "include_optional": False
        })
        
        assert result["scan_type"] == "transitive_dependencies"
        assert "dependency_tree" in result
        print(f"✓ Transitive dependency analysis completed")
        
        # Test supply chain risk assessment
        result = await server.call_tool("assess_supply_chain_risk", {
            "project_path": str(temp_project),
            "risk_factors": "age,popularity,maintenance,vulnerabilities"
        })
        
        assert result["scan_type"] == "supply_chain_risk_assessment"
        assert "overall_risk" in result
        print(f"✓ Supply chain risk: {result['overall_risk']['level']} (score: {result['overall_risk']['score']})")
    
    @pytest.mark.asyncio
    async def test_existing_security_scanner_integration(self, temp_project):
        """Test integration with existing security scanner."""
        server = SecurityScannerMCPServer()
        
        # Test file security scan
        result = await server.call_tool("file_security_scan", {
            "target_path": str(temp_project),
            "scan_type": "all",
            "recursive": True
        })
        
        assert result["scan_type"] == "file_security"
        assert "findings" in result
        print(f"✓ File security scan found {result['security_summary']['total_findings']} issues")
        
        # Test credential scan
        result = await server.call_tool("credential_scan", {
            "target_path": str(temp_project),
            "entropy_analysis": True
        })
        
        assert result["scan_type"] == "credential_scan"
        assert len(result["credentials_found"]) > 0
        print(f"✓ Credential scan found {len(result['credentials_found'])} potential credentials")
    
    @pytest.mark.asyncio
    async def test_security_server_performance(self, temp_project):
        """Test security server performance under load."""
        sast_server = SASTMCPServer()
        supply_chain_server = SupplyChainSecurityMCPServer()
        scanner_server = SecurityScannerMCPServer()
        
        # Run multiple scans concurrently
        tasks = [
            sast_server.call_tool("analyze_code_patterns", {
                "target_path": str(temp_project),
                "language": "auto"
            }),
            supply_chain_server.call_tool("generate_sbom", {
                "project_path": str(temp_project),
                "format": "json"
            }),
            scanner_server.call_tool("file_security_scan", {
                "target_path": str(temp_project),
                "scan_type": "secrets"
            })
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Verify all tasks completed successfully
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                pytest.fail(f"Task {i} failed: {result}")
            else:
                assert "scan_type" in result
        
        print("✓ Concurrent security scans completed successfully")
    
    @pytest.mark.asyncio
    async def test_comprehensive_security_workflow(self, temp_project):
        """Test complete security workflow integration."""
        print("\n🔍 Running Comprehensive Security Workflow...")
        
        # Step 1: SAST Analysis
        print("Step 1: Static Application Security Testing")
        sast_server = SASTMCPServer()
        
        sast_results = await sast_server.call_tool("run_semgrep_scan", {
            "target_path": str(temp_project),
            "config": "security"
        })
        
        critical_sast_issues = [f for f in sast_results.get("findings", []) 
                               if f.get("severity") == "ERROR"]
        print(f"   - Found {len(critical_sast_issues)} critical SAST issues")
        
        # Step 2: Supply Chain Analysis
        print("Step 2: Supply Chain Security Analysis")
        supply_chain_server = SupplyChainSecurityMCPServer()
        
        # Generate SBOM first
        sbom_result = await supply_chain_server.call_tool("generate_sbom", {
            "project_path": str(temp_project),
            "format": "cyclonedx"
        })
        print(f"   - Generated SBOM with {sbom_result['stats']['total_packages']} packages")
        
        # Check for dependency confusion
        confusion_result = await supply_chain_server.call_tool("detect_dependency_confusion", {
            "project_path": str(temp_project)
        })
        
        critical_supply_chain_issues = (
            len(confusion_result["findings"]["malicious_packages"]) +
            len(confusion_result["findings"]["typosquatting"])
        )
        print(f"   - Found {critical_supply_chain_issues} critical supply chain issues")
        
        # Step 3: Secret Detection
        print("Step 3: Secret and Credential Detection")
        scanner_server = SecurityScannerMCPServer()
        
        secret_result = await scanner_server.call_tool("credential_scan", {
            "target_path": str(temp_project),
            "entropy_analysis": True
        })
        
        critical_secrets = [s for s in secret_result.get("credentials_found", []) 
                          if s.get("severity") == "CRITICAL"]
        print(f"   - Found {len(critical_secrets)} critical secrets")
        
        # Step 4: Comprehensive Risk Assessment
        print("Step 4: Overall Risk Assessment")
        
        risk_result = await supply_chain_server.call_tool("assess_supply_chain_risk", {
            "project_path": str(temp_project),
            "risk_factors": "age,popularity,maintenance,vulnerabilities,licenses"
        })
        
        overall_risk = risk_result["overall_risk"]["level"]
        print(f"   - Overall supply chain risk: {overall_risk}")
        
        # Step 5: Generate Security Report
        print("Step 5: Security Report Generation")
        
        security_report = {
            "timestamp": sast_results["timestamp"],
            "project_path": str(temp_project),
            "summary": {
                "total_issues": (
                    len(sast_results.get("findings", [])) +
                    len(secret_result.get("credentials_found", [])) +
                    critical_supply_chain_issues
                ),
                "critical_issues": (
                    len(critical_sast_issues) +
                    len(critical_secrets) +
                    critical_supply_chain_issues
                ),
                "overall_risk_level": overall_risk
            },
            "detailed_findings": {
                "sast": sast_results,
                "supply_chain": {
                    "sbom": sbom_result,
                    "confusion_check": confusion_result,
                    "risk_assessment": risk_result
                },
                "secrets": secret_result
            }
        }
        
        # Step 6: Security Recommendations
        recommendations = []
        
        if critical_sast_issues:
            recommendations.append("CRITICAL: Address static analysis security vulnerabilities immediately")
        
        if critical_secrets:
            recommendations.append("CRITICAL: Remove hardcoded secrets and implement proper secret management")
        
        if critical_supply_chain_issues:
            recommendations.append("CRITICAL: Review and remediate supply chain security issues")
        
        if overall_risk in ["CRITICAL", "HIGH"]:
            recommendations.append("HIGH: Implement comprehensive security monitoring and controls")
        
        recommendations.extend([
            "Implement security gates in CI/CD pipeline",
            "Establish regular security scanning schedule",
            "Create incident response procedures for security issues",
            "Implement developer security training"
        ])
        
        security_report["recommendations"] = recommendations
        
        print("\n📊 Security Assessment Complete!")
        print(f"   Total Issues: {security_report['summary']['total_issues']}")
        print(f"   Critical Issues: {security_report['summary']['critical_issues']}")
        print(f"   Overall Risk: {security_report['summary']['overall_risk_level']}")
        print(f"   Recommendations: {len(recommendations)}")
        
        # Verify the workflow produced meaningful results
        assert security_report["summary"]["total_issues"] > 0
        assert len(recommendations) > 0
        assert security_report["detailed_findings"]["sast"]["findings"]
        
        print("\n✅ Comprehensive security workflow completed successfully!")
        
        return security_report


async def run_integration_tests():
    """Run all MCP security integration tests."""
    print("🚀 Starting MCP Security Integration Tests")
    
    # Create test instance
    test_instance = TestMCPSecurityIntegration()
    
    # Create temporary project
    import tempfile
    with tempfile.TemporaryDirectory() as temp_dir:
        project_path = Path(temp_dir)
        
        # Set up test project
        await test_instance.temp_project.__anext__()
        
        try:
            # Run comprehensive workflow test
            security_report = await test_instance.test_comprehensive_security_workflow(project_path)
            
            print("\n🎯 Integration Test Results:")
            print(f"   Security Servers: 3 (SAST, Supply Chain, Scanner)")
            print(f"   Total Security Issues Found: {security_report['summary']['total_issues']}")
            print(f"   Critical Issues: {security_report['summary']['critical_issues']}")
            print(f"   Risk Level: {security_report['summary']['overall_risk_level']}")
            print(f"   Recommendations: {len(security_report['recommendations'])}")
            
            print("\n✅ All MCP Security Integration Tests Passed!")
            
        except Exception as e:
            print(f"\n❌ Integration test failed: {e}")
            raise


if __name__ == "__main__":
    # Run the integration tests
    asyncio.run(run_integration_tests())