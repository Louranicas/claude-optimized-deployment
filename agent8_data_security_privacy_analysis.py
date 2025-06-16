#!/usr/bin/env python3
"""
Agent 8 - Phase 8: Data Security & Privacy Assessment
Comprehensive analysis and validation of data protection measures.

This script performs:
1. Data inventory and classification analysis
2. Encryption implementation assessment
3. Privacy compliance evaluation  
4. Data retention policy validation
5. Access control security review
6. Regulatory compliance gap analysis
"""

import os
import sys
import json
import logging
import hashlib
import re
import yaml
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import subprocess
import tempfile

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'agent8_data_security_analysis_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class DataSecurityPrivacyAnalyzer:
    """Comprehensive data security and privacy assessment tool."""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.analysis_results = {
            "timestamp": datetime.now().isoformat(),
            "project_path": str(self.project_root),
            "data_inventory": {},
            "encryption_assessment": {},
            "privacy_compliance": {},
            "data_retention": {},
            "access_controls": {},
            "vulnerabilities": [],
            "compliance_gaps": {},
            "recommendations": []
        }
        
    def run_comprehensive_analysis(self) -> Dict[str, Any]:
        """Execute complete data security and privacy assessment."""
        logger.info("Starting comprehensive data security and privacy analysis...")
        
        try:
            # 1. Data Inventory and Classification
            logger.info("Phase 1: Data inventory and classification analysis")
            self._analyze_data_inventory()
            
            # 2. Encryption Implementation Assessment
            logger.info("Phase 2: Encryption implementation assessment")
            self._assess_encryption_implementations()
            
            # 3. Privacy Protection Analysis
            logger.info("Phase 3: Privacy protection and compliance analysis")
            self._analyze_privacy_compliance()
            
            # 4. Data Retention Policy Evaluation
            logger.info("Phase 4: Data retention policy evaluation")
            self._evaluate_data_retention()
            
            # 5. Access Control Security Review
            logger.info("Phase 5: Access control security review")
            self._review_access_controls()
            
            # 6. Vulnerability Detection
            logger.info("Phase 6: Security vulnerability detection")
            self._detect_security_vulnerabilities()
            
            # 7. Regulatory Compliance Analysis
            logger.info("Phase 7: Regulatory compliance gap analysis")
            self._analyze_compliance_gaps()
            
            # 8. Generate Recommendations
            logger.info("Phase 8: Generating security recommendations")
            self._generate_recommendations()
            
            logger.info("Data security and privacy analysis completed successfully")
            return self.analysis_results
            
        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}")
            self.analysis_results["error"] = str(e)
            return self.analysis_results
    
    def _analyze_data_inventory(self):
        """Analyze and classify all data types in the project."""
        data_types = {
            "personal_data": [],
            "sensitive_data": [],
            "business_data": [],
            "technical_metadata": [],
            "credentials": []
        }
        
        # Scan for different data patterns
        patterns = {
            "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            "ip_address": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            "api_key": r'(api[_-]?key|token|secret)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})',
            "password": r'(password|passwd|pwd)["\']?\s*[:=]\s*["\']?([^\s"\']+)',
            "jwt_token": r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            "session_id": r'(session[_-]?id|sid)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{16,})',
            "user_id": r'(user[_-]?id|uid)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]+)',
            "database_url": r'(postgres|mysql|mongodb)://[^\s]+',
        }
        
        # Scan files for data patterns
        for file_path in self.project_root.rglob("*"):
            if file_path.is_file() and self._is_scannable_file(file_path):
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    
                    for pattern_name, pattern in patterns.items():
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            file_info = {
                                "file": str(file_path),
                                "pattern": pattern_name,
                                "matches": len(matches),
                                "classification": self._classify_data_type(pattern_name)
                            }
                            
                            data_types[file_info["classification"]].append(file_info)
                            
                except Exception as e:
                    logger.warning(f"Could not scan file {file_path}: {e}")
        
        # Analyze configuration files for sensitive data
        config_files = list(self.project_root.rglob("*.json")) + \
                      list(self.project_root.rglob("*.yaml")) + \
                      list(self.project_root.rglob("*.yml")) + \
                      list(self.project_root.rglob("*.toml"))
        
        for config_file in config_files:
            if self._is_config_file(config_file):
                self._analyze_config_file(config_file, data_types)
        
        self.analysis_results["data_inventory"] = {
            "total_files_scanned": len(list(self.project_root.rglob("*"))),
            "data_types_found": data_types,
            "classification_summary": self._generate_classification_summary(data_types),
            "high_risk_files": self._identify_high_risk_files(data_types)
        }
    
    def _assess_encryption_implementations(self):
        """Assess encryption implementations across the project."""
        encryption_analysis = {
            "at_rest_encryption": [],
            "in_transit_encryption": [],
            "key_management": [],
            "crypto_libraries": [],
            "weaknesses": []
        }
        
        # Look for encryption implementations
        crypto_patterns = {
            "aes": r'(AES|aes)[_-]?(256|128|192)',
            "rsa": r'(RSA|rsa)[_-]?(2048|4096|1024)',
            "tls": r'(TLS|tls|SSL|ssl)[_-]?(1\.2|1\.3)',
            "bcrypt": r'bcrypt',
            "pbkdf2": r'PBKDF2|pbkdf2',
            "fernet": r'Fernet|fernet',
            "jwt": r'JWT|jwt',
            "hash": r'(SHA|sha)[_-]?(256|512|1)',
            "crypto_key": r'(key|Key)[_-]?(generation|rotation|management)',
        }
        
        # Scan Python files for crypto implementations
        for py_file in self.project_root.rglob("*.py"):
            try:
                content = py_file.read_text(encoding='utf-8', errors='ignore')
                
                # Check for crypto imports
                crypto_imports = re.findall(r'from\s+(cryptography|bcrypt|jwt|hashlib|secrets)\s+import', content)
                if crypto_imports:
                    encryption_analysis["crypto_libraries"].append({
                        "file": str(py_file),
                        "libraries": crypto_imports
                    })
                
                # Check for crypto patterns
                for pattern_name, pattern in crypto_patterns.items():
                    if re.search(pattern, content, re.IGNORECASE):
                        encryption_analysis["at_rest_encryption"].append({
                            "file": str(py_file),
                            "type": pattern_name,
                            "implementation": "present"
                        })
                
                # Check for weak crypto
                weak_patterns = [
                    r'MD5|md5',
                    r'SHA1|sha1',
                    r'DES|des',
                    r'RC4|rc4',
                    r'SSL[^v]|ssl[^v]'  # SSL without version
                ]
                
                for weak_pattern in weak_patterns:
                    if re.search(weak_pattern, content, re.IGNORECASE):
                        encryption_analysis["weaknesses"].append({
                            "file": str(py_file),
                            "weakness": weak_pattern,
                            "risk": "high"
                        })
                        
            except Exception as e:
                logger.warning(f"Could not analyze crypto in {py_file}: {e}")
        
        # Check TLS configuration
        self._check_tls_configuration(encryption_analysis)
        
        self.analysis_results["encryption_assessment"] = encryption_analysis
    
    def _analyze_privacy_compliance(self):
        """Analyze privacy protection mechanisms and regulatory compliance."""
        privacy_analysis = {
            "gdpr_compliance": {
                "right_to_erasure": False,
                "data_portability": False,
                "consent_management": False,
                "privacy_by_design": False,
                "breach_notification": False,
                "dpo_contact": False
            },
            "ccpa_compliance": {
                "consumer_rights": False,
                "do_not_sell": False,
                "data_categories": False,
                "third_party_sharing": False
            },
            "privacy_controls": [],
            "data_subject_rights": [],
            "privacy_policies": []
        }
        
        # Scan for privacy-related implementations
        privacy_keywords = [
            "gdpr", "ccpa", "privacy", "consent", "erasure", "portability",
            "data_subject", "right_to_delete", "privacy_policy", "cookie",
            "tracking", "anonymization", "pseudonymization"
        ]
        
        for file_path in self.project_root.rglob("*.py"):
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore').lower()
                
                for keyword in privacy_keywords:
                    if keyword in content:
                        privacy_analysis["privacy_controls"].append({
                            "file": str(file_path),
                            "keyword": keyword,
                            "context": "implementation_found"
                        })
                        
            except Exception as e:
                logger.warning(f"Could not analyze privacy in {file_path}: {e}")
        
        # Check for specific GDPR implementations
        self._check_gdpr_implementations(privacy_analysis)
        
        self.analysis_results["privacy_compliance"] = privacy_analysis
    
    def _evaluate_data_retention(self):
        """Evaluate data retention and deletion policies."""
        retention_analysis = {
            "retention_policies": [],
            "automated_deletion": [],
            "data_lifecycle": [],
            "compliance_gaps": []
        }
        
        # Look for retention-related code
        retention_patterns = {
            "cleanup": r'cleanup|purge|delete|remove',
            "expiry": r'expir|ttl|timeout|retention',
            "schedule": r'schedule|cron|periodic',
            "lifecycle": r'lifecycle|archive|backup'
        }
        
        for file_path in self.project_root.rglob("*.py"):
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                
                for pattern_name, pattern in retention_patterns.items():
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        retention_analysis["retention_policies"].append({
                            "file": str(file_path),
                            "type": pattern_name,
                            "implementations": len(matches)
                        })
                        
            except Exception as e:
                logger.warning(f"Could not analyze retention in {file_path}: {e}")
        
        # Check configuration files for retention settings
        config_files = list(self.project_root.rglob("*.yaml")) + list(self.project_root.rglob("*.yml"))
        for config_file in config_files:
            try:
                if "security" in str(config_file) or "config" in str(config_file):
                    with open(config_file, 'r') as f:
                        config_data = yaml.safe_load(f)
                        if config_data and isinstance(config_data, dict):
                            self._extract_retention_policies(config_data, retention_analysis, str(config_file))
            except Exception as e:
                logger.warning(f"Could not parse config {config_file}: {e}")
        
        self.analysis_results["data_retention"] = retention_analysis
    
    def _review_access_controls(self):
        """Review data access controls and authorization mechanisms."""
        access_analysis = {
            "authentication_methods": [],
            "authorization_models": [],
            "session_management": [],
            "audit_logging": [],
            "weaknesses": []
        }
        
        # Look for access control implementations
        auth_patterns = {
            "authentication": r'(authenticate|auth|login|signin)',
            "authorization": r'(authorize|permissions|roles|rbac)',
            "session": r'(session|token|jwt|cookie)',
            "audit": r'(audit|log|track|monitor)',
            "crypto": r'(hash|encrypt|sign|verify)'
        }
        
        for py_file in self.project_root.rglob("*.py"):
            try:
                content = py_file.read_text(encoding='utf-8', errors='ignore')
                
                for pattern_name, pattern in auth_patterns.items():
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        access_analysis[f"{pattern_name}_methods"].append({
                            "file": str(py_file),
                            "implementations": len(matches),
                            "strength": self._assess_auth_strength(content, pattern_name)
                        })
                        
            except Exception as e:
                logger.warning(f"Could not analyze access controls in {py_file}: {e}")
        
        # Check for weak access control patterns
        weak_patterns = [
            r'password\s*=\s*["\'][^"\']*["\']',  # Hardcoded passwords
            r'admin\s*=\s*true',  # Default admin access
            r'auth\s*=\s*false',  # Disabled authentication
            r'permissions\s*=\s*\[\]'  # Empty permissions
        ]
        
        for py_file in self.project_root.rglob("*.py"):
            try:
                content = py_file.read_text(encoding='utf-8', errors='ignore')
                
                for weak_pattern in weak_patterns:
                    if re.search(weak_pattern, content, re.IGNORECASE):
                        access_analysis["weaknesses"].append({
                            "file": str(py_file),
                            "weakness": weak_pattern,
                            "risk": "high"
                        })
                        
            except Exception as e:
                logger.warning(f"Could not check weak patterns in {py_file}: {e}")
        
        self.analysis_results["access_controls"] = access_analysis
    
    def _detect_security_vulnerabilities(self):
        """Detect data security vulnerabilities."""
        vulnerabilities = []
        
        # Check for hardcoded credentials
        credential_patterns = [
            (r'password\s*[:=]\s*["\'][^"\']+["\']', 'hardcoded_password', 'critical'),
            (r'api[_-]?key\s*[:=]\s*["\'][^"\']+["\']', 'hardcoded_api_key', 'critical'),
            (r'secret\s*[:=]\s*["\'][^"\']+["\']', 'hardcoded_secret', 'critical'),
            (r'token\s*[:=]\s*["\'][^"\']+["\']', 'hardcoded_token', 'high'),
            (r'aws[_-]?access[_-]?key', 'aws_credentials', 'critical'),
            (r'private[_-]?key', 'private_key_exposure', 'high')
        ]
        
        for file_path in self.project_root.rglob("*"):
            if file_path.is_file() and self._is_scannable_file(file_path):
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    
                    for pattern, vuln_type, severity in credential_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            vulnerabilities.append({
                                "type": vuln_type,
                                "severity": severity,
                                "file": str(file_path),
                                "matches": len(matches),
                                "description": f"Found {vuln_type} in {file_path.name}"
                            })
                            
                except Exception as e:
                    logger.warning(f"Could not scan for vulnerabilities in {file_path}: {e}")
        
        # Check for SQL injection vulnerabilities
        self._check_sql_injection_risks(vulnerabilities)
        
        # Check for data exposure risks
        self._check_data_exposure_risks(vulnerabilities)
        
        self.analysis_results["vulnerabilities"] = vulnerabilities
    
    def _analyze_compliance_gaps(self):
        """Analyze regulatory compliance gaps."""
        compliance_gaps = {
            "gdpr": [],
            "ccpa": [],
            "hipaa": [],
            "sox": [],
            "pci_dss": [],
            "iso_27001": []
        }
        
        # GDPR compliance checks
        gdpr_requirements = [
            ("right_to_erasure", "Article 17 - Right to erasure implementation"),
            ("data_portability", "Article 20 - Data portability implementation"),
            ("privacy_by_design", "Article 25 - Privacy by design"),
            ("breach_notification", "Article 33 - Breach notification (72 hours)"),
            ("dpia", "Article 35 - Data Protection Impact Assessment"),
            ("records_processing", "Article 30 - Records of processing activities")
        ]
        
        for requirement, description in gdpr_requirements:
            if not self._check_gdpr_requirement(requirement):
                compliance_gaps["gdpr"].append({
                    "requirement": requirement,
                    "description": description,
                    "status": "not_implemented",
                    "risk": "high"
                })
        
        # CCPA compliance checks
        ccpa_requirements = [
            ("consumer_rights", "Consumer rights portal"),
            ("do_not_sell", "Do not sell mechanism"),
            ("data_categories", "Data category disclosure"),
            ("third_party_sharing", "Third-party sharing disclosure")
        ]
        
        for requirement, description in ccpa_requirements:
            if not self._check_ccpa_requirement(requirement):
                compliance_gaps["ccpa"].append({
                    "requirement": requirement,
                    "description": description,
                    "status": "not_implemented",
                    "risk": "medium"
                })
        
        self.analysis_results["compliance_gaps"] = compliance_gaps
    
    def _generate_recommendations(self):
        """Generate security and privacy recommendations."""
        recommendations = []
        
        # Critical recommendations based on vulnerabilities
        critical_vulns = [v for v in self.analysis_results.get("vulnerabilities", []) 
                         if v.get("severity") == "critical"]
        
        if critical_vulns:
            recommendations.append({
                "priority": "critical",
                "category": "credential_security",
                "title": "Remove hardcoded credentials",
                "description": "Implement secure credential management using environment variables or secret management systems",
                "effort": "high",
                "timeline": "immediate",
                "compliance_impact": ["gdpr", "sox", "pci_dss"]
            })
        
        # GDPR compliance recommendations
        gdpr_gaps = self.analysis_results.get("compliance_gaps", {}).get("gdpr", [])
        if gdpr_gaps:
            recommendations.append({
                "priority": "high",
                "category": "privacy_compliance",
                "title": "Implement GDPR compliance measures",
                "description": "Develop data subject rights portal, breach notification procedures, and privacy by design practices",
                "effort": "high",
                "timeline": "90_days",
                "compliance_impact": ["gdpr"]
            })
        
        # Data retention recommendations
        if not self.analysis_results.get("data_retention", {}).get("retention_policies"):
            recommendations.append({
                "priority": "high",
                "category": "data_governance",
                "title": "Implement data retention policies",
                "description": "Create and enforce automated data retention and deletion policies",
                "effort": "medium",
                "timeline": "60_days",
                "compliance_impact": ["gdpr", "ccpa", "hipaa"]
            })
        
        # Encryption recommendations
        weak_crypto = self.analysis_results.get("encryption_assessment", {}).get("weaknesses", [])
        if weak_crypto:
            recommendations.append({
                "priority": "medium",
                "category": "encryption",
                "title": "Upgrade weak cryptographic implementations",
                "description": "Replace weak hashing algorithms and encryption methods with stronger alternatives",
                "effort": "medium",
                "timeline": "30_days",
                "compliance_impact": ["pci_dss", "hipaa", "sox"]
            })
        
        # Access control recommendations
        auth_weaknesses = self.analysis_results.get("access_controls", {}).get("weaknesses", [])
        if auth_weaknesses:
            recommendations.append({
                "priority": "medium",
                "category": "access_control",
                "title": "Strengthen access control mechanisms",
                "description": "Implement stronger authentication, authorization, and session management",
                "effort": "medium",
                "timeline": "45_days",
                "compliance_impact": ["sox", "iso_27001"]
            })
        
        self.analysis_results["recommendations"] = recommendations
    
    # Helper methods
    def _is_scannable_file(self, file_path: Path) -> bool:
        """Check if file can be scanned for data."""
        scannable_extensions = {'.py', '.js', '.json', '.yaml', '.yml', '.toml', '.txt', '.md', '.env', '.conf', '.cfg'}
        return (file_path.suffix.lower() in scannable_extensions and 
                file_path.stat().st_size < 10 * 1024 * 1024)  # Max 10MB
    
    def _is_config_file(self, file_path: Path) -> bool:
        """Check if file is a configuration file."""
        config_indicators = ['config', 'settings', 'env', 'secret', 'credential']
        return any(indicator in str(file_path).lower() for indicator in config_indicators)
    
    def _classify_data_type(self, pattern_name: str) -> str:
        """Classify data type based on pattern."""
        classification_map = {
            'email': 'personal_data',
            'ip_address': 'personal_data',
            'user_id': 'personal_data',
            'session_id': 'personal_data',
            'api_key': 'credentials',
            'password': 'credentials',
            'jwt_token': 'credentials',
            'database_url': 'sensitive_data'
        }
        return classification_map.get(pattern_name, 'technical_metadata')
    
    def _analyze_config_file(self, config_file: Path, data_types: Dict):
        """Analyze configuration file for sensitive data."""
        try:
            if config_file.suffix.lower() == '.json':
                with open(config_file, 'r') as f:
                    config_data = json.load(f)
            else:
                with open(config_file, 'r') as f:
                    config_data = yaml.safe_load(f)
            
            if config_data:
                self._extract_sensitive_config_data(config_data, config_file, data_types)
                
        except Exception as e:
            logger.warning(f"Could not parse config file {config_file}: {e}")
    
    def _extract_sensitive_config_data(self, data: Any, file_path: Path, data_types: Dict):
        """Extract sensitive data from configuration."""
        sensitive_keys = ['password', 'secret', 'key', 'token', 'credential', 'api_key']
        
        if isinstance(data, dict):
            for key, value in data.items():
                if any(sensitive_key in key.lower() for sensitive_key in sensitive_keys):
                    if value and isinstance(value, str) and len(value) > 5:
                        data_types['credentials'].append({
                            "file": str(file_path),
                            "key": key,
                            "classification": "credentials",
                            "risk": "high"
                        })
                elif isinstance(value, (dict, list)):
                    self._extract_sensitive_config_data(value, file_path, data_types)
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    self._extract_sensitive_config_data(item, file_path, data_types)
    
    def _generate_classification_summary(self, data_types: Dict) -> Dict:
        """Generate summary of data classification."""
        return {
            "personal_data_files": len(data_types.get("personal_data", [])),
            "sensitive_data_files": len(data_types.get("sensitive_data", [])),
            "credential_files": len(data_types.get("credentials", [])),
            "business_data_files": len(data_types.get("business_data", [])),
            "technical_metadata_files": len(data_types.get("technical_metadata", []))
        }
    
    def _identify_high_risk_files(self, data_types: Dict) -> List[str]:
        """Identify high-risk files containing sensitive data."""
        high_risk = []
        for category in ['credentials', 'sensitive_data']:
            for item in data_types.get(category, []):
                if item.get('file') not in high_risk:
                    high_risk.append(item.get('file'))
        return high_risk
    
    def _check_tls_configuration(self, encryption_analysis: Dict):
        """Check TLS configuration."""
        # Look for TLS/SSL configuration files
        tls_files = []
        for file_path in self.project_root.rglob("*"):
            if any(keyword in str(file_path).lower() for keyword in ['ssl', 'tls', 'cert', 'key']):
                tls_files.append(str(file_path))
        
        encryption_analysis["in_transit_encryption"] = {
            "tls_config_files": tls_files,
            "certificate_files": [f for f in tls_files if any(ext in f for ext in ['.crt', '.pem', '.cer'])],
            "key_files": [f for f in tls_files if '.key' in f]
        }
    
    def _check_gdpr_implementations(self, privacy_analysis: Dict):
        """Check for specific GDPR implementations."""
        gdpr_features = {
            "right_to_erasure": ["delete", "erase", "remove", "purge"],
            "data_portability": ["export", "download", "portability", "extract"],
            "consent_management": ["consent", "opt-in", "opt-out", "agree"],
            "privacy_by_design": ["privacy", "by_design", "data_protection"],
            "breach_notification": ["breach", "incident", "notification", "alert"]
        }
        
        for feature, keywords in gdpr_features.items():
            found = False
            for file_path in self.project_root.rglob("*.py"):
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore').lower()
                    if any(keyword in content for keyword in keywords):
                        privacy_analysis["gdpr_compliance"][feature] = True
                        found = True
                        break
                except:
                    continue
            
            if not found:
                privacy_analysis["gdpr_compliance"][feature] = False
    
    def _extract_retention_policies(self, config_data: Dict, retention_analysis: Dict, file_path: str):
        """Extract retention policies from configuration."""
        retention_keys = ['retention', 'ttl', 'expire', 'cleanup', 'purge', 'lifecycle']
        
        def extract_recursive(data, path=""):
            if isinstance(data, dict):
                for key, value in data.items():
                    current_path = f"{path}.{key}" if path else key
                    if any(ret_key in key.lower() for ret_key in retention_keys):
                        retention_analysis["retention_policies"].append({
                            "file": file_path,
                            "config_path": current_path,
                            "value": value,
                            "type": "retention_setting"
                        })
                    elif isinstance(value, dict):
                        extract_recursive(value, current_path)
        
        extract_recursive(config_data)
    
    def _assess_auth_strength(self, content: str, pattern_name: str) -> str:
        """Assess authentication strength."""
        strong_indicators = ['bcrypt', 'pbkdf2', 'argon2', 'scrypt', '2fa', 'mfa', 'totp']
        weak_indicators = ['md5', 'sha1', 'plain', 'base64', 'simple']
        
        content_lower = content.lower()
        
        if any(indicator in content_lower for indicator in strong_indicators):
            return "strong"
        elif any(indicator in content_lower for indicator in weak_indicators):
            return "weak"
        else:
            return "medium"
    
    def _check_sql_injection_risks(self, vulnerabilities: List):
        """Check for SQL injection vulnerabilities."""
        sql_patterns = [
            r'execute\s*\(\s*["\'][^"\']*\+',  # String concatenation in SQL
            r'SELECT\s+.*\+.*FROM',  # Dynamic SQL construction
            r'cursor\.execute\s*\([^)]*%[^)]*\)',  # String formatting in SQL
        ]
        
        for py_file in self.project_root.rglob("*.py"):
            try:
                content = py_file.read_text(encoding='utf-8', errors='ignore')
                
                for pattern in sql_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        vulnerabilities.append({
                            "type": "sql_injection_risk",
                            "severity": "high",
                            "file": str(py_file),
                            "description": f"Potential SQL injection vulnerability in {py_file.name}"
                        })
                        
            except Exception as e:
                logger.warning(f"Could not check SQL injection risks in {py_file}: {e}")
    
    def _check_data_exposure_risks(self, vulnerabilities: List):
        """Check for data exposure risks."""
        exposure_patterns = [
            r'print\s*\([^)]*password[^)]*\)',  # Logging passwords
            r'log\w*\s*\([^)]*secret[^)]*\)',  # Logging secrets
            r'console\.log\s*\([^)]*token[^)]*\)',  # JS console logging
        ]
        
        for file_path in self.project_root.rglob("*"):
            if file_path.suffix in ['.py', '.js', '.ts']:
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    
                    for pattern in exposure_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            vulnerabilities.append({
                                "type": "data_exposure_risk",
                                "severity": "medium",
                                "file": str(file_path),
                                "description": f"Potential data exposure through logging in {file_path.name}"
                            })
                            
                except Exception as e:
                    logger.warning(f"Could not check data exposure risks in {file_path}: {e}")
    
    def _check_gdpr_requirement(self, requirement: str) -> bool:
        """Check if GDPR requirement is implemented."""
        # Simplified check - in reality this would be more comprehensive
        implementation_indicators = {
            "right_to_erasure": ["delete_user_data", "erase_data", "user_deletion"],
            "data_portability": ["export_user_data", "data_export", "user_export"],
            "privacy_by_design": ["privacy_settings", "data_protection", "privacy_controls"],
            "breach_notification": ["incident_response", "breach_alert", "security_incident"],
            "dpia": ["privacy_impact", "dpia", "data_protection_assessment"],
            "records_processing": ["processing_records", "data_processing_log", "processing_activities"]
        }
        
        indicators = implementation_indicators.get(requirement, [])
        
        for py_file in self.project_root.rglob("*.py"):
            try:
                content = py_file.read_text(encoding='utf-8', errors='ignore').lower()
                if any(indicator in content for indicator in indicators):
                    return True
            except:
                continue
        
        return False
    
    def _check_ccpa_requirement(self, requirement: str) -> bool:
        """Check if CCPA requirement is implemented."""
        # Simplified check
        implementation_indicators = {
            "consumer_rights": ["consumer_request", "ccpa_request", "privacy_request"],
            "do_not_sell": ["do_not_sell", "opt_out_sale", "sale_opt_out"],
            "data_categories": ["data_categories", "personal_info_categories", "data_types"],
            "third_party_sharing": ["third_party_sharing", "data_sharing", "partner_sharing"]
        }
        
        indicators = implementation_indicators.get(requirement, [])
        
        for py_file in self.project_root.rglob("*.py"):
            try:
                content = py_file.read_text(encoding='utf-8', errors='ignore').lower()
                if any(indicator in content for indicator in indicators):
                    return True
            except:
                continue
        
        return False

def main():
    """Main execution function."""
    if len(sys.argv) != 2:
        print("Usage: python agent8_data_security_privacy_analysis.py <project_root>")
        sys.exit(1)
    
    project_root = sys.argv[1]
    if not os.path.exists(project_root):
        print(f"Error: Project root '{project_root}' does not exist")
        sys.exit(1)
    
    # Initialize analyzer
    analyzer = DataSecurityPrivacyAnalyzer(project_root)
    
    # Run comprehensive analysis
    results = analyzer.run_comprehensive_analysis()
    
    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_file = f"agent8_data_security_privacy_analysis_{timestamp}.json"
    
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    # Generate summary report
    logger.info("=== DATA SECURITY AND PRIVACY ANALYSIS SUMMARY ===")
    logger.info(f"Total files scanned: {results['data_inventory'].get('total_files_scanned', 0)}")
    logger.info(f"Vulnerabilities found: {len(results.get('vulnerabilities', []))}")
    logger.info(f"Critical vulnerabilities: {len([v for v in results.get('vulnerabilities', []) if v.get('severity') == 'critical'])}")
    logger.info(f"Recommendations generated: {len(results.get('recommendations', []))}")
    logger.info(f"GDPR compliance gaps: {len(results.get('compliance_gaps', {}).get('gdpr', []))}")
    logger.info(f"CCPA compliance gaps: {len(results.get('compliance_gaps', {}).get('ccpa', []))}")
    
    logger.info(f"Detailed results saved to: {results_file}")
    print(f"\nAnalysis complete. Results saved to: {results_file}")

if __name__ == "__main__":
    main()