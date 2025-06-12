"""
Security Expert - Specialized in security testing under load
Vulnerability testing, security performance impact analysis, and threat simulation
"""

import asyncio
import logging
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import hashlib
import re


class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityTestType(Enum):
    VULNERABILITY_SCAN = "vulnerability_scan"
    PENETRATION_TEST = "penetration_test"
    LOAD_SECURITY_TEST = "load_security_test"
    THREAT_SIMULATION = "threat_simulation"
    COMPLIANCE_CHECK = "compliance_check"
    SECURITY_REGRESSION = "security_regression"


@dataclass
class SecurityVulnerability:
    """Security vulnerability details"""
    vulnerability_id: str
    severity: ThreatLevel
    category: str
    description: str
    affected_components: List[str]
    exploitation_likelihood: float
    impact_score: float
    remediation_effort: str
    performance_impact: float


@dataclass
class SecurityAnalysis:
    """Security analysis result"""
    vulnerabilities: List[SecurityVulnerability]
    security_score: float
    threat_landscape: Dict[str, ThreatLevel]
    security_performance_impact: Dict[str, float]
    compliance_gaps: List[str]
    security_controls: Dict[str, bool]
    attack_vectors: List[str]
    security_monitoring_gaps: List[str]


class SecurityExpert:
    """
    Expert specializing in security testing and vulnerability assessment under load
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.name = "Security Expert"
        self.specializations = [
            "vulnerability_assessment",
            "penetration_testing",
            "security_performance_analysis",
            "threat_modeling",
            "compliance_validation",
            "security_monitoring",
            "incident_response"
        ]
        
        # Security frameworks and standards
        self.security_frameworks = {
            'owasp_top_10': [
                'injection', 'broken_authentication', 'sensitive_data_exposure',
                'xml_external_entities', 'broken_access_control', 'security_misconfiguration',
                'cross_site_scripting', 'insecure_deserialization', 'known_vulnerabilities',
                'insufficient_logging'
            ],
            'nist_cybersecurity': [
                'identify', 'protect', 'detect', 'respond', 'recover'
            ],
            'iso_27001': [
                'information_security_policies', 'organization_of_information_security',
                'human_resource_security', 'asset_management', 'access_control',
                'cryptography', 'physical_security', 'operations_security'
            ]
        }
        
        # Security controls checklist
        self.security_controls = {
            'authentication': ['multi_factor_auth', 'strong_passwords', 'session_management'],
            'authorization': ['role_based_access', 'principle_of_least_privilege', 'access_reviews'],
            'encryption': ['data_at_rest', 'data_in_transit', 'key_management'],
            'monitoring': ['security_logging', 'intrusion_detection', 'anomaly_detection'],
            'network': ['firewalls', 'network_segmentation', 'secure_protocols'],
            'application': ['input_validation', 'output_encoding', 'secure_coding']
        }
        
        # Common vulnerability patterns
        self.vulnerability_patterns = {
            'injection': {
                'patterns': [r'(\w+)\s*=\s*["\']?\s*\+\s*\w+', r'execute\s*\(\s*\w+\s*\)'],
                'severity': ThreatLevel.HIGH,
                'performance_impact': 0.1
            },
            'authentication_bypass': {
                'patterns': [r'auth\s*=\s*false', r'bypass.*auth', r'admin.*true'],
                'severity': ThreatLevel.CRITICAL,
                'performance_impact': 0.05
            },
            'sensitive_data_exposure': {
                'patterns': [r'password\s*=\s*["\'].*["\']', r'api_key\s*=', r'secret.*='],
                'severity': ThreatLevel.HIGH,
                'performance_impact': 0.02
            },
            'access_control': {
                'patterns': [r'authorize\s*=\s*false', r'public.*method', r'admin.*access'],
                'severity': ThreatLevel.MEDIUM,
                'performance_impact': 0.03
            }
        }
        
        # Performance impact factors for security measures
        self.security_performance_impact = {
            'encryption': {'cpu_overhead': 5, 'latency_increase': 2},
            'authentication': {'cpu_overhead': 3, 'latency_increase': 10},
            'authorization': {'cpu_overhead': 2, 'latency_increase': 5},
            'logging': {'io_overhead': 3, 'storage_increase': 15},
            'monitoring': {'cpu_overhead': 4, 'network_overhead': 2},
            'scanning': {'cpu_overhead': 10, 'io_overhead': 5}
        }
        
        # Historical security data
        self.security_history: List[Dict[str, Any]] = []
        
    async def analyze_and_recommend(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze system security and provide expert recommendations
        """
        self.logger.info("Security Expert analyzing security posture under load")
        
        try:
            # Extract security-relevant metrics
            current_metrics = context.get('current_metrics', {})
            system_state = context.get('system_state', {})
            historical_data = context.get('historical_data', [])
            objectives = context.get('objectives', [])
            
            # Perform comprehensive security analysis
            analysis = await self._analyze_security(
                current_metrics, system_state, historical_data
            )
            
            # Generate security strategy
            strategy = await self._generate_security_strategy(analysis, objectives)
            
            # Assess confidence based on security data completeness
            confidence = self._calculate_confidence(current_metrics, system_state)
            
            # Generate implementation steps
            implementation_steps = self._generate_implementation_steps(strategy, analysis)
            
            # Identify metrics to monitor
            metrics_to_monitor = self._identify_monitoring_metrics(analysis)
            
            recommendation = {
                'strategy': strategy['name'],
                'confidence': confidence,
                'reasoning': self._generate_reasoning(analysis, strategy),
                'expected_outcome': strategy['expected_outcome'],
                'risk_assessment': self._assess_overall_security_risk(analysis),
                'implementation_steps': implementation_steps,
                'metrics_to_monitor': metrics_to_monitor,
                'security_analysis': {
                    'vulnerabilities': [self._vulnerability_to_dict(v) for v in analysis.vulnerabilities],
                    'security_score': analysis.security_score,
                    'threat_landscape': {k: v.value for k, v in analysis.threat_landscape.items()},
                    'security_performance_impact': analysis.security_performance_impact,
                    'compliance_gaps': analysis.compliance_gaps,
                    'security_controls': analysis.security_controls,
                    'attack_vectors': analysis.attack_vectors,
                    'security_monitoring_gaps': analysis.security_monitoring_gaps
                }
            }
            
            # Store analysis for learning
            self._store_analysis(analysis, recommendation)
            
            return recommendation
            
        except Exception as e:
            self.logger.error(f"Security analysis failed: {str(e)}")
            return self._generate_fallback_recommendation()
    
    async def _analyze_security(
        self,
        current_metrics: Dict[str, Any],
        system_state: Dict[str, Any],
        historical_data: List[Dict[str, Any]]
    ) -> SecurityAnalysis:
        """Comprehensive security analysis"""
        
        # Scan for vulnerabilities
        vulnerabilities = await self._scan_vulnerabilities(system_state, current_metrics)
        
        # Calculate security score
        security_score = self._calculate_security_score(vulnerabilities, system_state)
        
        # Analyze threat landscape
        threat_landscape = await self._analyze_threat_landscape(system_state, historical_data)
        
        # Assess security performance impact
        security_performance_impact = self._assess_security_performance_impact(
            current_metrics, system_state
        )
        
        # Check compliance gaps
        compliance_gaps = await self._check_compliance_gaps(system_state)
        
        # Evaluate security controls
        security_controls = self._evaluate_security_controls(system_state)
        
        # Identify attack vectors
        attack_vectors = await self._identify_attack_vectors(system_state, current_metrics)
        
        # Find security monitoring gaps
        security_monitoring_gaps = self._identify_monitoring_gaps(system_state)
        
        return SecurityAnalysis(
            vulnerabilities=vulnerabilities,
            security_score=security_score,
            threat_landscape=threat_landscape,
            security_performance_impact=security_performance_impact,
            compliance_gaps=compliance_gaps,
            security_controls=security_controls,
            attack_vectors=attack_vectors,
            security_monitoring_gaps=security_monitoring_gaps
        )
    
    async def _scan_vulnerabilities(
        self,
        system_state: Dict[str, Any],
        current_metrics: Dict[str, Any]
    ) -> List[SecurityVulnerability]:
        """Scan for security vulnerabilities"""
        vulnerabilities = []
        
        # Check for common OWASP Top 10 vulnerabilities
        for vuln_type in self.security_frameworks['owasp_top_10']:
            vuln = await self._check_owasp_vulnerability(vuln_type, system_state, current_metrics)
            if vuln:
                vulnerabilities.append(vuln)
        
        # Check for infrastructure vulnerabilities
        infra_vulns = await self._check_infrastructure_vulnerabilities(system_state)
        vulnerabilities.extend(infra_vulns)
        
        # Check for configuration vulnerabilities
        config_vulns = await self._check_configuration_vulnerabilities(system_state)
        vulnerabilities.extend(config_vulns)
        
        # Check for performance-related security issues
        perf_vulns = await self._check_performance_security_issues(current_metrics)
        vulnerabilities.extend(perf_vulns)
        
        return vulnerabilities
    
    async def _check_owasp_vulnerability(
        self,
        vuln_type: str,
        system_state: Dict[str, Any],
        current_metrics: Dict[str, Any]
    ) -> Optional[SecurityVulnerability]:
        """Check for specific OWASP vulnerability"""
        
        if vuln_type == 'injection':
            if not system_state.get('input_validation', False):
                return SecurityVulnerability(
                    vulnerability_id=f"OWASP-A03-{hash(vuln_type) % 10000}",
                    severity=ThreatLevel.HIGH,
                    category="Injection",
                    description="SQL injection vulnerability due to lack of input validation",
                    affected_components=["database", "web_application"],
                    exploitation_likelihood=0.7,
                    impact_score=8.5,
                    remediation_effort="medium",
                    performance_impact=0.1
                )
        
        elif vuln_type == 'broken_authentication':
            if not system_state.get('multi_factor_auth', False):
                return SecurityVulnerability(
                    vulnerability_id=f"OWASP-A02-{hash(vuln_type) % 10000}",
                    severity=ThreatLevel.HIGH,
                    category="Broken Authentication",
                    description="Weak authentication mechanisms without MFA",
                    affected_components=["authentication_service", "user_management"],
                    exploitation_likelihood=0.6,
                    impact_score=7.8,
                    remediation_effort="medium",
                    performance_impact=0.05
                )
        
        elif vuln_type == 'sensitive_data_exposure':
            if not system_state.get('encryption_at_rest', False):
                return SecurityVulnerability(
                    vulnerability_id=f"OWASP-A03-{hash(vuln_type) % 10000}",
                    severity=ThreatLevel.HIGH,
                    category="Sensitive Data Exposure",
                    description="Sensitive data not encrypted at rest",
                    affected_components=["database", "file_storage"],
                    exploitation_likelihood=0.5,
                    impact_score=8.0,
                    remediation_effort="high",
                    performance_impact=0.15
                )
        
        elif vuln_type == 'broken_access_control':
            if not system_state.get('role_based_access_control', False):
                return SecurityVulnerability(
                    vulnerability_id=f"OWASP-A01-{hash(vuln_type) % 10000}",
                    severity=ThreatLevel.MEDIUM,
                    category="Broken Access Control",
                    description="Inadequate access control implementation",
                    affected_components=["authorization_service", "api_endpoints"],
                    exploitation_likelihood=0.8,
                    impact_score=6.5,
                    remediation_effort="medium",
                    performance_impact=0.08
                )
        
        elif vuln_type == 'security_misconfiguration':
            misconfigs = []
            if system_state.get('debug_mode', False):
                misconfigs.append("debug mode enabled")
            if not system_state.get('security_headers', False):
                misconfigs.append("missing security headers")
            if not system_state.get('secure_defaults', True):
                misconfigs.append("insecure default configurations")
            
            if misconfigs:
                return SecurityVulnerability(
                    vulnerability_id=f"OWASP-A05-{hash(vuln_type) % 10000}",
                    severity=ThreatLevel.MEDIUM,
                    category="Security Misconfiguration",
                    description=f"Security misconfigurations: {', '.join(misconfigs)}",
                    affected_components=["web_server", "application_server"],
                    exploitation_likelihood=0.7,
                    impact_score=5.5,
                    remediation_effort="low",
                    performance_impact=0.02
                )
        
        elif vuln_type == 'insufficient_logging':
            if not system_state.get('security_logging', False):
                return SecurityVulnerability(
                    vulnerability_id=f"OWASP-A09-{hash(vuln_type) % 10000}",
                    severity=ThreatLevel.MEDIUM,
                    category="Insufficient Logging & Monitoring",
                    description="Inadequate security logging and monitoring",
                    affected_components=["logging_system", "monitoring_system"],
                    exploitation_likelihood=0.4,
                    impact_score=4.0,
                    remediation_effort="medium",
                    performance_impact=0.12
                )
        
        return None
    
    async def _check_infrastructure_vulnerabilities(
        self,
        system_state: Dict[str, Any]
    ) -> List[SecurityVulnerability]:
        """Check for infrastructure security vulnerabilities"""
        vulnerabilities = []
        
        # Check for unpatched systems
        last_patch_days = system_state.get('last_security_patch_days', 30)
        if last_patch_days > 30:
            vulnerabilities.append(SecurityVulnerability(
                vulnerability_id=f"INFRA-PATCH-{hash('patch') % 10000}",
                severity=ThreatLevel.HIGH if last_patch_days > 90 else ThreatLevel.MEDIUM,
                category="Infrastructure",
                description=f"System not patched for {last_patch_days} days",
                affected_components=["operating_system", "runtime_environment"],
                exploitation_likelihood=0.6,
                impact_score=7.0,
                remediation_effort="low",
                performance_impact=0.05
            ))
        
        # Check for weak network security
        if not system_state.get('firewall_enabled', True):
            vulnerabilities.append(SecurityVulnerability(
                vulnerability_id=f"INFRA-FW-{hash('firewall') % 10000}",
                severity=ThreatLevel.HIGH,
                category="Network Security",
                description="Firewall not properly configured",
                affected_components=["network_infrastructure"],
                exploitation_likelihood=0.8,
                impact_score=6.5,
                remediation_effort="medium",
                performance_impact=0.03
            ))
        
        # Check for insecure protocols
        if system_state.get('http_enabled', False) and not system_state.get('https_redirect', False):
            vulnerabilities.append(SecurityVulnerability(
                vulnerability_id=f"INFRA-PROTO-{hash('protocol') % 10000}",
                severity=ThreatLevel.MEDIUM,
                category="Protocol Security",
                description="Insecure HTTP protocol enabled without HTTPS redirect",
                affected_components=["web_server"],
                exploitation_likelihood=0.7,
                impact_score=5.0,
                remediation_effort="low",
                performance_impact=0.01
            ))
        
        return vulnerabilities
    
    async def _check_configuration_vulnerabilities(
        self,
        system_state: Dict[str, Any]
    ) -> List[SecurityVulnerability]:
        """Check for configuration security vulnerabilities"""
        vulnerabilities = []
        
        # Check for default credentials
        if system_state.get('default_credentials', False):
            vulnerabilities.append(SecurityVulnerability(
                vulnerability_id=f"CONFIG-CRED-{hash('credentials') % 10000}",
                severity=ThreatLevel.CRITICAL,
                category="Configuration",
                description="Default credentials still in use",
                affected_components=["admin_interface", "database"],
                exploitation_likelihood=0.9,
                impact_score=9.0,
                remediation_effort="low",
                performance_impact=0.0
            ))
        
        # Check for excessive permissions
        if system_state.get('overprivileged_services', False):
            vulnerabilities.append(SecurityVulnerability(
                vulnerability_id=f"CONFIG-PERM-{hash('permissions') % 10000}",
                severity=ThreatLevel.MEDIUM,
                category="Privilege Escalation",
                description="Services running with excessive privileges",
                affected_components=["application_services"],
                exploitation_likelihood=0.5,
                impact_score=6.0,
                remediation_effort="medium",
                performance_impact=0.0
            ))
        
        # Check for insecure storage
        if not system_state.get('secure_config_storage', False):
            vulnerabilities.append(SecurityVulnerability(
                vulnerability_id=f"CONFIG-STOR-{hash('storage') % 10000}",
                severity=ThreatLevel.MEDIUM,
                category="Configuration Security",
                description="Configuration files stored insecurely",
                affected_components=["configuration_management"],
                exploitation_likelihood=0.4,
                impact_score=5.5,
                remediation_effort="medium",
                performance_impact=0.02
            ))
        
        return vulnerabilities
    
    async def _check_performance_security_issues(
        self,
        current_metrics: Dict[str, Any]
    ) -> List[SecurityVulnerability]:
        """Check for performance-related security issues"""
        vulnerabilities = []
        
        # Check for DoS vulnerability based on performance
        response_time = current_metrics.get('response_time', 0)
        if response_time > 5000:  # 5 seconds
            vulnerabilities.append(SecurityVulnerability(
                vulnerability_id=f"PERF-DOS-{hash('dos') % 10000}",
                severity=ThreatLevel.MEDIUM,
                category="Denial of Service",
                description=f"High response time ({response_time}ms) indicates DoS vulnerability",
                affected_components=["web_application", "load_balancer"],
                exploitation_likelihood=0.6,
                impact_score=5.0,
                remediation_effort="medium",
                performance_impact=0.0
            ))
        
        # Check for resource exhaustion
        cpu_usage = current_metrics.get('cpu_utilization', 0)
        memory_usage = current_metrics.get('memory_usage', 0)
        if cpu_usage > 95 or memory_usage > 95:
            vulnerabilities.append(SecurityVulnerability(
                vulnerability_id=f"PERF-EXHAUST-{hash('exhaust') % 10000}",
                severity=ThreatLevel.HIGH,
                category="Resource Exhaustion",
                description="System resources near exhaustion, potential for DoS",
                affected_components=["system_resources"],
                exploitation_likelihood=0.7,
                impact_score=6.5,
                remediation_effort="medium",
                performance_impact=0.0
            ))
        
        # Check for timing attack vulnerabilities
        response_time_variance = current_metrics.get('response_time_variance', 0)
        if response_time_variance > 1000:  # High variance
            vulnerabilities.append(SecurityVulnerability(
                vulnerability_id=f"PERF-TIMING-{hash('timing') % 10000}",
                severity=ThreatLevel.LOW,
                category="Timing Attack",
                description="High response time variance may enable timing attacks",
                affected_components=["authentication_service"],
                exploitation_likelihood=0.3,
                impact_score=3.0,
                remediation_effort="low",
                performance_impact=0.05
            ))
        
        return vulnerabilities
    
    def _calculate_security_score(
        self,
        vulnerabilities: List[SecurityVulnerability],
        system_state: Dict[str, Any]
    ) -> float:
        """Calculate overall security score (0-1)"""
        base_score = 1.0
        
        # Deduct points for vulnerabilities
        for vuln in vulnerabilities:
            severity_weight = {
                ThreatLevel.LOW: 0.05,
                ThreatLevel.MEDIUM: 0.1,
                ThreatLevel.HIGH: 0.2,
                ThreatLevel.CRITICAL: 0.3
            }
            impact_factor = vuln.exploitation_likelihood * (vuln.impact_score / 10)
            score_reduction = severity_weight[vuln.severity] * impact_factor
            base_score -= score_reduction
        
        # Add points for security controls
        security_controls_score = 0
        total_controls = 0
        
        for category, controls in self.security_controls.items():
            for control in controls:
                total_controls += 1
                if system_state.get(control, False):
                    security_controls_score += 1
        
        if total_controls > 0:
            controls_bonus = (security_controls_score / total_controls) * 0.3
            base_score += controls_bonus
        
        return max(0.0, min(1.0, base_score))
    
    async def _analyze_threat_landscape(
        self,
        system_state: Dict[str, Any],
        historical_data: List[Dict[str, Any]]
    ) -> Dict[str, ThreatLevel]:
        """Analyze current threat landscape"""
        threats = {}
        
        # Analyze based on system exposure
        if system_state.get('internet_facing', True):
            threats['external_attacks'] = ThreatLevel.HIGH
            threats['ddos_attacks'] = ThreatLevel.MEDIUM
        else:
            threats['external_attacks'] = ThreatLevel.LOW
            threats['ddos_attacks'] = ThreatLevel.LOW
        
        # Analyze based on data sensitivity
        if system_state.get('sensitive_data', False):
            threats['data_breaches'] = ThreatLevel.HIGH
            threats['insider_threats'] = ThreatLevel.MEDIUM
        else:
            threats['data_breaches'] = ThreatLevel.MEDIUM
            threats['insider_threats'] = ThreatLevel.LOW
        
        # Analyze based on historical patterns
        if len(historical_data) >= 5:
            security_incidents = sum(1 for d in historical_data if d.get('security_incident', False))
            if security_incidents > 2:
                threats['recurring_attacks'] = ThreatLevel.HIGH
            elif security_incidents > 0:
                threats['recurring_attacks'] = ThreatLevel.MEDIUM
            else:
                threats['recurring_attacks'] = ThreatLevel.LOW
        
        # Analyze based on technology stack
        if system_state.get('legacy_systems', False):
            threats['legacy_vulnerabilities'] = ThreatLevel.HIGH
        else:
            threats['legacy_vulnerabilities'] = ThreatLevel.LOW
        
        # Analyze based on user base
        user_count = system_state.get('user_count', 0)
        if user_count > 10000:
            threats['social_engineering'] = ThreatLevel.HIGH
            threats['account_takeover'] = ThreatLevel.MEDIUM
        elif user_count > 1000:
            threats['social_engineering'] = ThreatLevel.MEDIUM
            threats['account_takeover'] = ThreatLevel.MEDIUM
        else:
            threats['social_engineering'] = ThreatLevel.LOW
            threats['account_takeover'] = ThreatLevel.LOW
        
        return threats
    
    def _assess_security_performance_impact(
        self,
        current_metrics: Dict[str, Any],
        system_state: Dict[str, Any]
    ) -> Dict[str, float]:
        """Assess performance impact of security measures"""
        impact = {}
        
        # Calculate impact for each security measure
        for measure, factors in self.security_performance_impact.items():
            if system_state.get(f"{measure}_enabled", False):
                cpu_impact = factors.get('cpu_overhead', 0) / 100
                latency_impact = factors.get('latency_increase', 0) / 100
                io_impact = factors.get('io_overhead', 0) / 100
                
                # Combined impact score
                combined_impact = (cpu_impact + latency_impact + io_impact) / 3
                impact[measure] = combined_impact
            else:
                impact[measure] = 0.0
        
        # Calculate overall security overhead
        current_response_time = current_metrics.get('response_time', 100)
        baseline_response_time = current_response_time * 0.8  # Assume 20% security overhead
        
        if current_response_time > 0:
            security_overhead = (current_response_time - baseline_response_time) / current_response_time
            impact['overall_security_overhead'] = max(0, security_overhead)
        else:
            impact['overall_security_overhead'] = 0.0
        
        return impact
    
    async def _check_compliance_gaps(self, system_state: Dict[str, Any]) -> List[str]:
        """Check for compliance gaps"""
        gaps = []
        
        # GDPR compliance checks
        if system_state.get('processes_personal_data', False):
            if not system_state.get('gdpr_compliant', False):
                gaps.append("GDPR compliance: Data protection requirements not met")
            if not system_state.get('data_retention_policy', False):
                gaps.append("GDPR compliance: Data retention policy not implemented")
            if not system_state.get('right_to_be_forgotten', False):
                gaps.append("GDPR compliance: Right to be forgotten not implemented")
        
        # PCI DSS compliance checks
        if system_state.get('processes_payment_data', False):
            if not system_state.get('pci_compliant', False):
                gaps.append("PCI DSS compliance: Payment card data protection requirements not met")
            if not system_state.get('payment_data_encryption', False):
                gaps.append("PCI DSS compliance: Payment data encryption not implemented")
        
        # SOX compliance checks
        if system_state.get('financial_reporting_system', False):
            if not system_state.get('sox_compliant', False):
                gaps.append("SOX compliance: Financial reporting controls not adequate")
            if not system_state.get('audit_trail', False):
                gaps.append("SOX compliance: Audit trail not implemented")
        
        # HIPAA compliance checks
        if system_state.get('processes_health_data', False):
            if not system_state.get('hipaa_compliant', False):
                gaps.append("HIPAA compliance: Health data protection requirements not met")
            if not system_state.get('health_data_encryption', False):
                gaps.append("HIPAA compliance: Health data encryption not implemented")
        
        # ISO 27001 compliance checks
        if not system_state.get('information_security_policy', False):
            gaps.append("ISO 27001: Information security policy not documented")
        if not system_state.get('security_incident_management', False):
            gaps.append("ISO 27001: Security incident management not implemented")
        if not system_state.get('security_awareness_training', False):
            gaps.append("ISO 27001: Security awareness training not provided")
        
        return gaps
    
    def _evaluate_security_controls(self, system_state: Dict[str, Any]) -> Dict[str, bool]:
        """Evaluate implemented security controls"""
        controls = {}
        
        for category, control_list in self.security_controls.items():
            category_controls = {}
            for control in control_list:
                category_controls[control] = system_state.get(control, False)
            controls[category] = category_controls
        
        return controls
    
    async def _identify_attack_vectors(
        self,
        system_state: Dict[str, Any],
        current_metrics: Dict[str, Any]
    ) -> List[str]:
        """Identify potential attack vectors"""
        vectors = []
        
        # Web application attack vectors
        if system_state.get('web_application', True):
            vectors.append("Cross-site scripting (XSS) attacks")
            vectors.append("Cross-site request forgery (CSRF) attacks")
            if not system_state.get('input_validation', False):
                vectors.append("SQL injection attacks")
                vectors.append("Command injection attacks")
        
        # Network attack vectors
        if system_state.get('internet_facing', True):
            vectors.append("Distributed denial of service (DDoS) attacks")
            vectors.append("Man-in-the-middle attacks")
            if not system_state.get('https_only', False):
                vectors.append("Network eavesdropping")
        
        # Authentication attack vectors
        if not system_state.get('multi_factor_auth', False):
            vectors.append("Password brute force attacks")
            vectors.append("Credential stuffing attacks")
        
        if not system_state.get('account_lockout', False):
            vectors.append("Account enumeration attacks")
        
        # API attack vectors
        if system_state.get('api_endpoints', False):
            vectors.append("API abuse and rate limiting bypass")
            if not system_state.get('api_authentication', False):
                vectors.append("Unauthorized API access")
        
        # Infrastructure attack vectors
        if system_state.get('cloud_deployment', False):
            vectors.append("Cloud misconfiguration exploitation")
            vectors.append("Container escape attacks")
        
        # Performance-based attack vectors
        response_time = current_metrics.get('response_time', 0)
        if response_time > 1000:
            vectors.append("Application-layer DoS attacks")
        
        # Social engineering vectors
        if system_state.get('user_facing', True):
            vectors.append("Phishing attacks")
            vectors.append("Social engineering attacks")
        
        return vectors
    
    def _identify_monitoring_gaps(self, system_state: Dict[str, Any]) -> List[str]:
        """Identify security monitoring gaps"""
        gaps = []
        
        # Security logging gaps
        if not system_state.get('security_logging', False):
            gaps.append("Security event logging not implemented")
        
        if not system_state.get('log_aggregation', False):
            gaps.append("Centralized log aggregation not configured")
        
        if not system_state.get('log_integrity', False):
            gaps.append("Log integrity protection not implemented")
        
        # Intrusion detection gaps
        if not system_state.get('intrusion_detection', False):
            gaps.append("Intrusion detection system not deployed")
        
        if not system_state.get('anomaly_detection', False):
            gaps.append("Anomaly detection not configured")
        
        # Security monitoring gaps
        if not system_state.get('security_monitoring', False):
            gaps.append("Real-time security monitoring not implemented")
        
        if not system_state.get('security_alerting', False):
            gaps.append("Security alerting not configured")
        
        if not system_state.get('incident_response_automation', False):
            gaps.append("Automated incident response not implemented")
        
        # Vulnerability monitoring gaps
        if not system_state.get('vulnerability_scanning', False):
            gaps.append("Regular vulnerability scanning not scheduled")
        
        if not system_state.get('dependency_scanning', False):
            gaps.append("Dependency vulnerability scanning not configured")
        
        # Compliance monitoring gaps
        if not system_state.get('compliance_monitoring', False):
            gaps.append("Compliance monitoring not implemented")
        
        return gaps
    
    async def _generate_security_strategy(
        self,
        analysis: SecurityAnalysis,
        objectives: List[str]
    ) -> Dict[str, Any]:
        """Generate security improvement strategy"""
        
        # Determine strategy based on security score and vulnerabilities
        critical_vulns = sum(1 for v in analysis.vulnerabilities if v.severity == ThreatLevel.CRITICAL)
        high_vulns = sum(1 for v in analysis.vulnerabilities if v.severity == ThreatLevel.HIGH)
        
        if critical_vulns > 0 or analysis.security_score < 0.3:
            strategy_name = "critical_security_remediation"
            priority = "critical"
        elif high_vulns > 2 or analysis.security_score < 0.6:
            strategy_name = "comprehensive_security_hardening"
            priority = "high"
        elif analysis.security_score < 0.8:
            strategy_name = "targeted_security_improvement"
            priority = "medium"
        else:
            strategy_name = "security_optimization_and_monitoring"
            priority = "low"
        
        # Define strategy details
        strategy = {
            'name': strategy_name,
            'priority': priority,
            'security_focus_areas': self._determine_security_focus_areas(analysis),
            'security_techniques': self._select_security_techniques(analysis),
            'remediation_phases': self._plan_remediation_phases(analysis),
            'expected_outcome': {
                'security_score_improvement': self._estimate_security_improvement(analysis),
                'vulnerability_reduction': self._estimate_vulnerability_reduction(analysis),
                'compliance_improvement': self._estimate_compliance_improvement(analysis),
                'performance_impact': self._estimate_security_performance_impact(analysis),
                'implementation_time': self._estimate_security_implementation_time(analysis),
                'success_probability': self._estimate_security_success_probability(analysis),
                'risk_reduction': self._estimate_risk_reduction(analysis)
            },
            'security_testing_strategy': {
                'vulnerability_scanning': True,
                'penetration_testing': analysis.security_score < 0.7,
                'security_load_testing': True,
                'compliance_testing': len(analysis.compliance_gaps) > 0
            }
        }
        
        return strategy
    
    def _determine_security_focus_areas(self, analysis: SecurityAnalysis) -> List[str]:
        """Determine security focus areas"""
        focus_areas = []
        
        # Based on vulnerability categories
        vuln_categories = set(v.category for v in analysis.vulnerabilities)
        if "Injection" in vuln_categories:
            focus_areas.append("input_validation_and_sanitization")
        if "Broken Authentication" in vuln_categories:
            focus_areas.append("authentication_and_session_management")
        if "Sensitive Data Exposure" in vuln_categories:
            focus_areas.append("data_protection_and_encryption")
        if "Broken Access Control" in vuln_categories:
            focus_areas.append("authorization_and_access_control")
        
        # Based on threat landscape
        high_threats = [k for k, v in analysis.threat_landscape.items() if v == ThreatLevel.HIGH]
        if "external_attacks" in high_threats:
            focus_areas.append("perimeter_security")
        if "data_breaches" in high_threats:
            focus_areas.append("data_loss_prevention")
        if "ddos_attacks" in high_threats:
            focus_areas.append("availability_and_resilience")
        
        # Based on compliance gaps
        if analysis.compliance_gaps:
            focus_areas.append("compliance_and_governance")
        
        # Based on monitoring gaps
        if analysis.security_monitoring_gaps:
            focus_areas.append("security_monitoring_and_incident_response")
        
        return focus_areas or ["general_security_hardening"]
    
    def _select_security_techniques(self, analysis: SecurityAnalysis) -> List[str]:
        """Select appropriate security techniques"""
        techniques = []
        
        # Based on vulnerabilities
        for vuln in analysis.vulnerabilities:
            if vuln.category == "Injection":
                techniques.extend(["input_validation", "parameterized_queries", "output_encoding"])
            elif vuln.category == "Broken Authentication":
                techniques.extend(["multi_factor_authentication", "secure_session_management"])
            elif vuln.category == "Sensitive Data Exposure":
                techniques.extend(["encryption_at_rest", "encryption_in_transit", "key_management"])
            elif vuln.category == "Security Misconfiguration":
                techniques.extend(["security_hardening", "secure_defaults", "configuration_management"])
        
        # Based on compliance gaps
        if analysis.compliance_gaps:
            techniques.extend(["compliance_automation", "audit_logging", "data_governance"])
        
        # Based on monitoring gaps
        if analysis.security_monitoring_gaps:
            techniques.extend(["security_monitoring", "intrusion_detection", "incident_response"])
        
        return list(set(techniques))[:10]  # Limit and remove duplicates
    
    def _plan_remediation_phases(self, analysis: SecurityAnalysis) -> List[str]:
        """Plan security remediation phases"""
        phases = []
        
        # Phase 1: Critical vulnerabilities
        critical_vulns = [v for v in analysis.vulnerabilities if v.severity == ThreatLevel.CRITICAL]
        if critical_vulns:
            phases.append("Phase 1: Critical vulnerability remediation")
        
        # Phase 2: High-priority vulnerabilities
        high_vulns = [v for v in analysis.vulnerabilities if v.severity == ThreatLevel.HIGH]
        if high_vulns:
            phases.append("Phase 2: High-priority vulnerability fixes")
        
        # Phase 3: Security controls implementation
        phases.append("Phase 3: Security controls and hardening")
        
        # Phase 4: Monitoring and detection
        if analysis.security_monitoring_gaps:
            phases.append("Phase 4: Security monitoring implementation")
        
        # Phase 5: Compliance and governance
        if analysis.compliance_gaps:
            phases.append("Phase 5: Compliance gap remediation")
        
        # Phase 6: Testing and validation
        phases.append("Phase 6: Security testing and validation")
        
        return phases
    
    def _estimate_security_improvement(self, analysis: SecurityAnalysis) -> float:
        """Estimate expected security score improvement"""
        current_score = analysis.security_score
        vuln_count = len(analysis.vulnerabilities)
        gap_count = len(analysis.compliance_gaps) + len(analysis.security_monitoring_gaps)
        
        # Base improvement potential
        improvement_potential = (1 - current_score) * 0.7
        
        # Additional improvement from fixing vulnerabilities
        vuln_improvement = min(0.4, vuln_count * 0.05)
        
        # Additional improvement from closing gaps
        gap_improvement = min(0.2, gap_count * 0.02)
        
        total_improvement = improvement_potential + vuln_improvement + gap_improvement
        
        return min(0.6, total_improvement)  # Cap at 60% improvement
    
    def _estimate_vulnerability_reduction(self, analysis: SecurityAnalysis) -> float:
        """Estimate percentage of vulnerabilities that can be fixed"""
        if not analysis.vulnerabilities:
            return 0.0
        
        # Estimate based on remediation effort
        easily_fixed = sum(1 for v in analysis.vulnerabilities if v.remediation_effort == "low")
        moderately_fixed = sum(1 for v in analysis.vulnerabilities if v.remediation_effort == "medium")
        hard_to_fix = sum(1 for v in analysis.vulnerabilities if v.remediation_effort == "high")
        
        total_vulns = len(analysis.vulnerabilities)
        
        # Assume 90% of easy, 70% of medium, 40% of hard vulnerabilities can be fixed
        fixable_vulns = (easily_fixed * 0.9) + (moderately_fixed * 0.7) + (hard_to_fix * 0.4)
        
        return fixable_vulns / total_vulns
    
    def _estimate_compliance_improvement(self, analysis: SecurityAnalysis) -> float:
        """Estimate compliance gap closure percentage"""
        if not analysis.compliance_gaps:
            return 1.0
        
        # Assume 80% of compliance gaps can be addressed
        return 0.8
    
    def _estimate_security_performance_impact(self, analysis: SecurityAnalysis) -> Dict[str, float]:
        """Estimate performance impact of security improvements"""
        return {
            'cpu_overhead_increase': 5.0,  # 5% CPU overhead
            'memory_overhead_increase': 3.0,  # 3% memory overhead
            'latency_increase': 8.0,  # 8% latency increase
            'throughput_reduction': 2.0,  # 2% throughput reduction
            'storage_increase': 10.0  # 10% storage increase for logs
        }
    
    def _estimate_security_implementation_time(self, analysis: SecurityAnalysis) -> int:
        """Estimate implementation time in hours"""
        base_time = 40  # 40 hours base
        
        # Add time based on vulnerabilities
        vuln_time = 0
        for vuln in analysis.vulnerabilities:
            if vuln.remediation_effort == "low":
                vuln_time += 4
            elif vuln.remediation_effort == "medium":
                vuln_time += 12
            else:
                vuln_time += 24
        
        # Add time based on gaps
        gap_time = (len(analysis.compliance_gaps) + len(analysis.security_monitoring_gaps)) * 6
        
        total_time = base_time + vuln_time + gap_time
        
        return min(300, total_time)  # Cap at 300 hours
    
    def _estimate_security_success_probability(self, analysis: SecurityAnalysis) -> float:
        """Estimate probability of successful security implementation"""
        base_probability = 0.85
        
        # Reduce probability based on complexity
        critical_vulns = sum(1 for v in analysis.vulnerabilities if v.severity == ThreatLevel.CRITICAL)
        if critical_vulns > 2:
            base_probability *= 0.7
        elif critical_vulns > 0:
            base_probability *= 0.8
        
        # Adjust based on remediation effort
        hard_vulns = sum(1 for v in analysis.vulnerabilities if v.remediation_effort == "high")
        if hard_vulns > 3:
            base_probability *= 0.8
        
        return max(0.6, base_probability)  # Minimum 60% probability
    
    def _estimate_risk_reduction(self, analysis: SecurityAnalysis) -> float:
        """Estimate overall risk reduction percentage"""
        vuln_risk_reduction = self._estimate_vulnerability_reduction(analysis) * 0.4
        compliance_risk_reduction = self._estimate_compliance_improvement(analysis) * 0.3
        monitoring_risk_reduction = 0.2 if analysis.security_monitoring_gaps else 0.0
        
        total_risk_reduction = vuln_risk_reduction + compliance_risk_reduction + monitoring_risk_reduction
        
        return min(0.8, total_risk_reduction)  # Cap at 80% risk reduction
    
    def _assess_overall_security_risk(self, analysis: SecurityAnalysis) -> str:
        """Assess overall security risk level"""
        risk_score = 0
        
        # Risk based on vulnerabilities
        for vuln in analysis.vulnerabilities:
            if vuln.severity == ThreatLevel.CRITICAL:
                risk_score += 4
            elif vuln.severity == ThreatLevel.HIGH:
                risk_score += 3
            elif vuln.severity == ThreatLevel.MEDIUM:
                risk_score += 2
            else:
                risk_score += 1
        
        # Risk based on security score
        if analysis.security_score < 0.3:
            risk_score += 5
        elif analysis.security_score < 0.6:
            risk_score += 3
        elif analysis.security_score < 0.8:
            risk_score += 1
        
        # Risk based on compliance gaps
        risk_score += min(3, len(analysis.compliance_gaps) // 2)
        
        # Risk based on monitoring gaps
        risk_score += min(2, len(analysis.security_monitoring_gaps) // 3)
        
        if risk_score >= 10:
            return "critical"
        elif risk_score >= 7:
            return "high"
        elif risk_score >= 4:
            return "medium"
        else:
            return "low"
    
    def _calculate_confidence(
        self,
        current_metrics: Dict[str, Any],
        system_state: Dict[str, Any]
    ) -> float:
        """Calculate confidence in the recommendation"""
        base_confidence = 0.8
        
        # Increase confidence with more security data
        security_metrics = ['error_rate', 'response_time', 'cpu_utilization']
        metrics_coverage = sum(1 for metric in security_metrics if metric in current_metrics) / len(security_metrics)
        base_confidence += (metrics_coverage - 0.5) * 0.1
        
        # Increase confidence with more system state information
        security_state_keys = ['multi_factor_auth', 'encryption_at_rest', 'security_logging']
        state_coverage = sum(1 for key in security_state_keys if key in system_state) / len(security_state_keys)
        base_confidence += (state_coverage - 0.5) * 0.1
        
        return min(0.95, max(0.6, base_confidence))
    
    def _generate_reasoning(
        self,
        analysis: SecurityAnalysis,
        strategy: Dict[str, Any]
    ) -> str:
        """Generate reasoning for the recommendation"""
        reasoning_parts = []
        
        # Analysis summary
        reasoning_parts.append(f"Security analysis identified {len(analysis.vulnerabilities)} vulnerabilities")
        reasoning_parts.append(f"Current security score: {analysis.security_score:.2f}")
        
        critical_vulns = sum(1 for v in analysis.vulnerabilities if v.severity == ThreatLevel.CRITICAL)
        if critical_vulns > 0:
            reasoning_parts.append(f"Found {critical_vulns} critical vulnerabilities requiring immediate attention")
        
        # Strategy justification
        reasoning_parts.append(f"Recommended {strategy['name']} strategy")
        reasoning_parts.append(f"Expected {strategy['expected_outcome']['security_score_improvement']:.1%} security improvement")
        
        # Key focus areas
        if strategy['security_focus_areas']:
            focus_str = ", ".join(strategy['security_focus_areas'])
            reasoning_parts.append(f"Primary focus areas: {focus_str}")
        
        return ". ".join(reasoning_parts)
    
    def _generate_implementation_steps(
        self,
        strategy: Dict[str, Any],
        analysis: SecurityAnalysis
    ) -> List[str]:
        """Generate detailed implementation steps"""
        steps = []
        
        # Always start with assessment
        steps.append("Conduct comprehensive security baseline assessment")
        steps.append("Document current security controls and vulnerabilities")
        
        # Add strategy-specific steps
        for technique in strategy.get('security_techniques', []):
            if technique == "input_validation":
                steps.append("Implement comprehensive input validation and sanitization")
            elif technique == "multi_factor_authentication":
                steps.append("Deploy multi-factor authentication for all user accounts")
            elif technique == "encryption_at_rest":
                steps.append("Implement encryption for sensitive data at rest")
            elif technique == "security_monitoring":
                steps.append("Deploy security monitoring and incident detection systems")
            elif technique == "compliance_automation":
                steps.append("Implement automated compliance monitoring and reporting")
        
        # Add phase-specific steps
        for phase in strategy.get('remediation_phases', []):
            steps.append(f"Execute {phase}")
        
        # Add validation steps
        steps.append("Conduct security testing and penetration testing")
        steps.append("Validate security improvements and update documentation")
        steps.append("Implement continuous security monitoring and improvement")
        
        return steps
    
    def _identify_monitoring_metrics(self, analysis: SecurityAnalysis) -> List[str]:
        """Identify key security metrics to monitor"""
        metrics = [
            'security_events_per_minute',
            'failed_authentication_attempts',
            'intrusion_detection_alerts',
            'vulnerability_scan_results',
            'security_patch_status',
            'encryption_performance_impact',
            'security_log_volume'
        ]
        
        # Add specific metrics based on vulnerabilities
        vuln_categories = set(v.category for v in analysis.vulnerabilities)
        if "Injection" in vuln_categories:
            metrics.append('sql_injection_attempts')
        if "Broken Authentication" in vuln_categories:
            metrics.append('authentication_anomalies')
        if "DoS" in vuln_categories:
            metrics.append('request_rate_anomalies')
        
        return list(set(metrics))  # Remove duplicates
    
    def _vulnerability_to_dict(self, vuln: SecurityVulnerability) -> Dict[str, Any]:
        """Convert vulnerability to dictionary"""
        return {
            'vulnerability_id': vuln.vulnerability_id,
            'severity': vuln.severity.value,
            'category': vuln.category,
            'description': vuln.description,
            'affected_components': vuln.affected_components,
            'exploitation_likelihood': vuln.exploitation_likelihood,
            'impact_score': vuln.impact_score,
            'remediation_effort': vuln.remediation_effort,
            'performance_impact': vuln.performance_impact
        }
    
    def _store_analysis(self, analysis: SecurityAnalysis, recommendation: Dict[str, Any]):
        """Store analysis results for learning"""
        record = {
            'timestamp': time.time(),
            'security_score': analysis.security_score,
            'vulnerability_count': len(analysis.vulnerabilities),
            'critical_vulnerabilities': sum(1 for v in analysis.vulnerabilities if v.severity == ThreatLevel.CRITICAL),
            'compliance_gap_count': len(analysis.compliance_gaps),
            'strategy': recommendation['strategy'],
            'confidence': recommendation['confidence']
        }
        
        self.security_history.append(record)
        
        # Keep only last 50 records
        if len(self.security_history) > 50:
            self.security_history = self.security_history[-50:]
    
    def _generate_fallback_recommendation(self) -> Dict[str, Any]:
        """Generate fallback recommendation when analysis fails"""
        return {
            'strategy': 'basic_security_assessment',
            'confidence': 0.6,
            'reasoning': 'Security analysis failed, recommending basic security assessment',
            'expected_outcome': {
                'security_score_improvement': 0.2,
                'vulnerability_reduction': 0.5,
                'compliance_improvement': 0.3,
                'performance_impact': {'cpu_overhead_increase': 3.0},
                'implementation_time': 24,
                'success_probability': 0.8,
                'risk_reduction': 0.3
            },
            'risk_assessment': 'medium',
            'implementation_steps': [
                'Conduct basic security vulnerability scan',
                'Review and harden basic security configurations',
                'Implement essential security controls',
                'Set up basic security monitoring'
            ],
            'metrics_to_monitor': ['security_events_per_minute', 'failed_authentication_attempts']
        }
    
    async def configure(self, config: Dict[str, Any]):
        """Configure expert parameters"""
        if 'security_frameworks' in config:
            self.security_frameworks.update(config['security_frameworks'])
        
        if 'security_controls' in config:
            self.security_controls.update(config['security_controls'])
        
        if 'vulnerability_patterns' in config:
            self.vulnerability_patterns.update(config['vulnerability_patterns'])
        
        self.logger.info(f"Security Expert configured with {len(config)} parameters")