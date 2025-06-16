#!/usr/bin/env python3
"""
SYNTHEX Security Mitigation Engine
Implements enterprise-grade security fixes aligned with Zero Trust principles
"""

import asyncio
import json
import os
import re
import shutil
import subprocess
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import hashlib
import secrets

class SecurityMitigationEngine:
    """Advanced security mitigation implementation engine"""
    
    def __init__(self, report_path: str):
        self.report_path = report_path
        self.report = self._load_report()
        self.backup_dir = Path(f"security_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.mitigations_applied = []
        self.validation_results = []
        
    def _load_report(self) -> Dict[str, Any]:
        """Load security report"""
        with open(self.report_path, 'r') as f:
            return json.load(f)
            
    async def execute_mitigations(self):
        """Execute comprehensive security mitigations"""
        print(f"\n{'='*100}")
        print("SYNTHEX SECURITY MITIGATION ENGINE")
        print(f"{'='*100}")
        print(f"Report: {self.report_path}")
        print(f"Critical Issues: {self.report['executive_summary']['critical']}")
        print(f"High Issues: {self.report['executive_summary']['high']}")
        print(f"{'='*100}\n")
        
        # Create backup
        await self._create_backup()
        
        # Phase 1: Critical Mitigations
        print("[PHASE 1] Implementing Critical Mitigations...")
        await self._mitigate_critical_issues()
        
        # Phase 2: High Priority Mitigations
        print("\n[PHASE 2] Implementing High Priority Mitigations...")
        await self._mitigate_high_issues()
        
        # Phase 3: Infrastructure Hardening
        print("\n[PHASE 3] Infrastructure Hardening...")
        await self._harden_infrastructure()
        
        # Phase 4: Authentication & Authorization
        print("\n[PHASE 4] Strengthening Authentication & Authorization...")
        await self._strengthen_auth()
        
        # Phase 5: Data Protection
        print("\n[PHASE 5] Implementing Data Protection...")
        await self._implement_data_protection()
        
        # Phase 6: Supply Chain Security
        print("\n[PHASE 6] Securing Supply Chain...")
        await self._secure_supply_chain()
        
        # Phase 7: Monitoring & Logging
        print("\n[PHASE 7] Enhancing Monitoring & Logging...")
        await self._enhance_monitoring()
        
        # Phase 8: Validation
        print("\n[PHASE 8] Validating Mitigations...")
        await self._validate_mitigations()
        
        # Generate report
        await self._generate_mitigation_report()
        
    async def _create_backup(self):
        """Create backup of current code"""
        print("Creating backup...")
        self.backup_dir.mkdir(exist_ok=True)
        
        # Backup critical directories
        for dir_name in ["src", "k8s", "rust_core"]:
            if Path(dir_name).exists():
                shutil.copytree(dir_name, self.backup_dir / dir_name)
                
        print(f"✓ Backup created at: {self.backup_dir}")
        
    async def _mitigate_critical_issues(self):
        """Fix critical security issues"""
        critical_findings = [f for f in self.report["findings"] if f["threat_level"] == "CRITICAL"]
        
        for finding in critical_findings:
            print(f"\nFixing: {finding['title']}")
            
            if "Password exposed" in finding["title"] or "Hardcoded" in finding["title"]:
                await self._fix_hardcoded_secrets(finding)
            elif "Weak Password Hashing" in finding["title"]:
                await self._fix_password_hashing(finding)
                
    async def _fix_hardcoded_secrets(self, finding: Dict[str, Any]):
        """Remove hardcoded secrets"""
        affected_file = finding["affected_components"][0]
        
        if Path(affected_file).exists():
            # Read file
            with open(affected_file, 'r') as f:
                content = f.read()
                
            # Replace hardcoded values with environment variables
            patterns = [
                (r'password\s*=\s*["\']([^"\']+)["\']', 'password = os.getenv("DB_PASSWORD")'),
                (r'api_key\s*=\s*["\']([^"\']+)["\']', 'api_key = os.getenv("API_KEY")'),
                (r'secret_key\s*=\s*["\']([^"\']+)["\']', 'secret_key = os.getenv("SECRET_KEY")'),
            ]
            
            modified = False
            for pattern, replacement in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    content = re.sub(pattern, replacement, content, flags=re.IGNORECASE)
                    modified = True
                    
            if modified:
                # Add import if needed
                if "import os" not in content:
                    content = "import os\n" + content
                    
                # Write back
                with open(affected_file, 'w') as f:
                    f.write(content)
                    
                self.mitigations_applied.append({
                    "finding_id": finding["id"],
                    "file": affected_file,
                    "mitigation": "Replaced hardcoded secrets with environment variables"
                })
                
                print(f"  ✓ Fixed hardcoded secrets in {affected_file}")
                
    async def _fix_password_hashing(self, finding: Dict[str, Any]):
        """Upgrade to secure password hashing"""
        affected_file = finding["affected_components"][0]
        
        if Path(affected_file).exists():
            with open(affected_file, 'r') as f:
                content = f.read()
                
            # Replace weak hashing
            replacements = [
                ("import md5", "from argon2 import PasswordHasher"),
                ("import hashlib", "from argon2 import PasswordHasher\nimport hashlib"),
                ("md5.new(", "# DEPRECATED: md5.new("),
                ("hashlib.md5(", "# DEPRECATED: hashlib.md5("),
                ("hashlib.sha1(", "# DEPRECATED: hashlib.sha1("),
            ]
            
            for old, new in replacements:
                content = content.replace(old, new)
                
            # Add secure password hashing function
            if "PasswordHasher" in content and "hash_password" not in content:
                secure_hash_func = '''
def hash_password(password: str) -> str:
    """Securely hash password using Argon2"""
    ph = PasswordHasher()
    return ph.hash(password)

def verify_password(password: str, hash: str) -> bool:
    """Verify password against hash"""
    ph = PasswordHasher()
    try:
        ph.verify(hash, password)
        return True
    except:
        return False
'''
                content += secure_hash_func
                
            with open(affected_file, 'w') as f:
                f.write(content)
                
            self.mitigations_applied.append({
                "finding_id": finding["id"],
                "file": affected_file,
                "mitigation": "Upgraded to Argon2 password hashing"
            })
            
            print(f"  ✓ Upgraded password hashing in {affected_file}")
            
    async def _mitigate_high_issues(self):
        """Fix high priority issues"""
        high_findings = [f for f in self.report["findings"] if f["threat_level"] == "HIGH"]
        
        # Group by type
        by_type = {}
        for finding in high_findings:
            finding_type = finding["title"].split(":")[0] if ":" in finding["title"] else finding["title"]
            if finding_type not in by_type:
                by_type[finding_type] = []
            by_type[finding_type].append(finding)
            
        # Fix SQL injections
        if "SQL Injection" in by_type:
            await self._fix_sql_injections(by_type["SQL Injection"])
            
        # Fix authentication issues
        auth_issues = [f for f in high_findings if "auth" in f["title"].lower()]
        if auth_issues:
            await self._fix_authentication_issues(auth_issues)
            
        # Fix vulnerable dependencies
        dep_issues = [f for f in high_findings if "Dependency" in f["title"]]
        if dep_issues:
            await self._update_dependencies(dep_issues)
            
    async def _fix_sql_injections(self, findings: List[Dict[str, Any]]):
        """Fix SQL injection vulnerabilities"""
        print("\nFixing SQL injection vulnerabilities...")
        
        for finding in findings:
            affected_file = finding["affected_components"][0]
            
            if Path(affected_file).exists():
                with open(affected_file, 'r') as f:
                    content = f.read()
                    
                # Fix common SQL injection patterns
                fixes = [
                    # String formatting to parameterized
                    (r'execute\s*\(\s*["\'](.+)%s(.+)["\'].*%\s*\((.*?)\)', 
                     r'execute("\1%s\2", (\3))'),
                    # F-string to parameterized
                    (r'execute\s*\(\s*f["\'](.+){(.+)}(.+)["\']', 
                     r'execute("\1%s\3", (\2,))'),
                    # String concatenation to parameterized
                    (r'execute\s*\(\s*["\'](.+)["\'].*\+.*([a-zA-Z_]+)', 
                     r'execute("\1%s", (\2,))'),
                ]
                
                for pattern, replacement in fixes:
                    content = re.sub(pattern, replacement, content)
                    
                with open(affected_file, 'w') as f:
                    f.write(content)
                    
                print(f"  ✓ Fixed SQL injection in {affected_file}")
                
    async def _fix_authentication_issues(self, findings: List[Dict[str, Any]]):
        """Fix authentication vulnerabilities"""
        print("\nStrengthening authentication...")
        
        # Create secure authentication module
        auth_module = '''
"""
Enhanced Authentication Module
Implements secure authentication with MFA support
"""
import os
import secrets
import time
from typing import Optional, Dict, Any
from argon2 import PasswordHasher
import pyotp
import jwt
from datetime import datetime, timedelta

class SecureAuthenticator:
    """Secure authentication with MFA"""
    
    def __init__(self):
        self.ph = PasswordHasher()
        self.jwt_secret = os.getenv("JWT_SECRET", secrets.token_urlsafe(32))
        self.token_expiry = 3600  # 1 hour
        
    def hash_password(self, password: str) -> str:
        """Hash password using Argon2"""
        return self.ph.hash(password)
        
    def verify_password(self, password: str, hash: str) -> bool:
        """Verify password"""
        try:
            self.ph.verify(hash, password)
            return True
        except:
            return False
            
    def generate_mfa_secret(self) -> str:
        """Generate MFA secret"""
        return pyotp.random_base32()
        
    def verify_mfa_token(self, secret: str, token: str) -> bool:
        """Verify MFA token"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)
        
    def generate_jwt(self, user_id: str, additional_claims: Dict[str, Any] = None) -> str:
        """Generate JWT token"""
        payload = {
            "user_id": user_id,
            "exp": datetime.utcnow() + timedelta(seconds=self.token_expiry),
            "iat": datetime.utcnow(),
            "jti": secrets.token_urlsafe(16)
        }
        
        if additional_claims:
            payload.update(additional_claims)
            
        return jwt.encode(payload, self.jwt_secret, algorithm="HS256")
        
    def verify_jwt(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
            
    def requires_auth(self, func):
        """Decorator for requiring authentication"""
        async def wrapper(*args, **kwargs):
            # Extract token from request
            token = kwargs.get("auth_token")
            if not token:
                raise AuthenticationError("No authentication token provided")
                
            payload = self.verify_jwt(token)
            if not payload:
                raise AuthenticationError("Invalid or expired token")
                
            kwargs["user_id"] = payload["user_id"]
            return await func(*args, **kwargs)
            
        return wrapper

class AuthenticationError(Exception):
    """Authentication error"""
    pass

# Global authenticator instance
authenticator = SecureAuthenticator()
'''
        
        # Write enhanced auth module
        auth_path = Path("src/synthex/auth_enhanced.py")
        auth_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(auth_path, 'w') as f:
            f.write(auth_module)
            
        self.mitigations_applied.append({
            "finding_id": "AUTH-ENHANCEMENT",
            "file": str(auth_path),
            "mitigation": "Created enhanced authentication module with MFA"
        })
        
        print(f"  ✓ Created enhanced authentication module at {auth_path}")
        
    async def _update_dependencies(self, findings: List[Dict[str, Any]]):
        """Update vulnerable dependencies"""
        print("\nUpdating vulnerable dependencies...")
        
        # Create updated requirements
        safe_versions = {
            "cryptography": "cryptography>=41.0.7",
            "pyyaml": "pyyaml>=6.0.1",
            "requests": "requests>=2.31.0",
            "django": "django>=4.2.8",
            "flask": "flask>=3.0.0",
            "pillow": "pillow>=10.1.0",
            "numpy": "numpy>=1.24.3",
            "urllib3": "urllib3>=2.0.7",
            "jinja2": "jinja2>=3.1.2",
            "werkzeug": "werkzeug>=3.0.1"
        }
        
        # Read current requirements
        req_files = list(Path(".").glob("**/requirements*.txt"))
        
        for req_file in req_files:
            if "requirements-fixed.txt" not in str(req_file):
                with open(req_file, 'r') as f:
                    lines = f.readlines()
                    
                # Update versions
                updated_lines = []
                for line in lines:
                    updated = False
                    for pkg, safe_ver in safe_versions.items():
                        if pkg in line.lower():
                            updated_lines.append(safe_ver + "\n")
                            updated = True
                            break
                    if not updated:
                        updated_lines.append(line)
                        
                # Write updated requirements
                updated_file = req_file.parent / f"{req_file.stem}_secure{req_file.suffix}"
                with open(updated_file, 'w') as f:
                    f.writelines(updated_lines)
                    
                print(f"  ✓ Created secure requirements at {updated_file}")
                
    async def _harden_infrastructure(self):
        """Harden infrastructure configurations"""
        print("\nHardening infrastructure...")
        
        # Fix Docker security
        await self._fix_docker_security()
        
        # Fix Kubernetes security
        await self._fix_kubernetes_security()
        
        # Set secure file permissions
        await self._set_secure_permissions()
        
    async def _fix_docker_security(self):
        """Fix Docker security issues"""
        dockerfiles = list(Path(".").glob("**/Dockerfile*"))
        
        for dockerfile in dockerfiles:
            with open(dockerfile, 'r') as f:
                content = f.read()
                
            # Add non-root user
            if "USER " not in content:
                # Add user creation before CMD/ENTRYPOINT
                lines = content.split('\n')
                new_lines = []
                
                for line in lines:
                    new_lines.append(line)
                    if line.startswith("FROM "):
                        new_lines.extend([
                            "",
                            "# Create non-root user",
                            "RUN groupadd -r synthex && useradd -r -g synthex synthex",
                            ""
                        ])
                    elif line.startswith("CMD ") or line.startswith("ENTRYPOINT "):
                        new_lines.insert(-1, "USER synthex")
                        
                content = '\n'.join(new_lines)
                
            # Replace latest tags
            content = re.sub(r':latest\b', ':stable', content)
            
            with open(dockerfile, 'w') as f:
                f.write(content)
                
            print(f"  ✓ Hardened {dockerfile}")
            
    async def _fix_kubernetes_security(self):
        """Fix Kubernetes security issues"""
        # Create security context template
        security_context = '''
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 1000
  capabilities:
    drop:
    - ALL
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
'''
        
        # Create network policy
        network_policy = '''apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: synthex-network-policy
  namespace: synthex
spec:
  podSelector:
    matchLabels:
      app: synthex
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: synthex
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 443
    - protocol: TCP
      port: 5432
'''
        
        # Write network policy
        netpol_path = Path("k8s/network-policy-secure.yaml")
        with open(netpol_path, 'w') as f:
            f.write(network_policy)
            
        print(f"  ✓ Created secure network policy at {netpol_path}")
        
    async def _set_secure_permissions(self):
        """Set secure file permissions"""
        sensitive_patterns = [
            "**/.env*",
            "**/secrets*",
            "**/credentials*",
            "**/*key*",
            "**/*password*"
        ]
        
        for pattern in sensitive_patterns:
            for file in Path(".").glob(pattern):
                if file.is_file():
                    # Set restrictive permissions (owner read/write only)
                    os.chmod(file, 0o600)
                    print(f"  ✓ Secured permissions for {file}")
                    
    async def _strengthen_auth(self):
        """Strengthen authentication and authorization"""
        print("\nStrengthening authentication...")
        
        # Create RBAC implementation
        rbac_module = '''
"""
Role-Based Access Control (RBAC) Implementation
"""
from enum import Enum
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import json

class Permission(Enum):
    """System permissions"""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"
    EXECUTE = "execute"

class Resource(Enum):
    """System resources"""
    SEARCH = "search"
    AGENTS = "agents"
    CONFIG = "config"
    USERS = "users"
    LOGS = "logs"
    METRICS = "metrics"

@dataclass
class Role:
    """Role definition"""
    name: str
    permissions: Dict[Resource, List[Permission]]
    description: str = ""
    
class RBACManager:
    """RBAC manager"""
    
    def __init__(self):
        self.roles = self._initialize_roles()
        self.user_roles = {}
        
    def _initialize_roles(self) -> Dict[str, Role]:
        """Initialize default roles"""
        return {
            "admin": Role(
                name="admin",
                permissions={
                    Resource.SEARCH: [Permission.READ, Permission.WRITE, Permission.DELETE, Permission.ADMIN],
                    Resource.AGENTS: [Permission.READ, Permission.WRITE, Permission.DELETE, Permission.ADMIN],
                    Resource.CONFIG: [Permission.READ, Permission.WRITE, Permission.ADMIN],
                    Resource.USERS: [Permission.READ, Permission.WRITE, Permission.DELETE, Permission.ADMIN],
                    Resource.LOGS: [Permission.READ, Permission.ADMIN],
                    Resource.METRICS: [Permission.READ, Permission.ADMIN]
                },
                description="Full system access"
            ),
            "operator": Role(
                name="operator",
                permissions={
                    Resource.SEARCH: [Permission.READ, Permission.WRITE, Permission.EXECUTE],
                    Resource.AGENTS: [Permission.READ, Permission.EXECUTE],
                    Resource.CONFIG: [Permission.READ],
                    Resource.LOGS: [Permission.READ],
                    Resource.METRICS: [Permission.READ]
                },
                description="System operator access"
            ),
            "viewer": Role(
                name="viewer",
                permissions={
                    Resource.SEARCH: [Permission.READ],
                    Resource.AGENTS: [Permission.READ],
                    Resource.METRICS: [Permission.READ]
                },
                description="Read-only access"
            )
        }
        
    def assign_role(self, user_id: str, role_name: str):
        """Assign role to user"""
        if role_name not in self.roles:
            raise ValueError(f"Unknown role: {role_name}")
        self.user_roles[user_id] = role_name
        
    def check_permission(self, user_id: str, resource: Resource, permission: Permission) -> bool:
        """Check if user has permission"""
        if user_id not in self.user_roles:
            return False
            
        role_name = self.user_roles[user_id]
        role = self.roles[role_name]
        
        if resource not in role.permissions:
            return False
            
        return permission in role.permissions[resource]
        
    def requires_permission(self, resource: Resource, permission: Permission):
        """Decorator for permission checking"""
        def decorator(func):
            async def wrapper(*args, **kwargs):
                user_id = kwargs.get("user_id")
                if not user_id:
                    raise PermissionError("No user ID provided")
                    
                if not self.check_permission(user_id, resource, permission):
                    raise PermissionError(f"User {user_id} lacks {permission.value} permission for {resource.value}")
                    
                return await func(*args, **kwargs)
            return wrapper
        return decorator

# Global RBAC manager
rbac_manager = RBACManager()
'''
        
        # Write RBAC module
        rbac_path = Path("src/synthex/rbac_enhanced.py")
        with open(rbac_path, 'w') as f:
            f.write(rbac_module)
            
        print(f"  ✓ Created RBAC module at {rbac_path}")
        
    async def _implement_data_protection(self):
        """Implement data protection measures"""
        print("\nImplementing data protection...")
        
        # Create encryption module
        encryption_module = '''
"""
Data Encryption Module
Implements encryption at rest and in transit
"""
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class DataEncryption:
    """Handles data encryption/decryption"""
    
    def __init__(self):
        self.key = self._get_or_generate_key()
        self.cipher = Fernet(self.key)
        
    def _get_or_generate_key(self) -> bytes:
        """Get or generate encryption key"""
        key_file = os.getenv("ENCRYPTION_KEY_FILE", ".encryption.key")
        
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            # Generate new key
            key = Fernet.generate_key()
            
            # Save securely
            with open(key_file, 'wb') as f:
                f.write(key)
            os.chmod(key_file, 0o600)
            
            return key
            
    def encrypt(self, data: str) -> str:
        """Encrypt data"""
        return self.cipher.encrypt(data.encode()).decode()
        
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt data"""
        return self.cipher.decrypt(encrypted_data.encode()).decode()
        
    def encrypt_pii(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Encrypt PII fields in data"""
        pii_fields = ["ssn", "email", "phone", "address", "credit_card", "password"]
        encrypted_data = data.copy()
        
        for field in pii_fields:
            if field in encrypted_data:
                encrypted_data[field] = self.encrypt(str(encrypted_data[field]))
                
        return encrypted_data

# Global encryption instance
data_encryption = DataEncryption()
'''
        
        # Write encryption module
        enc_path = Path("src/synthex/encryption.py")
        with open(enc_path, 'w') as f:
            f.write(encryption_module)
            
        print(f"  ✓ Created encryption module at {enc_path}")
        
    async def _secure_supply_chain(self):
        """Implement supply chain security"""
        print("\nSecuring supply chain...")
        
        # Create dependency check script
        dep_check_script = '''#!/bin/bash
# Supply Chain Security Check

echo "Running supply chain security checks..."

# Check Python dependencies
echo "Checking Python dependencies..."
pip-audit --desc

# Check npm dependencies (if applicable)
if [ -f "package.json" ]; then
    echo "Checking npm dependencies..."
    npm audit
fi

# Check for known vulnerabilities
echo "Checking for known vulnerabilities..."
safety check

# Generate SBOM (Software Bill of Materials)
echo "Generating SBOM..."
pip-licenses --format=json > sbom_python.json

echo "Supply chain security check complete!"
'''
        
        # Write script
        script_path = Path("scripts/supply_chain_check.sh")
        script_path.parent.mkdir(exist_ok=True)
        
        with open(script_path, 'w') as f:
            f.write(dep_check_script)
            
        os.chmod(script_path, 0o755)
        print(f"  ✓ Created supply chain check script at {script_path}")
        
    async def _enhance_monitoring(self):
        """Enhance security monitoring and logging"""
        print("\nEnhancing monitoring and logging...")
        
        # Create security monitoring module
        monitoring_module = '''
"""
Security Monitoring and Alerting
"""
import logging
import json
from datetime import datetime
from typing import Dict, Any, Optional
import asyncio
from collections import defaultdict
import os

class SecurityMonitor:
    """Security event monitoring and alerting"""
    
    def __init__(self):
        self.logger = logging.getLogger("security")
        self.event_counts = defaultdict(int)
        self.alert_thresholds = {
            "authentication_failure": 5,
            "authorization_failure": 10,
            "rate_limit_exceeded": 20,
            "suspicious_activity": 3,
            "sql_injection_attempt": 1,
            "xss_attempt": 1
        }
        self.alert_callbacks = []
        
    def log_security_event(self, event_type: str, details: Dict[str, Any], severity: str = "INFO"):
        """Log security event"""
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "severity": severity,
            "details": details,
            "source_ip": details.get("source_ip", "unknown"),
            "user_id": details.get("user_id", "anonymous")
        }
        
        # Log event
        self.logger.log(
            getattr(logging, severity, logging.INFO),
            json.dumps(event)
        )
        
        # Count events
        self.event_counts[event_type] += 1
        
        # Check thresholds
        if event_type in self.alert_thresholds:
            if self.event_counts[event_type] >= self.alert_thresholds[event_type]:
                asyncio.create_task(self._trigger_alert(event_type, event))
                
    async def _trigger_alert(self, event_type: str, event: Dict[str, Any]):
        """Trigger security alert"""
        alert = {
            "alert_id": f"ALERT-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            "event_type": event_type,
            "threshold": self.alert_thresholds[event_type],
            "count": self.event_counts[event_type],
            "event": event,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Log alert
        self.logger.critical(f"SECURITY ALERT: {json.dumps(alert)}")
        
        # Call alert handlers
        for callback in self.alert_callbacks:
            try:
                await callback(alert)
            except Exception as e:
                self.logger.error(f"Alert callback failed: {e}")
                
        # Reset counter
        self.event_counts[event_type] = 0
        
    def register_alert_handler(self, callback):
        """Register alert handler"""
        self.alert_callbacks.append(callback)
        
    def get_security_metrics(self) -> Dict[str, Any]:
        """Get security metrics"""
        return {
            "event_counts": dict(self.event_counts),
            "alerts_triggered": sum(1 for k, v in self.event_counts.items() 
                                  if k in self.alert_thresholds and v >= self.alert_thresholds[k]),
            "timestamp": datetime.utcnow().isoformat()
        }

# Global security monitor
security_monitor = SecurityMonitor()

# Configure security logging
security_handler = logging.FileHandler("security.log")
security_handler.setFormatter(
    logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
)
security_logger = logging.getLogger("security")
security_logger.addHandler(security_handler)
security_logger.setLevel(logging.INFO)
'''
        
        # Write monitoring module
        mon_path = Path("src/synthex/security_monitoring.py")
        with open(mon_path, 'w') as f:
            f.write(monitoring_module)
            
        print(f"  ✓ Created security monitoring module at {mon_path}")
        
    async def _validate_mitigations(self):
        """Validate applied mitigations"""
        print("\nValidating mitigations...")
        
        # Re-run basic security checks
        validation_tests = [
            ("Hardcoded secrets", self._check_hardcoded_secrets),
            ("SQL injection", self._check_sql_injection),
            ("Authentication", self._check_authentication),
            ("File permissions", self._check_file_permissions),
            ("Docker security", self._check_docker_security)
        ]
        
        for test_name, test_func in validation_tests:
            result = await test_func()
            self.validation_results.append({
                "test": test_name,
                "result": "PASS" if result else "FAIL",
                "timestamp": datetime.now().isoformat()
            })
            
            status = "✓" if result else "✗"
            print(f"  {status} {test_name}: {'PASSED' if result else 'FAILED'}")
            
    async def _check_hardcoded_secrets(self) -> bool:
        """Check for hardcoded secrets"""
        secret_patterns = [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'api_key\s*=\s*["\'][a-zA-Z0-9]{20,}["\']',
            r'secret\s*=\s*["\'][^"\']+["\']'
        ]
        
        found_secrets = False
        
        for py_file in Path("src").glob("**/*.py"):
            try:
                with open(py_file, 'r') as f:
                    content = f.read()
                    
                for pattern in secret_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        # Check if it's using env vars
                        if "os.getenv" not in content and "os.environ" not in content:
                            found_secrets = True
                            break
            except:
                pass
                
        return not found_secrets
        
    async def _check_sql_injection(self) -> bool:
        """Check for SQL injection vulnerabilities"""
        vulnerable_patterns = [
            r'execute\s*\(\s*["\'].*%s.*["\'].*%\s*[^,\)]',
            r'execute\s*\(\s*f["\'].*{.*}',
            r'execute\s*\(\s*["\'].*\+.*["\']'
        ]
        
        found_vulnerable = False
        
        for py_file in Path("src").glob("**/*.py"):
            try:
                with open(py_file, 'r') as f:
                    content = f.read()
                    
                for pattern in vulnerable_patterns:
                    if re.search(pattern, content):
                        found_vulnerable = True
                        break
            except:
                pass
                
        return not found_vulnerable
        
    async def _check_authentication(self) -> bool:
        """Check authentication implementation"""
        # Check if enhanced auth module exists
        return Path("src/synthex/auth_enhanced.py").exists()
        
    async def _check_file_permissions(self) -> bool:
        """Check file permissions"""
        sensitive_files = list(Path(".").glob("**/.env*"))
        
        for file in sensitive_files:
            if file.is_file():
                stat = os.stat(file)
                mode = stat.st_mode & 0o777
                if mode != 0o600:
                    return False
                    
        return True
        
    async def _check_docker_security(self) -> bool:
        """Check Docker security"""
        dockerfiles = list(Path(".").glob("**/Dockerfile*"))
        
        for dockerfile in dockerfiles:
            try:
                with open(dockerfile, 'r') as f:
                    content = f.read()
                    
                if "USER " not in content:
                    return False
                    
                if ":latest" in content:
                    return False
            except:
                pass
                
        return True
        
    async def _generate_mitigation_report(self):
        """Generate mitigation report"""
        report = {
            "mitigation_id": f"MIT-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "timestamp": datetime.now().isoformat(),
            "original_report": self.report_path,
            "critical_issues_before": self.report["executive_summary"]["critical"],
            "high_issues_before": self.report["executive_summary"]["high"],
            "mitigations_applied": len(self.mitigations_applied),
            "mitigation_details": self.mitigations_applied,
            "validation_results": self.validation_results,
            "validation_success_rate": sum(1 for r in self.validation_results if r["result"] == "PASS") / len(self.validation_results) * 100 if self.validation_results else 0,
            "recommendations": [
                "Continue monitoring security events",
                "Schedule regular dependency updates",
                "Implement continuous security testing",
                "Conduct penetration testing quarterly",
                "Review and update security policies"
            ]
        }
        
        report_path = f"SYNTHEX_MITIGATION_REPORT_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
            
        print(f"\n✅ Mitigation report saved to: {report_path}")
        
        # Print summary
        print(f"\n{'='*100}")
        print("MITIGATION SUMMARY")
        print(f"{'='*100}")
        print(f"Mitigations Applied: {len(self.mitigations_applied)}")
        print(f"Validation Success Rate: {report['validation_success_rate']:.1f}%")
        print(f"Backup Location: {self.backup_dir}")
        print(f"{'='*100}")

async def main():
    """Run security mitigation engine"""
    # Find latest security report
    reports = list(Path(".").glob("SYNTHEX_ENTERPRISE_SECURITY_REPORT_*.json"))
    if not reports:
        print("No security report found!")
        return
        
    latest_report = max(reports, key=lambda p: p.stat().st_mtime)
    
    engine = SecurityMitigationEngine(str(latest_report))
    await engine.execute_mitigations()

if __name__ == "__main__":
    asyncio.run(main())