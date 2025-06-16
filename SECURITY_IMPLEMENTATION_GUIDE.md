# Security Implementation Guide

## Quick Start Guide

This guide provides step-by-step instructions for implementing the comprehensive security architecture designed by SYNTHEX Agent 4.

## Prerequisites

### System Requirements
- Python 3.9+
- Redis (for caching and rate limiting)
- PostgreSQL (for persistent storage)
- Docker (optional, for enhanced sandboxing)

### Dependencies Installation

```bash
# Install core dependencies
pip install -r requirements.txt

# Additional security dependencies
pip install cryptography pyotp python-magic defusedxml pillow
pip install asyncpg aioredis
pip install psutil resource

# Optional: Docker SDK for enhanced sandboxing
pip install docker
```

## Implementation Steps

### Step 1: Basic Security Configuration

Create a security configuration file:

```python
# security_config.py
import os
from pathlib import Path

SECURITY_CONFIG = {
    # Directories
    'sandbox_dir': Path('./sandbox'),
    'downloads_dir': Path('./downloads'),
    'uploads_dir': Path('./uploads'),
    'audit_log_dir': Path('./audit_logs'),
    
    # File limits
    'max_file_size': 100 * 1024 * 1024,  # 100MB
    'max_decompressed_size': 1024 * 1024 * 1024,  # 1GB
    'allowed_mime_types': [
        'text/plain', 'text/csv', 'application/json',
        'application/pdf', 'image/png', 'image/jpeg'
    ],
    
    # Resource limits
    'max_memory_mb': 512,
    'max_cpu_seconds': 30,
    'max_file_handles': 100,
    'max_threads': 10,
    
    # Communication security
    'encryption_enabled': True,
    'require_signature': True,
    
    # Authentication
    'jwt_secret': os.getenv('JWT_SECRET_KEY', 'your-secret-key'),
    'mfa_required_for_admin': True,
    'session_timeout_minutes': 30,
    
    # Rate limiting
    'rate_limits': {
        'auth_attempt': {'requests': 10, 'window': 60},
        'api_request': {'requests': 1000, 'window': 3600},
        'file_upload': {'requests': 50, 'window': 3600}
    }
}
```

### Step 2: Initialize Security Architecture

```python
# main.py
from src.security.comprehensive_security_architecture import SecurityArchitecture
from src.security.mcp_enhanced_authentication import MCPAuthenticationProvider
from security_config import SECURITY_CONFIG

# Initialize security architecture
security_arch = SecurityArchitecture(SECURITY_CONFIG)

# Initialize authentication provider
auth_provider = MCPAuthenticationProvider(
    secret_key=SECURITY_CONFIG['jwt_secret']
)

# Example: Process a secure request
async def handle_request(request_type, request_data, user_context):
    context = SecurityContext(
        user_id=user_context['user_id'],
        client_id=user_context['client_id'],
        ip_address=user_context['ip_address'],
        permissions=user_context['permissions']
    )
    
    result, validation = await security_arch.process_request(
        request_type, request_data, context
    )
    
    return result, validation
```

### Step 3: Implement File Upload Security

```python
# file_upload_example.py
from src.security.comprehensive_security_architecture import SecurityArchitecture
import tempfile

async def secure_file_upload(filename, file_content, user_context):
    # Initialize security architecture
    security_arch = SecurityArchitecture(SECURITY_CONFIG)
    
    # Create security context
    context = SecurityContext(
        user_id=user_context['user_id'],
        client_id=user_context['client_id'],
        ip_address=user_context['ip_address'],
        permissions=['file:write']
    )
    
    # Prepare request data
    request_data = {
        'filename': filename,
        'content': file_content
    }
    
    # Process through security layers
    result, validation = await security_arch.process_request(
        'file_upload', request_data, context
    )
    
    if validation.is_valid:
        print(f"File uploaded successfully: {result}")
        return result
    else:
        print(f"Upload failed: {validation.errors}")
        return None

# Usage example
async def main():
    with open('test_file.txt', 'rb') as f:
        content = f.read()
    
    user_context = {
        'user_id': 'user123',
        'client_id': 'client456',
        'ip_address': '192.168.1.100',
        'permissions': ['file:write', 'file:read']
    }
    
    result = await secure_file_upload('test_file.txt', content, user_context)
```

### Step 4: Implement MCP Authentication

```python
# mcp_auth_example.py
from src.security.mcp_enhanced_authentication import (
    MCPAuthenticationProvider, MCPAuthorizationManager
)
from src.auth.rbac import RBACManager

async def setup_mcp_security():
    # Initialize authentication provider
    auth_provider = MCPAuthenticationProvider(
        secret_key=SECURITY_CONFIG['jwt_secret']
    )
    
    # Initialize authorization manager
    rbac_manager = RBACManager()
    auth_manager = MCPAuthorizationManager(rbac_manager)
    
    return auth_provider, auth_manager

async def authenticate_mcp_client(api_key, client_ip, user_agent):
    auth_provider, _ = await setup_mcp_security()
    
    # Authenticate using API key
    result = await auth_provider.authenticate_api_key(
        api_key=api_key,
        client_ip=client_ip,
        user_agent=user_agent
    )
    
    if result.success:
        print(f"Authentication successful for user: {result.user_id}")
        return result.context
    else:
        print(f"Authentication failed: {result.error_message}")
        return None

# Usage example
async def main():
    # Example API key format: key_id.key_secret.signature
    api_key = "test_key.test_secret.signature_hash"
    
    context = await authenticate_mcp_client(
        api_key=api_key,
        client_ip="192.168.1.100",
        user_agent="MCP-Client/1.0"
    )
    
    if context:
        print(f"Client authenticated: {context.client_id}")
```

### Step 5: Set Up Input Validation

```python
# input_validation_example.py
from src.security.comprehensive_security_architecture import InputValidator

def setup_input_validation():
    validator = InputValidator()
    return validator

def validate_user_input(input_value, input_type):
    validator = setup_input_validation()
    
    result = validator.validate(input_value, input_type)
    
    if result.is_valid:
        print(f"Input valid: {result.sanitized_value}")
        return result.sanitized_value
    else:
        print(f"Input invalid: {result.errors}")
        if result.threat_indicators:
            print(f"Threat indicators: {result.threat_indicators}")
        return None

# Usage examples
if __name__ == "__main__":
    # Validate email
    email = validate_user_input("user@example.com", "email")
    
    # Validate file path
    file_path = validate_user_input("../../../etc/passwd", "file_path")
    
    # Validate SQL identifier
    sql_id = validate_user_input("'; DROP TABLE users; --", "sql_identifier")
    
    # Validate URL
    url = validate_user_input("http://169.254.169.254/metadata", "url")
```

### Step 6: Configure Monitoring and Alerting

```python
# monitoring_setup.py
from src.security.mcp_enhanced_authentication import MCPSecurityMonitor
import asyncio

async def alert_handler(alert):
    """Handle security alerts"""
    print(f"SECURITY ALERT: {alert['type']} - {alert['message']}")
    
    # In production, send to:
    # - SIEM system
    # - Email notifications
    # - Slack/Teams alerts
    # - Incident management system

async def setup_monitoring():
    # Initialize security monitor
    monitor = MCPSecurityMonitor(
        alert_handlers=[alert_handler]
    )
    
    return monitor

async def simulate_security_events():
    monitor = await setup_monitoring()
    
    # Simulate authentication event
    from src.security.mcp_enhanced_authentication import (
        MCPSecurityContext, AuthenticationMethod
    )
    
    context = MCPSecurityContext(
        client_id="test_client",
        user_id="test_user",
        session_id="test_session",
        ip_address="192.168.1.100",
        user_agent="Test-Agent/1.0",
        authentication_method=AuthenticationMethod.API_KEY,
        permissions=["read", "write"]
    )
    
    # Record successful authentication
    await monitor.record_auth_attempt(context, True, AuthenticationMethod.API_KEY)
    
    # Record security event
    await monitor.record_security_event(
        "suspicious_activity",
        context,
        {"description": "Multiple failed login attempts"}
    )

if __name__ == "__main__":
    asyncio.run(simulate_security_events())
```

## Integration Examples

### FastAPI Integration

```python
# fastapi_integration.py
from fastapi import FastAPI, Depends, HTTPException, Request
from src.security.comprehensive_security_architecture import SecurityArchitecture
from src.security.mcp_enhanced_authentication import MCPAuthenticationProvider

app = FastAPI()

# Initialize security components
security_arch = SecurityArchitecture(SECURITY_CONFIG)
auth_provider = MCPAuthenticationProvider(SECURITY_CONFIG['jwt_secret'])

async def get_current_user(request: Request):
    """Dependency to get current authenticated user"""
    # Extract API key or JWT from headers
    api_key = request.headers.get("X-API-Key")
    auth_header = request.headers.get("Authorization")
    
    if api_key:
        result = await auth_provider.authenticate_api_key(
            api_key=api_key,
            client_ip=request.client.host,
            user_agent=request.headers.get("User-Agent", "Unknown")
        )
    elif auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:]
        result = await auth_provider.authenticate_jwt(
            jwt_token=token,
            client_ip=request.client.host,
            user_agent=request.headers.get("User-Agent", "Unknown")
        )
    else:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    if not result.success:
        raise HTTPException(status_code=401, detail=result.error_message)
    
    return result.context

@app.post("/upload")
async def upload_file(
    request: Request,
    current_user=Depends(get_current_user)
):
    """Secure file upload endpoint"""
    # Get file data from request
    form = await request.form()
    file = form["file"]
    
    # Process through security architecture
    request_data = {
        'filename': file.filename,
        'content': await file.read()
    }
    
    result, validation = await security_arch.process_request(
        'file_upload', request_data, current_user
    )
    
    if validation.is_valid:
        return {"status": "success", "file_path": str(result)}
    else:
        raise HTTPException(
            status_code=400,
            detail={"errors": validation.errors, "threats": validation.threat_indicators}
        )

@app.get("/download/{file_id}")
async def download_file(
    file_id: str,
    current_user=Depends(get_current_user)
):
    """Secure file download endpoint"""
    request_data = {
        'file_path': f"downloads/{file_id}"
    }
    
    result, validation = await security_arch.process_request(
        'file_download', request_data, current_user
    )
    
    if validation.is_valid:
        return {"content": result}
    else:
        raise HTTPException(
            status_code=403,
            detail={"errors": validation.errors}
        )
```

### Database Setup

```sql
-- Create security-related tables
CREATE TABLE api_keys (
    key_id VARCHAR(64) PRIMARY KEY,
    client_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64),
    permissions TEXT[],
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP,
    last_used_ip INET
);

CREATE TABLE users (
    id VARCHAR(64) PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMP,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP
);

CREATE TABLE user_mfa_settings (
    user_id VARCHAR(64) PRIMARY KEY REFERENCES users(id),
    enabled BOOLEAN DEFAULT FALSE,
    totp_secret VARCHAR(32),
    backup_codes TEXT[],
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE clients (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    permissions TEXT[],
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_time_restrictions (
    user_id VARCHAR(64) PRIMARY KEY REFERENCES users(id),
    start_time TIME,
    end_time TIME,
    timezone VARCHAR(50) DEFAULT 'UTC'
);

CREATE TABLE user_ip_restrictions (
    user_id VARCHAR(64) PRIMARY KEY REFERENCES users(id),
    allowed_ips INET[],
    blocked_ips INET[]
);

-- Create indexes for performance
CREATE INDEX idx_api_keys_client_id ON api_keys(client_id);
CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
```

## Environment Setup

### Environment Variables

```bash
# .env file
# Database configuration
DATABASE_URL=postgresql://user:password@localhost/security_db
REDIS_URL=redis://localhost:6379

# Security keys (generate with: openssl rand -base64 32)
JWT_SECRET_KEY=your_jwt_secret_key_here
API_KEY_SECRET=your_api_key_secret_here
ENCRYPTION_KEY=your_encryption_key_here

# File storage
UPLOADS_DIR=/secure/uploads
DOWNLOADS_DIR=/secure/downloads
SANDBOX_DIR=/secure/sandbox

# Monitoring
LOG_LEVEL=INFO
AUDIT_LOG_DIR=/var/log/security

# TLS/SSL
SSL_CERT_PATH=/etc/ssl/certs/app.crt
SSL_KEY_PATH=/etc/ssl/private/app.key
CA_CERT_PATH=/etc/ssl/certs/ca.crt
```

### Docker Compose Setup

```yaml
# docker-compose.security.yml
version: '3.8'

services:
  app:
    build: .
    environment:
      - DATABASE_URL=postgresql://postgres:password@db:5432/security_db
      - REDIS_URL=redis://redis:6379
      - JWT_SECRET_KEY=${JWT_SECRET_KEY}
    volumes:
      - uploads:/secure/uploads
      - downloads:/secure/downloads
      - sandbox:/secure/sandbox
      - audit_logs:/var/log/security
    depends_on:
      - db
      - redis
    ports:
      - "8000:8000"

  db:
    image: postgres:14
    environment:
      - POSTGRES_DB=security_db
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  redis:
    image: redis:7
    command: redis-server --requirepass password
    volumes:
      - redis_data:/data
    ports:
      - "6379:6379"

volumes:
  postgres_data:
  redis_data:
  uploads:
  downloads:
  sandbox:
  audit_logs:
```

## Testing and Validation

### Security Testing Script

```python
# security_tests.py
import asyncio
import aiohttp
import pytest
from src.security.comprehensive_security_architecture import SecurityArchitecture

class SecurityTester:
    def __init__(self, base_url="http://localhost:8000"):
        self.base_url = base_url
        self.security_arch = SecurityArchitecture(SECURITY_CONFIG)
    
    async def test_authentication(self):
        """Test authentication mechanisms"""
        print("Testing authentication...")
        
        # Test API key authentication
        valid_key = "test_key.test_secret.valid_signature"
        invalid_key = "invalid.key.signature"
        
        # Test with valid key
        async with aiohttp.ClientSession() as session:
            headers = {"X-API-Key": valid_key}
            async with session.get(f"{self.base_url}/protected", headers=headers) as resp:
                assert resp.status == 200, "Valid API key should be accepted"
        
        # Test with invalid key
        async with aiohttp.ClientSession() as session:
            headers = {"X-API-Key": invalid_key}
            async with session.get(f"{self.base_url}/protected", headers=headers) as resp:
                assert resp.status == 401, "Invalid API key should be rejected"
    
    async def test_input_validation(self):
        """Test input validation"""
        print("Testing input validation...")
        
        from src.security.comprehensive_security_architecture import InputValidator
        validator = InputValidator()
        
        # Test SQL injection
        sql_injection = "'; DROP TABLE users; --"
        result = validator.validate(sql_injection, "sql_identifier")
        assert not result.is_valid, "SQL injection should be blocked"
        
        # Test path traversal
        path_traversal = "../../../etc/passwd"
        result = validator.validate(path_traversal, "file_path")
        assert not result.is_valid, "Path traversal should be blocked"
        
        # Test XSS
        xss_payload = "<script>alert('xss')</script>"
        result = validator.validate(xss_payload, "generic")
        assert "script" not in result.sanitized_value, "XSS should be sanitized"
    
    async def test_file_upload_security(self):
        """Test file upload security"""
        print("Testing file upload security...")
        
        # Test malicious file upload
        malicious_content = b"PK\x03\x04" + b"A" * 1000000  # Fake zip with large content
        
        context = SecurityContext(
            user_id="test_user",
            client_id="test_client",
            ip_address="127.0.0.1",
            permissions=["file:write"]
        )
        
        request_data = {
            'filename': 'malicious.zip',
            'content': malicious_content
        }
        
        result, validation = await self.security_arch.process_request(
            'file_upload', request_data, context
        )
        
        # Should detect potential zip bomb
        assert not validation.is_valid or len(validation.warnings) > 0
    
    async def test_rate_limiting(self):
        """Test rate limiting"""
        print("Testing rate limiting...")
        
        # Make multiple rapid requests
        async with aiohttp.ClientSession() as session:
            for i in range(15):  # Exceed limit of 10 per minute
                headers = {"X-API-Key": "test_key.test_secret.valid_signature"}
                async with session.get(f"{self.base_url}/protected", headers=headers) as resp:
                    if i >= 10:
                        assert resp.status == 429, "Rate limiting should kick in"
    
    async def run_all_tests(self):
        """Run all security tests"""
        await self.test_input_validation()
        await self.test_file_upload_security()
        print("All security tests completed!")

if __name__ == "__main__":
    tester = SecurityTester()
    asyncio.run(tester.run_all_tests())
```

## Production Deployment

### Security Checklist

- [ ] All default passwords changed
- [ ] SSL/TLS certificates installed and configured
- [ ] Environment variables properly set
- [ ] Database permissions restricted
- [ ] File permissions set correctly
- [ ] Firewall rules configured
- [ ] Monitoring and alerting set up
- [ ] Backup and recovery procedures tested
- [ ] Security scanning completed
- [ ] Penetration testing performed

### Monitoring Setup

```python
# monitoring_integration.py
import logging
from prometheus_client import Counter, Histogram, Gauge

# Security metrics
auth_attempts = Counter('auth_attempts_total', 'Total authentication attempts', ['method', 'result'])
blocked_requests = Counter('blocked_requests_total', 'Total blocked requests', ['reason'])
file_uploads = Counter('file_uploads_total', 'Total file uploads', ['result'])
security_events = Counter('security_events_total', 'Total security events', ['type', 'severity'])

response_time = Histogram('security_check_duration_seconds', 'Time spent on security checks')
active_sessions = Gauge('active_sessions', 'Number of active sessions')

def setup_security_monitoring():
    """Set up security monitoring integration"""
    # Configure structured logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('/var/log/security/app.log'),
            logging.StreamHandler()
        ]
    )
    
    # Add security event handlers
    security_logger = logging.getLogger('security')
    
    return security_logger
```

This implementation guide provides practical, step-by-step instructions for deploying the comprehensive security architecture. Follow these steps to ensure your MCP deployment is secure, monitored, and maintainable.

Remember to regularly update dependencies, review security configurations, and test incident response procedures to maintain a strong security posture.