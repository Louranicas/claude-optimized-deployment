# Authentication Migration Guide

This guide provides step-by-step instructions for migrating from the mock authentication implementation to the production-ready authentication system.

## Overview

The production authentication system includes:
- JWT token generation with secure key management
- Redis-backed token revocation
- Session management with concurrent limits
- Two-factor authentication (2FA) support
- Comprehensive audit logging
- Rate limiting and security controls

## Prerequisites

1. **Redis Server**
   - Redis 6.0+ installed and running
   - Accessible via `REDIS_URL` environment variable

2. **Environment Variables**
   ```bash
   # Required
   JWT_SECRET_KEY="your-secure-secret-key-at-least-32-chars"
   REDIS_URL="redis://localhost:6379/0"
   DATABASE_URL="postgresql://user:pass@localhost/dbname"
   
   # Optional (with defaults)
   ACCESS_TOKEN_EXPIRE_MINUTES=15
   REFRESH_TOKEN_EXPIRE_DAYS=30
   MAX_CONCURRENT_SESSIONS=5
   SESSION_TIMEOUT_MINUTES=30
   2FA_ISSUER_NAME="Your App Name"
   ```

3. **Database Schema**
   - Ensure user tables support new fields:
     - `mfa_enabled` (boolean)
     - `mfa_secret` (string, nullable)
     - `last_login_at` (timestamp)
     - `failed_login_attempts` (integer)
     - `locked_until` (timestamp, nullable)

## Migration Steps

### Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

Key new dependencies:
- `redis[hiredis]>=4.5.0` - Redis client with performance improvements
- `pyotp>=2.8.0` - TOTP/2FA support
- `qrcode[pil]>=7.4.0` - QR code generation for 2FA
- `user-agents>=2.2.0` - User agent parsing

### Step 2: Update Application Startup

```python
# main.py or app.py
from fastapi import FastAPI
from src.auth.startup import initialize_authentication

app = FastAPI()

@app.on_event("startup")
async def startup_event():
    # Initialize authentication services
    await initialize_authentication(app)
    
    # Your other startup code...
```

### Step 3: Update User Model

If using SQLAlchemy:

```python
from sqlalchemy import Column, String, Boolean, DateTime, Integer

class User(Base):
    __tablename__ = "users"
    
    # Existing fields...
    
    # Add new fields for production auth
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String, nullable=True)
    last_login_at = Column(DateTime, nullable=True)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    password_changed_at = Column(DateTime, default=func.now())
    password_history = Column(JSON, default=list)  # Store hashed passwords
    refresh_tokens = Column(JSON, default=list)  # Active refresh tokens
```

### Step 4: Database Migration

Create and run migration:

```sql
-- Add new columns for authentication
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP;
ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP;
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMP DEFAULT NOW();
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_history JSONB DEFAULT '[]'::jsonb;
ALTER TABLE users ADD COLUMN IF NOT EXISTS refresh_tokens JSONB DEFAULT '[]'::jsonb;

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_locked_until ON users(locked_until) WHERE locked_until IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_last_login ON users(last_login_at);
```

### Step 5: Update Authentication Endpoints

The production system maintains backward compatibility, but you should update your frontend to handle new responses:

```javascript
// Login with 2FA support
async function login(username, password, mfaCode = null) {
    const response = await fetch('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            username,
            password,
            mfa_code: mfaCode
        })
    });
    
    const data = await response.json();
    
    // Check if 2FA is required
    if (data.requires_2fa) {
        // Show 2FA input to user
        const code = await prompt2FACode();
        
        // Verify 2FA
        const verifyResponse = await fetch('/auth/2fa/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                challenge_id: data.challenge_id,
                code
            })
        });
        
        if (verifyResponse.ok) {
            // Retry login with 2FA code
            return login(username, password, code);
        }
    }
    
    // Store tokens
    localStorage.setItem('access_token', data.access_token);
    localStorage.setItem('refresh_token', data.refresh_token);
    
    return data;
}

// Logout with token revocation
async function logout() {
    const token = localStorage.getItem('access_token');
    
    await fetch('/auth/logout', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${token}`
        }
    });
    
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
}
```

### Step 6: Enable 2FA for Users

```javascript
// Setup TOTP 2FA
async function setup2FA() {
    const response = await fetch('/auth/2fa/setup/totp', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${token}`
        }
    });
    
    const data = await response.json();
    
    // Display QR code to user
    showQRCode(data.qr_code);
    
    // Get verification code from user
    const code = await getUserInput('Enter code from authenticator app');
    
    // Verify setup
    const verifyResponse = await fetch('/auth/2fa/verify/totp', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ code })
    });
    
    if (verifyResponse.ok) {
        const result = await verifyResponse.json();
        // Save backup codes
        saveBackupCodes(result.backup_codes);
    }
}
```

### Step 7: Implement Token Refresh

```javascript
// Auto-refresh tokens
async function refreshAccessToken() {
    const refreshToken = localStorage.getItem('refresh_token');
    
    const response = await fetch('/auth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            refresh_token: refreshToken
        })
    });
    
    if (response.ok) {
        const data = await response.json();
        localStorage.setItem('access_token', data.access_token);
        return data.access_token;
    }
    
    // Refresh failed, redirect to login
    window.location.href = '/login';
}

// Axios interceptor example
axios.interceptors.response.use(
    response => response,
    async error => {
        const originalRequest = error.config;
        
        if (error.response?.status === 401 && !originalRequest._retry) {
            originalRequest._retry = true;
            const newToken = await refreshAccessToken();
            originalRequest.headers.Authorization = `Bearer ${newToken}`;
            return axios(originalRequest);
        }
        
        return Promise.reject(error);
    }
);
```

### Step 8: Monitor Sessions

```javascript
// Get active sessions
async function getActiveSessions() {
    const response = await fetch('/auth/sessions', {
        headers: {
            'Authorization': `Bearer ${token}`
        }
    });
    
    return response.json();
}

// Revoke specific session
async function revokeSession(sessionId) {
    await fetch(`/auth/sessions/${sessionId}`, {
        method: 'DELETE',
        headers: {
            'Authorization': `Bearer ${token}`
        }
    });
}

// Revoke all other sessions
async function revokeAllOtherSessions() {
    await fetch('/auth/sessions', {
        method: 'DELETE',
        headers: {
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ keep_current: true })
    });
}
```

## Security Best Practices

### 1. Secure Token Storage

**Frontend:**
```javascript
// Use httpOnly cookies for tokens (recommended)
// Or use secure storage
class SecureTokenStorage {
    setTokens(access, refresh) {
        // Store in memory for access token
        this.accessToken = access;
        
        // Store refresh token more securely
        sessionStorage.setItem('refresh_token', refresh);
    }
    
    getAccessToken() {
        return this.accessToken;
    }
    
    clear() {
        this.accessToken = null;
        sessionStorage.clear();
    }
}
```

### 2. Implement CSRF Protection

```python
# Add CSRF middleware
from fastapi_csrf_protect import CsrfProtect
from pydantic import BaseModel

class CsrfSettings(BaseModel):
    secret_key: str = os.getenv("CSRF_SECRET_KEY", "your-csrf-secret")

@CsrfProtect.load_config
def get_csrf_config():
    return CsrfSettings()

# Use in endpoints
@app.post("/auth/login")
async def login(request: Request, csrf_protect: CsrfProtect = Depends()):
    await csrf_protect.validate_csrf(request)
    # ... rest of login logic
```

### 3. Rate Limiting

The production system includes built-in rate limiting, but you can add additional layers:

```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/auth/login")
@limiter.limit("5/minute")
async def login(request: Request):
    # ... login logic
```

### 4. Security Headers

```python
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from secure import SecureHeaders

# Add security headers
secure_headers = SecureHeaders()

@app.middleware("http")
async def set_secure_headers(request, call_next):
    response = await call_next(request)
    secure_headers.framework.fastapi(response)
    return response

# Add trusted host validation
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["example.com", "*.example.com"]
)
```

## Monitoring and Alerts

### 1. Track Authentication Metrics

```python
# Prometheus metrics
from prometheus_client import Counter, Histogram, Gauge

auth_attempts = Counter('auth_login_attempts_total', 'Total login attempts')
auth_failures = Counter('auth_login_failures_total', 'Total login failures')
auth_2fa_challenges = Counter('auth_2fa_challenges_total', 'Total 2FA challenges')
active_sessions = Gauge('auth_active_sessions', 'Number of active sessions')
token_refresh_duration = Histogram('auth_token_refresh_duration_seconds', 'Token refresh duration')
```

### 2. Set Up Alerts

```yaml
# Prometheus alert rules
groups:
  - name: authentication
    rules:
      - alert: HighFailedLoginRate
        expr: rate(auth_login_failures_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: High rate of failed login attempts
          
      - alert: SuspiciousLoginActivity
        expr: rate(auth_login_attempts_total{result="suspicious"}[1h]) > 5
        for: 10m
        labels:
          severity: critical
        annotations:
          summary: Suspicious login activity detected
```

### 3. Audit Log Monitoring

```python
# Query audit logs
@app.get("/auth/audit/suspicious")
async def get_suspicious_activity(
    current_user: User = Depends(require_permission("audit", "read"))
):
    events = await audit_logger.query_events(
        filters={
            "event_type__in": [
                "LOGIN_FAILED",
                "INVALID_TOKEN",
                "IP_CHANGE",
                "CONCURRENT_LIMIT_EXCEEDED"
            ],
            "severity__gte": "WARNING"
        },
        start_time=datetime.now() - timedelta(hours=24),
        limit=100
    )
    
    return {"events": [e.to_dict() for e in events]}
```

## Rollback Plan

If you need to rollback to the mock authentication:

1. **Keep both implementations:**
   ```python
   USE_PRODUCTION_AUTH = os.getenv("USE_PRODUCTION_AUTH", "false").lower() == "true"
   
   if USE_PRODUCTION_AUTH:
       from .auth.api import auth_router as prod_auth_router
       app.include_router(prod_auth_router)
   else:
       from .auth.mock_api import auth_router as mock_auth_router
       app.include_router(mock_auth_router)
   ```

2. **Gradual rollout:**
   ```python
   # Feature flag based rollout
   def should_use_production_auth(user_id: str) -> bool:
       # Roll out to specific users or percentage
       if user_id in BETA_USERS:
           return True
       
       # Or percentage based
       import hashlib
       hash_value = int(hashlib.md5(user_id.encode()).hexdigest(), 16)
       return (hash_value % 100) < ROLLOUT_PERCENTAGE
   ```

3. **Data migration rollback:**
   ```sql
   -- Remove new columns if needed (be careful with data loss)
   ALTER TABLE users DROP COLUMN IF EXISTS mfa_enabled;
   ALTER TABLE users DROP COLUMN IF EXISTS mfa_secret;
   -- ... other columns
   ```

## Testing the Migration

### 1. Unit Tests

Run the comprehensive test suite:

```bash
pytest tests/auth/test_auth_production.py -v
```

### 2. Integration Tests

```python
# Test full authentication flow
async def test_full_auth_flow():
    # Create user
    user = await create_test_user()
    
    # Login
    tokens = await login(user.username, "password")
    assert tokens["access_token"]
    
    # Use token
    profile = await get_profile(tokens["access_token"])
    assert profile["username"] == user.username
    
    # Refresh token
    new_token = await refresh_token(tokens["refresh_token"])
    assert new_token
    
    # Logout
    await logout(tokens["access_token"])
    
    # Token should be revoked
    with pytest.raises(Unauthorized):
        await get_profile(tokens["access_token"])
```

### 3. Load Testing

```bash
# Use locust for load testing
locust -f tests/load/auth_load_test.py --host=http://localhost:8000
```

## Troubleshooting

### Common Issues

1. **"JWT_SECRET_KEY not set" error**
   - Set the environment variable with a secure key
   - Generate one: `openssl rand -hex 32`

2. **Redis connection errors**
   - Ensure Redis is running: `redis-cli ping`
   - Check REDIS_URL format: `redis://[:password@]host[:port][/db]`

3. **Token verification failures**
   - Check clock synchronization between servers
   - Verify JWT_SECRET_KEY is consistent across instances

4. **2FA codes not working**
   - Ensure server time is synchronized (NTP)
   - Check TOTP window setting (default: 1)

5. **Session limits not enforced**
   - Verify Redis is accessible
   - Check session manager initialization

### Debug Mode

Enable debug logging:

```python
import logging

# Enable debug logs for auth
logging.getLogger("src.auth").setLevel(logging.DEBUG)

# Or set via environment
LOG_LEVEL=DEBUG
```

## Performance Optimization

### 1. Redis Connection Pooling

Already implemented in the production code, but ensure proper configuration:

```python
# Adjust pool settings based on load
config = ConnectionPoolConfig(
    redis_max_connections=100,  # Increase for high load
    redis_connection_timeout=5,
    redis_socket_timeout=5
)
```

### 2. Token Caching

The production system includes local caching for revocation checks. Monitor cache hit rates:

```python
stats = await token_revocation_service.get_cache_stats()
print(f"Cache hit rate: {stats['hit_rate']:.2%}")
```

### 3. Database Optimization

Add indexes for frequently queried fields:

```sql
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash);
```

## Conclusion

The production authentication system provides enterprise-grade security features while maintaining ease of use. Follow this guide carefully and test thoroughly before deploying to production.

For questions or issues, please refer to:
- [API Documentation](/api_docs/auth)
- [Security Best Practices](/docs/SECURITY.md)
- [Troubleshooting Guide](/docs/TROUBLESHOOTING.md)