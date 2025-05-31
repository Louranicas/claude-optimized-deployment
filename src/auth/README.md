# Production-Grade RBAC Authentication System

This module implements a comprehensive Role-Based Access Control (RBAC) system following OWASP security guidelines. It provides enterprise-grade authentication, authorization, user management, and security auditing capabilities.

## 🚀 Features

### Core Authentication
- ✅ **JWT Token Management** - Secure token generation with refresh tokens
- ✅ **Password Security** - bcrypt hashing with complexity enforcement
- ✅ **Multi-Factor Authentication** - TOTP-based MFA support
- ✅ **Account Security** - Automatic lockout after failed attempts
- ✅ **Session Management** - Secure session handling with revocation

### Authorization & RBAC
- ✅ **Hierarchical Roles** - Role inheritance with permission aggregation
- ✅ **Fine-Grained Permissions** - Resource-based permission checking
- ✅ **Permission Caching** - High-performance permission evaluation
- ✅ **Custom Roles** - Dynamic role creation and management
- ✅ **Context-Aware Permissions** - IP, time, and environment-based conditions

### User Management
- ✅ **Complete User Lifecycle** - Create, update, delete, manage users
- ✅ **Role Assignment** - Assign/revoke roles with expiration support
- ✅ **API Key Management** - Service account authentication
- ✅ **Password Management** - Change, reset, and complexity validation
- ✅ **User Search & Pagination** - Efficient user discovery

### Security & Auditing
- ✅ **Comprehensive Audit Logging** - All security events tracked
- ✅ **OWASP Compliance** - Following security best practices
- ✅ **Rate Limiting** - Protection against brute force attacks
- ✅ **IP Filtering** - Whitelist/blacklist support
- ✅ **Security Headers** - XSS, CSRF, and other protections

### Integration
- ✅ **MCP Server Integration** - Authenticated tool execution
- ✅ **Circle of Experts Integration** - AI model access control
- ✅ **FastAPI Middleware** - Ready-to-use authentication middleware
- ✅ **Database Agnostic** - Pluggable storage backends

## 📋 Quick Start

### 1. Initialize the Authentication System

```python
from auth import create_auth_system

# Create complete auth system
auth_system = create_auth_system(
    user_store=your_user_store,
    api_key_store=your_api_key_store,
    secret_key="your-jwt-secret-key",
    mcp_manager=your_mcp_manager,
    expert_manager=your_expert_manager
)

# Access components
user_manager = auth_system["user_manager"]
token_manager = auth_system["token_manager"]
permission_checker = auth_system["permission_checker"]
audit_logger = auth_system["audit_logger"]
```

### 2. Create Users and Assign Roles

```python
from auth import UserCreationRequest

# Create a new user
user_request = UserCreationRequest(
    username="alice",
    email="alice@company.com",
    password="SecurePassword123!",
    roles=["operator"]
)

user = await user_manager.create_user(user_request, created_by="admin")

# Assign additional role
await user_manager.assign_role(
    user_id=user.id,
    role_name="admin",
    assigned_by="system",
    expires_at=datetime.now() + timedelta(days=30)
)
```

### 3. Authenticate Users

```python
# Authenticate user
user, tokens = await user_manager.authenticate(
    username="alice",
    password="SecurePassword123!",
    ip_address="192.168.1.100"
)

print(f"Access Token: {tokens['access_token']}")
print(f"Refresh Token: {tokens['refresh_token']}")
```

### 4. Check Permissions

```python
# Check if user can execute Docker commands
can_execute = permission_checker.check_permission(
    user_id=user.id,
    user_roles=user.roles,
    resource="mcp.docker",
    action="execute"
)

if can_execute:
    # User is authorized
    await mcp_manager.call_tool("docker", "docker_build", {"dockerfile": "."})
```

### 5. Use with FastAPI

```python
from fastapi import FastAPI, Depends
from auth import auth_router, get_current_user_dependency, require_permission

app = FastAPI()

# Include auth routes
app.include_router(auth_router)

# Protected endpoint
@app.get("/protected")
async def protected_route(current_user = Depends(get_current_user_dependency)):
    return {"message": f"Hello {current_user.username}!"}

# Permission-based endpoint
@app.post("/deploy")
async def deploy(current_user = Depends(require_permission("deployment", "execute"))):
    return {"status": "deployed"}
```

## 🔐 Security Features

### Password Security
- **bcrypt Hashing** - Industry-standard password hashing
- **Complexity Requirements** - Uppercase, lowercase, digits, special characters
- **History Tracking** - Prevent password reuse
- **Secure Reset** - Time-limited reset tokens

### Token Security
- **JWT with HMAC-SHA256** - Secure token signing
- **Short-lived Access Tokens** - 15-minute default expiry
- **Refresh Token Rotation** - Enhanced security
- **Token Revocation** - Immediate invalidation support

### Account Security
- **Automatic Lockout** - After 5 failed login attempts
- **Temporary Locks** - 30-minute lockout duration
- **Session Management** - Multiple session support with limits
- **MFA Support** - TOTP-based two-factor authentication

### Audit & Monitoring
- **Comprehensive Logging** - All security events tracked
- **Event Signatures** - Tamper detection with HMAC
- **Real-time Alerts** - Critical event notifications
- **Compliance Reports** - Export for security audits

## 🏗️ Architecture

### Core Components

```
src/auth/
├── models.py              # User, APIKey, UserRole models
├── tokens.py              # JWT token management
├── rbac.py                # Role-based access control
├── permissions.py         # Fine-grained permissions
├── middleware.py          # FastAPI authentication middleware
├── user_manager.py        # Complete user lifecycle management
├── audit.py               # Security audit logging
├── mcp_integration.py     # MCP server authentication
├── experts_integration.py # Circle of Experts authentication
├── api.py                 # FastAPI authentication endpoints
└── __init__.py           # Module initialization
```

### Default Roles

| Role | Description | Permissions |
|------|-------------|-------------|
| **viewer** | Read-only access | Read permissions on all resources |
| **operator** | Operations user | Execute MCP tools, deployments, read access |
| **admin** | Full administrator | All permissions on all resources |
| **mcp_service** | MCP service account | Full MCP tool access, infrastructure operations |
| **ci_cd_service** | CI/CD automation | Deployment, Docker, Kubernetes, Azure DevOps |
| **monitoring_service** | Monitoring system | Prometheus, Slack notifications, log access |

### Permission Matrix

| Resource | Viewer | Operator | Admin |
|----------|--------|----------|-------|
| `mcp.docker` | read | execute | admin |
| `mcp.kubernetes` | read | execute | admin |
| `circle_of_experts` | read | execute | admin |
| `deployment` | - | execute | admin |
| `rbac` | - | - | admin |
| `audit` | - | - | admin |

## 🔧 Configuration

### Environment Variables

```bash
# JWT Configuration
JWT_SECRET_KEY=your-secure-secret-key
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15
JWT_REFRESH_TOKEN_EXPIRE_DAYS=30

# Security Policies
MAX_FAILED_LOGIN_ATTEMPTS=5
ACCOUNT_LOCKOUT_DURATION_MINUTES=30
PASSWORD_MIN_LENGTH=8
PASSWORD_COMPLEXITY_REQUIRED=true

# MFA Configuration
MFA_ISSUER_NAME="Claude Optimized Deployment"
MFA_ENABLED_BY_DEFAULT=false

# Rate Limiting
RATE_LIMIT_REQUESTS_PER_MINUTE=60
RATE_LIMIT_BURST_SIZE=10

# Audit Logging
AUDIT_LOG_RETENTION_DAYS=90
AUDIT_EXPORT_FORMATS=json,csv
```

### Storage Backend

The system uses pluggable storage backends. Implement these interfaces:

```python
class UserStore:
    async def create_user(self, user: User) -> None: ...
    async def get_user(self, user_id: str) -> User: ...
    async def get_user_by_username(self, username: str) -> User: ...
    async def update_user(self, user: User) -> None: ...
    # ... other methods

class APIKeyStore:
    async def create_api_key(self, api_key: APIKey) -> None: ...
    async def get_api_key(self, key_id: str) -> APIKey: ...
    async def update_api_key(self, api_key: APIKey) -> None: ...
    # ... other methods
```

## 📊 Usage Examples

### Advanced Permission Checking

```python
# Context-aware permissions
context = {
    "client_ip": "192.168.1.100",
    "environment": "production",
    "time_window": "business_hours"
}

can_deploy = permission_checker.check_permission(
    user_id="user_123",
    user_roles=["operator"],
    resource="deployment:prod-cluster",
    action="execute",
    context=context
)
```

### Custom Role Creation

```python
# Create specialized role
custom_role = rbac_manager.create_custom_role(
    name="security_analyst",
    description="Security monitoring and analysis",
    permissions=[
        "audit:read",
        "security:read", 
        "mcp.security_scanner:execute",
        "monitoring:read"
    ],
    parent_roles=["viewer"]
)
```

### API Key Authentication

```python
# Create service account API key
api_key, raw_key = await user_manager.create_api_key(
    user_id=service_user.id,
    name="ci_cd_pipeline",
    permissions=[
        "deployment:execute",
        "mcp.docker:execute",
        "mcp.kubernetes:execute"
    ],
    expires_at=datetime.now() + timedelta(days=365)
)

# Use API key in requests
headers = {"X-API-Key": raw_key}
```

### Audit Log Analysis

```python
# Get security events
security_events = await audit_logger.get_security_events(
    severity=AuditSeverity.WARNING,
    start_time=datetime.now() - timedelta(hours=24)
)

# Export audit logs for compliance
audit_export = await audit_logger.export_audit_log(
    start_time=datetime.now() - timedelta(days=30),
    end_time=datetime.now(),
    format="json"
)
```

## 🧪 Testing

Run the comprehensive test suite:

```bash
# Install dependencies
pip install -r requirements.txt

# Run RBAC system tests
python test_rbac_system.py
```

Test output will show:
- ✅ JWT token management validation
- ✅ RBAC system functionality  
- ✅ Permission checking accuracy
- ✅ User lifecycle management
- ✅ Security audit logging
- ✅ Integration capabilities

## 🔒 Security Considerations

### Production Deployment

1. **Use Strong Secret Keys**
   ```python
   # Generate secure secret key
   import secrets
   secret_key = secrets.token_urlsafe(32)
   ```

2. **Enable HTTPS Only**
   ```python
   # Configure secure cookies
   app.add_middleware(
       HTTPSRedirectMiddleware
   )
   ```

3. **Configure Rate Limiting**
   ```python
   # Use Redis for production rate limiting
   rate_limiter = RedisRateLimiter(
       redis_url="redis://localhost:6379"
   )
   ```

4. **Set Up Monitoring**
   ```python
   # Configure audit alerts
   audit_logger.add_alert_callback(
       lambda event, message: send_security_alert(event, message)
   )
   ```

### Security Best Practices

- **Regular Key Rotation** - Rotate JWT secret keys every 90 days
- **Monitor Failed Logins** - Alert on suspicious patterns
- **Audit Permission Changes** - Track all role/permission modifications
- **Use MFA for Admins** - Require 2FA for administrative accounts
- **Regular Security Reviews** - Audit user permissions quarterly

## 📈 Performance

### Optimization Features

- **Permission Caching** - 5-minute TTL for permission checks
- **Background Audit Processing** - Async event logging
- **Connection Pooling** - Efficient database usage
- **Rate Limiting** - Prevent abuse and DoS attacks

### Scalability

- **Horizontal Scaling** - Stateless design supports clustering
- **Database Agnostic** - Works with PostgreSQL, MySQL, MongoDB
- **Microservice Ready** - Independent authentication service
- **Cloud Native** - Container and Kubernetes support

## 🤝 Contributing

1. Follow OWASP security guidelines
2. Add comprehensive tests for new features
3. Update documentation with code changes
4. Ensure backward compatibility
5. Add audit logging for security events

## 📄 License

This authentication system follows the same license as the main project.

---

**⚠️ Security Notice**: This system handles sensitive authentication data. Always follow security best practices in production deployments.