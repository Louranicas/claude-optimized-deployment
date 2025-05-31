"""Simple RBAC system demonstration without external dependencies."""

import asyncio
from datetime import datetime, timezone
import json

# Import only the auth components
from src.auth.models import User, APIKey, UserStatus
from src.auth.rbac import Role, Permission, RBACManager, PermissionType
from src.auth.tokens import TokenManager, TokenData
from src.auth.permissions import PermissionChecker, ResourceType, ResourcePermission


def demonstrate_rbac_core():
    """Demonstrate core RBAC functionality."""
    print("=== RBAC System Core Demonstration ===\n")
    
    # 1. User Management
    print("1. USER MANAGEMENT")
    print("-" * 50)
    
    # Create users
    admin = User.create("admin", "admin@example.com", "AdminPass123!")
    admin.add_role("admin")
    print(f"✅ Created admin user: {admin.username}")
    
    operator = User.create("operator", "operator@example.com", "OperatorPass123!")
    operator.add_role("operator")
    print(f"✅ Created operator user: {operator.username}")
    
    viewer = User.create("viewer", "viewer@example.com", "ViewerPass123!")
    viewer.add_role("viewer")
    print(f"✅ Created viewer user: {viewer.username}")
    
    # Test password verification
    print(f"\n✅ Password verification test:")
    print(f"   - Correct password: {admin.verify_password('AdminPass123!')}")
    print(f"   - Wrong password: {admin.verify_password('WrongPassword')}")
    
    # Test failed login tracking
    print(f"\n✅ Failed login tracking:")
    for i in range(3):
        viewer.record_failed_login()
    print(f"   - Failed attempts: {viewer.failed_login_attempts}")
    print(f"   - Account locked: {viewer.is_locked()}")
    
    # 2. JWT Token Management
    print("\n\n2. JWT TOKEN MANAGEMENT")
    print("-" * 50)
    
    token_manager = TokenManager()
    
    # Create tokens
    tokens = token_manager.create_token_pair(
        admin.id, admin.username, admin.roles, list(admin.permissions)
    )
    print(f"✅ Created token pair for admin")
    print(f"   - Access token: {tokens['access_token'][:40]}...")
    print(f"   - Refresh token: {tokens['refresh_token'][:40]}...")
    print(f"   - Session ID: {tokens['session_id']}")
    
    # Verify token
    token_data = token_manager.verify_token(tokens['access_token'])
    if token_data:
        print(f"\n✅ Token verification successful:")
        print(f"   - User ID: {token_data.user_id}")
        print(f"   - Username: {token_data.username}")
        print(f"   - Roles: {token_data.roles}")
        print(f"   - Token type: {token_data.token_type}")
    
    # 3. API Key Management
    print("\n\n3. API KEY MANAGEMENT")
    print("-" * 50)
    
    # Create API keys
    ci_key, ci_raw = APIKey.create("CI/CD Pipeline", service_name="github_actions")
    ci_key.permissions = {"deployment.execute", "mcp.docker.execute"}
    print(f"✅ Created CI/CD API key:")
    print(f"   - Key ID: {ci_key.id}")
    print(f"   - Raw key: {ci_raw[:30]}...")
    print(f"   - Permissions: {ci_key.permissions}")
    
    monitoring_key, monitoring_raw = APIKey.create("Monitoring", user_id=viewer.id)
    monitoring_key.permissions = {"monitoring.read", "logs.read"}
    monitoring_key.rate_limit = 1000
    print(f"\n✅ Created Monitoring API key:")
    print(f"   - Key ID: {monitoring_key.id}")
    print(f"   - Rate limit: {monitoring_key.rate_limit} req/hour")
    print(f"   - Permissions: {monitoring_key.permissions}")
    
    # 4. Role Hierarchy
    print("\n\n4. ROLE HIERARCHY & PERMISSIONS")
    print("-" * 50)
    
    rbac_manager = RBACManager()
    
    # Show default roles
    print("✅ Default roles initialized:")
    for role_name in ["viewer", "operator", "admin"]:
        role = rbac_manager.get_role(role_name)
        if role:
            hierarchy = rbac_manager.get_role_hierarchy(role_name)
            print(f"\n   {role_name.upper()}:")
            print(f"   - Description: {role.description}")
            print(f"   - Direct permissions: {len(hierarchy['direct_permissions'])}")
            print(f"   - Inherited from: {hierarchy['parent_roles']}")
            print(f"   - Total permissions: {len(hierarchy['direct_permissions']) + len(hierarchy['inherited_permissions'])}")
    
    # Create custom role
    print("\n✅ Creating custom role:")
    ml_engineer = rbac_manager.create_custom_role(
        name="ml_engineer",
        description="Machine Learning Engineer",
        permissions=[
            "circle_of_experts:execute",
            "circle_of_experts.gemini:execute",
            "mcp.docker:execute",
            "monitoring:read"
        ],
        parent_roles=["viewer"]
    )
    print(f"   - Name: {ml_engineer.name}")
    print(f"   - Permissions: {[str(p) for p in ml_engineer.permissions]}")
    
    # 5. Permission Checking
    print("\n\n5. PERMISSION CHECKING")
    print("-" * 50)
    
    permission_checker = PermissionChecker(rbac_manager)
    
    # Test various permission scenarios
    test_cases = [
        ("Admin", ["admin"], "mcp.docker", "execute", True),
        ("Admin", ["admin"], "rbac", "admin", True),
        ("Operator", ["operator"], "mcp.docker", "execute", True),
        ("Operator", ["operator"], "deployment", "write", True),
        ("Operator", ["operator"], "rbac", "admin", False),
        ("Viewer", ["viewer"], "mcp.docker", "read", True),
        ("Viewer", ["viewer"], "mcp.docker", "execute", False),
        ("ML Engineer", ["ml_engineer"], "circle_of_experts", "execute", True),
        ("ML Engineer", ["ml_engineer"], "monitoring", "read", True),
        ("ML Engineer", ["ml_engineer"], "monitoring", "write", False),
    ]
    
    print("✅ Permission check results:")
    for user_name, roles, resource, action, expected in test_cases:
        result = permission_checker.check_permission("test_user", roles, resource, action)
        status = "✓" if result == expected else "✗"
        print(f"   {status} {user_name:<12} | {resource:<20} | {action:<8} | {result}")
    
    # 6. Resource-Based Permissions
    print("\n\n6. RESOURCE-BASED ACCESS CONTROL")
    print("-" * 50)
    
    # Create a deployment resource owned by operator
    deployment = permission_checker.register_resource_permission(
        ResourceType.DEPLOYMENT,
        "prod-deployment-123",
        owner_id=operator.id,
        initial_permissions={
            "role:viewer": {"read": True},
            "role:operator": {"read": True, "write": True, "execute": True}
        }
    )
    
    print(f"✅ Created deployment resource:")
    print(f"   - Resource: prod-deployment-123")
    print(f"   - Owner: {operator.username}")
    
    # Test resource access
    print(f"\n✅ Resource access tests:")
    print(f"   - Owner can write: {deployment.check_permission(operator.id, 'write', ['operator'])}")
    print(f"   - Admin can write: {deployment.check_permission(admin.id, 'write', ['admin'])}")
    print(f"   - Viewer can read: {deployment.check_permission(viewer.id, 'read', ['viewer'])}")
    print(f"   - Viewer can write: {deployment.check_permission(viewer.id, 'write', ['viewer'])}")
    
    # Grant specific permission
    deployment.grant_permission(f"user:{viewer.id}", "execute", {
        "conditions": {"time_window": {"start": "09:00", "end": "17:00"}}
    })
    print(f"\n✅ Granted conditional execute permission to viewer (9-5 only)")
    
    # 7. Session Management
    print("\n\n7. SESSION MANAGEMENT")
    print("-" * 50)
    
    # Create session tokens
    session_tokens = token_manager.create_token_pair(
        operator.id, operator.username, operator.roles, []
    )
    session_id = session_tokens["session_id"]
    print(f"✅ Created session: {session_id}")
    
    # Verify token works
    verified = token_manager.verify_token(session_tokens['access_token'])
    print(f"✅ Token valid: {verified is not None}")
    
    # Revoke session
    token_manager.revoke_session(session_id)
    print(f"✅ Revoked session: {session_id}")
    
    # Verify token no longer works
    verified_after = token_manager.verify_token(session_tokens['access_token'])
    print(f"✅ Token valid after revocation: {verified_after is not None}")
    
    # 8. Security Features Summary
    print("\n\n8. SECURITY FEATURES SUMMARY")
    print("-" * 50)
    print("✅ Password Security:")
    print("   - Bcrypt hashing (12 rounds)")
    print("   - Failed login tracking")
    print("   - Account lockout after 5 attempts")
    
    print("\n✅ Token Security:")
    print("   - JWT with HS256")
    print("   - 15-minute access tokens")
    print("   - 30-day refresh tokens")
    print("   - Session revocation")
    
    print("\n✅ API Key Security:")
    print("   - SHA-256 hashed storage")
    print("   - Rate limiting support")
    print("   - IP restrictions capability")
    
    print("\n✅ RBAC Features:")
    print("   - Role hierarchy with inheritance")
    print("   - Resource-based permissions")
    print("   - Conditional access rules")
    print("   - Custom role creation")
    
    print("\n✅ Compliance:")
    print("   - OWASP security guidelines")
    print("   - Audit trail support")
    print("   - Permission caching")
    print("   - Fine-grained access control")


if __name__ == "__main__":
    demonstrate_rbac_core()