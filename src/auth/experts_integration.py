"""Circle of Experts Authentication Integration.

Integrates RBAC with Circle of Experts to control AI model access.
"""

from typing import Dict, Any, Optional, List, Set
from dataclasses import dataclass
import asyncio

from ..circle_of_experts.core.expert_manager import ExpertManager
from ..circle_of_experts.models.query import ExpertQuery
from ..circle_of_experts.models.response import ConsensusResponse
from .permissions import PermissionChecker, ResourceType
from .models import User

from src.core.error_handler import (
    handle_errors,
    async_handle_errors,
    AuthenticationError,
    AuthorizationError,
    RateLimitError,
    log_error
)

__all__ = [
    "AuthenticatedExpertContext",
    "AuthenticatedExpertManager"
]



@dataclass
class AuthenticatedExpertContext:
    """Context for authenticated expert operations."""
    user: User
    session_id: str
    allowed_models: Set[str]
    query_limit: Optional[int] = None
    cost_limit: Optional[float] = None
    metadata: Dict[str, Any] = None


class AuthenticatedExpertManager:
    """Expert Manager with authentication and authorization."""
    
    def __init__(self, expert_manager: ExpertManager, 
                 permission_checker: PermissionChecker):
        """
        Initialize authenticated expert manager.
        
        Args:
            expert_manager: Original expert manager instance
            permission_checker: Permission checker instance
        """
        self.expert_manager = expert_manager
        self.permission_checker = permission_checker
        self._usage_tracking: Dict[str, Dict[str, Any]] = {}
    
    async def initialize(self) -> None:
        """Initialize the expert manager."""
        await self.expert_manager.initialize()
        self._register_expert_permissions()
    
    def _register_expert_permissions(self) -> None:
        """Register default expert permissions in RBAC system."""
        # Define expert model permissions
        expert_resources = {
            "circle_of_experts": ["execute", "read"],
            "circle_of_experts.claude": ["execute"],
            "circle_of_experts.openai": ["execute"],
            "circle_of_experts.gemini": ["execute"],
            "circle_of_experts.deepseek": ["execute"],
            "circle_of_experts.ollama": ["execute"],
        }
        
        # Register each resource
        for resource, actions in expert_resources.items():
            initial_perms = {
                "role:admin": {"*": True},
                "role:operator": {action: True for action in actions},
                "role:viewer": {"read": True}
            }
            
            # Special handling for expensive models
            if resource in ["circle_of_experts.claude", "circle_of_experts.openai"]:
                initial_perms["role:operator"] = {"execute": {"conditions": {"cost_limit": 10.0}}}
            
            self.permission_checker.register_resource_permission(
                ResourceType.AI_MODEL,
                resource,
                initial_permissions=initial_perms
            )
    
    def get_allowed_experts(self, user: User) -> List[str]:
        """Get list of AI experts user can access."""
        allowed = []
        
        # Check general permission first
        if self.permission_checker.check_permission(
            user.id, user.roles, "circle_of_experts", "execute"
        ):
            # Check specific model permissions
            for expert_type in ["claude", "openai", "gemini", "deepseek", "ollama"]:
                resource = f"circle_of_experts.{expert_type}"
                if self.permission_checker.check_permission(
                    user.id, user.roles, resource, "execute"
                ):
                    allowed.append(expert_type)
        
        return allowed
    
    def get_user_limits(self, user: User) -> Dict[str, Any]:
        """Get usage limits for user."""
        limits = {
            "query_limit": None,
            "cost_limit": None,
            "allowed_models": self.get_allowed_experts(user),
            "rate_limit": 100  # queries per hour
        }
        
        # Check for specific role limits
        if "viewer" in user.roles:
            limits["query_limit"] = 10
            limits["cost_limit"] = 1.0
            limits["rate_limit"] = 10
        elif "operator" in user.roles:
            limits["query_limit"] = 100
            limits["cost_limit"] = 10.0
            limits["rate_limit"] = 50
        
        return limits
    
    async def submit_query(self, context: AuthenticatedExpertContext,
                          query: str, expert_types: Optional[List[str]] = None,
                          **kwargs) -> ConsensusResponse:
        """Submit query with authentication and authorization."""
        # Check basic permission
        if not self.permission_checker.check_permission(
            context.user.id, context.user.roles, "circle_of_experts", "execute"
        ):
            raise PermissionError("User does not have permission to use Circle of Experts")
        
        # Filter expert types by permissions
        if expert_types:
            allowed_types = []
            for expert_type in expert_types:
                if expert_type in context.allowed_models:
                    resource = f"circle_of_experts.{expert_type}"
                    if self.permission_checker.check_permission(
                        context.user.id, context.user.roles, resource, "execute"
                    ):
                        allowed_types.append(expert_type)
            
            if not allowed_types:
                raise PermissionError("User does not have permission for any requested models")
            
            expert_types = allowed_types
        else:
            # Use all allowed models
            expert_types = list(context.allowed_models)
        
        # Check usage limits
        await self._check_usage_limits(context)
        
        # Track query start
        query_id = await self._start_query_tracking(context, query, expert_types)
        
        try:
            # Create expert query
            expert_query = ExpertQuery(
                query=query,
                expert_types=expert_types,
                metadata={
                    "user_id": context.user.id,
                    "session_id": context.session_id,
                    "query_id": query_id,
                    **(context.metadata or {})
                }
            )
            
            # Submit to expert manager
            response = await self.expert_manager.get_consensus(
                expert_query.query,
                expert_types=expert_query.expert_types,
                **kwargs
            )
            
            # Track successful completion
            await self._complete_query_tracking(context, query_id, response)
            
            return response
            
        except Exception as e:
            # Track failure
            await self._fail_query_tracking(context, query_id, str(e))
            raise
    
    async def _check_usage_limits(self, context: AuthenticatedExpertContext) -> None:
        """Check if user is within usage limits."""
        user_id = context.user.id
        
        # Initialize tracking if needed
        if user_id not in self._usage_tracking:
            self._usage_tracking[user_id] = {
                "queries": 0,
                "cost": 0.0,
                "last_reset": asyncio.get_event_loop().time()
            }
        
        usage = self._usage_tracking[user_id]
        
        # Check query limit
        if context.query_limit and usage["queries"] >= context.query_limit:
            raise PermissionError(f"Query limit exceeded: {context.query_limit}")
        
        # Check cost limit
        if context.cost_limit and usage["cost"] >= context.cost_limit:
            raise PermissionError(f"Cost limit exceeded: ${context.cost_limit}")
        
        # Check rate limit (reset hourly)
        current_time = asyncio.get_event_loop().time()
        if current_time - usage["last_reset"] > 3600:  # 1 hour
            usage["queries"] = 0
            usage["cost"] = 0.0
            usage["last_reset"] = current_time
    
    async def _start_query_tracking(self, context: AuthenticatedExpertContext,
                                  query: str, expert_types: List[str]) -> str:
        """Start tracking a query."""
        import uuid
        query_id = str(uuid.uuid4())
        
        # Increment query count
        if context.user.id in self._usage_tracking:
            self._usage_tracking[context.user.id]["queries"] += 1
        
        # Audit query start
        audit_entry = {
            "timestamp": asyncio.get_event_loop().time(),
            "user_id": context.user.id,
            "session_id": context.session_id,
            "action": "expert_query_start",
            "query_id": query_id,
            "expert_types": expert_types,
            "query_preview": query[:100] + "..." if len(query) > 100 else query
        }
        print(f"AUDIT: {audit_entry}")
        
        return query_id
    
    async def _complete_query_tracking(self, context: AuthenticatedExpertContext,
                                     query_id: str, response: ConsensusResponse) -> None:
        """Track successful query completion."""
        # Estimate cost (simplified)
        estimated_cost = len(response.consensus) * 0.001  # $0.001 per 1K chars
        
        if context.user.id in self._usage_tracking:
            self._usage_tracking[context.user.id]["cost"] += estimated_cost
        
        # Audit success
        audit_entry = {
            "timestamp": asyncio.get_event_loop().time(),
            "user_id": context.user.id,
            "session_id": context.session_id,
            "action": "expert_query_success",
            "query_id": query_id,
            "estimated_cost": estimated_cost,
            "response_length": len(response.consensus)
        }
        print(f"AUDIT: {audit_entry}")
    
    async def _fail_query_tracking(self, context: AuthenticatedExpertContext,
                                 query_id: str, error: str) -> None:
        """Track query failure."""
        audit_entry = {
            "timestamp": asyncio.get_event_loop().time(),
            "user_id": context.user.id,
            "session_id": context.session_id,
            "action": "expert_query_failure",
            "query_id": query_id,
            "error": error
        }
        print(f"AUDIT: {audit_entry}")
    
    def get_usage_stats(self, user_id: str) -> Dict[str, Any]:
        """Get usage statistics for a user."""
        if user_id not in self._usage_tracking:
            return {
                "queries": 0,
                "cost": 0.0,
                "last_reset": None
            }
        
        return self._usage_tracking[user_id].copy()
    
    def reset_usage(self, user_id: str) -> None:
        """Reset usage tracking for a user."""
        if user_id in self._usage_tracking:
            self._usage_tracking[user_id] = {
                "queries": 0,
                "cost": 0.0,
                "last_reset": asyncio.get_event_loop().time()
            }
    
    async def get_model_access_matrix(self) -> Dict[str, Dict[str, bool]]:
        """Get matrix of which roles can access which models."""
        matrix = {}
        roles = ["viewer", "operator", "admin"]
        models = ["claude", "openai", "gemini", "deepseek", "ollama"]
        
        for role in roles:
            matrix[role] = {}
            for model in models:
                resource = f"circle_of_experts.{model}"
                # Create a temporary context to check
                matrix[role][model] = self.permission_checker.check_permission(
                    "temp_user", [role], resource, "execute"
                )
        
        return matrix
    
    def create_limited_context(self, user: User, **overrides) -> AuthenticatedExpertContext:
        """Create an authenticated context with appropriate limits."""
        limits = self.get_user_limits(user)
        
        return AuthenticatedExpertContext(
            user=user,
            session_id=overrides.get("session_id", "default"),
            allowed_models=set(limits["allowed_models"]),
            query_limit=overrides.get("query_limit", limits["query_limit"]),
            cost_limit=overrides.get("cost_limit", limits["cost_limit"]),
            metadata=overrides.get("metadata", {})
        )