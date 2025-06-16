
# AGENT 6: MODULARITY AND ARCHITECTURE ANALYSIS REPORT
**Analysis Date**: 2025-06-07 10:04:38

## 📊 EXECUTIVE SUMMARY

### Overall Modularity Score: 0.10/1.0
### Interface Quality Score: 0.47/1.0

## 🏗️ ARCHITECTURE OVERVIEW

- **Total Modules**: 132
- **Total Lines of Code**: 43,207
- **Average Module Size**: 327.3 LOC
- **Circular Dependencies**: 4
- **Layer Violations**: 3

## 📈 MODULE METRICS

### Top 10 Largest Modules
 1. **mcp.infrastructure_servers**: 1588 LOC, 11 responsibilities
 2. **utils.security**: 1153 LOC, 11 responsibilities
 3. **mcp.devops_servers**: 908 LOC, 11 responsibilities
 4. **utils.database**: 748 LOC, 8 responsibilities
 5. **mcp.communication.slack_server**: 742 LOC, 9 responsibilities
 6. **circle_of_experts.experts.commercial_experts**: 740 LOC, 10 responsibilities
 7. **mcp.security.supply_chain_server**: 731 LOC, 11 responsibilities
 8. **auth.audit**: 691 LOC, 11 responsibilities
 9. **core.connections**: 661 LOC, 9 responsibilities
10. **utils.monitoring**: 650 LOC, 7 responsibilities

### Cohesion Analysis
- **High Cohesion** (≥0.7): 1 modules
- **Medium Cohesion** (0.4-0.69): 27 modules
- **Low Cohesion** (<0.4): 104 modules

**Low Cohesion Modules (Need Refactoring)**:
- .: 0.00 (1 responsibilities)
- utils.__main__: 0.00 (1 responsibilities)
- utils: 0.00 (5 responsibilities)
- circle_of_experts: 0.00 (2 responsibilities)
- core.stream_processor: 0.00 (7 responsibilities)
- core.path_validation: 0.00 (6 responsibilities)
- core: 0.00 (6 responsibilities)
- mcp.infrastructure_servers: 0.00 (11 responsibilities)
- mcp: 0.00 (2 responsibilities)
- database.connection: 0.00 (7 responsibilities)
- database: 0.00 (5 responsibilities)
- database.models: 0.00 (8 responsibilities)
- database.tortoise_config: 0.00 (5 responsibilities)
- monitoring.metrics: 0.00 (10 responsibilities)
- monitoring.tracing: 0.00 (6 responsibilities)
- monitoring.mcp_integration: 0.00 (9 responsibilities)
- monitoring.enhanced_memory_metrics: 0.00 (7 responsibilities)
- monitoring.setup_monitoring: 0.00 (9 responsibilities)
- monitoring: 0.00 (4 responsibilities)
- monitoring.api: 0.00 (9 responsibilities)
- api: 0.00 (1 responsibilities)
- api.circuit_breaker_api: 0.00 (6 responsibilities)
- platform: 0.00 (0 responsibilities)
- auth: 0.00 (9 responsibilities)
- circle_of_experts.utils: 0.00 (5 responsibilities)
- circle_of_experts.core.expert_manager: 0.00 (11 responsibilities)
- circle_of_experts.core.query_handler: 0.00 (9 responsibilities)
- circle_of_experts.core.connection_pool_integration: 0.00 (10 responsibilities)
- circle_of_experts.core: 0.00 (4 responsibilities)
- circle_of_experts.core.response_collector: 0.00 (8 responsibilities)
- circle_of_experts.drive: 0.00 (0 responsibilities)
- circle_of_experts.experts.expert_factory: 0.00 (9 responsibilities)
- circle_of_experts.experts: 0.00 (3 responsibilities)
- circle_of_experts.models: 0.00 (2 responsibilities)
- mcp.communication: 0.00 (2 responsibilities)
- mcp.storage: 0.00 (1 responsibilities)
- mcp.base: 0.00 (1 responsibilities)
- mcp.security: 0.00 (3 responsibilities)
- mcp.monitoring: 0.00 (4 responsibilities)
- mcp.devops: 0.00 (1 responsibilities)
- mcp.infrastructure: 0.00 (1 responsibilities)
- database.repositories.audit_repository: 0.00 (5 responsibilities)
- database.repositories: 0.00 (4 responsibilities)
- database.repositories.deployment_repository: 0.00 (5 responsibilities)
- database.migrations: 0.00 (1 responsibilities)
- mcp.security.supply_chain_server: 0.04 (11 responsibilities)
- circle_of_experts.experts.openrouter_expert: 0.05 (9 responsibilities)
- auth.experts_integration: 0.06 (6 responsibilities)
- mcp.security.sast_server: 0.07 (12 responsibilities)
- circle_of_experts.utils.rust_integration: 0.11 (7 responsibilities)
- monitoring.memory_integration: 0.12 (7 responsibilities)
- circle_of_experts.core.enhanced_response_collector: 0.12 (4 responsibilities)
- database.migrations.alembic.env: 0.12 (7 responsibilities)
- circle_of_experts.experts.claude_expert: 0.14 (10 responsibilities)
- core.gc_optimization: 0.16 (4 responsibilities)
- circle_of_experts.mcp_integration: 0.17 (6 responsibilities)
- database.init: 0.17 (9 responsibilities)
- utils.security: 0.17 (11 responsibilities)
- core.lifecycle_gc_integration: 0.18 (8 responsibilities)
- utils.database: 0.18 (8 responsibilities)
- utils.integration: 0.19 (10 responsibilities)
- monitoring.memory_response: 0.21 (8 responsibilities)
- mcp.infrastructure.commander_server: 0.22 (11 responsibilities)
- utils.monitoring: 0.23 (7 responsibilities)
- core.parallel_executor: 0.23 (8 responsibilities)
- auth.audit: 0.24 (11 responsibilities)
- __main__: 0.25 (4 responsibilities)
- circle_of_experts.rust_integration: 0.25 (6 responsibilities)
- core.circuit_breaker_config: 0.25 (7 responsibilities)
- circle_of_experts.utils.validation: 0.25 (6 responsibilities)
- circle_of_experts.core.enhanced_expert_manager: 0.25 (10 responsibilities)
- mcp.communication.hub_server: 0.25 (8 responsibilities)
- mcp.communication.slack_server: 0.25 (9 responsibilities)
- mcp.storage.s3_server: 0.25 (7 responsibilities)
- auth.mcp_integration: 0.27 (8 responsibilities)
- core.log_sanitization: 0.28 (9 responsibilities)
- monitoring.memory_alerts: 0.28 (8 responsibilities)
- mcp.manager: 0.28 (7 responsibilities)
- core.retry: 0.28 (8 responsibilities)
- core.cleanup_scheduler: 0.29 (5 responsibilities)
- core.lazy_imports: 0.30 (7 responsibilities)
- circle_of_experts.experts.open_source_experts: 0.31 (9 responsibilities)
- utils.git: 0.31 (12 responsibilities)
- utils.imports: 0.32 (9 responsibilities)
- core.cache_config: 0.32 (10 responsibilities)
- core.circuit_breaker_monitoring: 0.32 (9 responsibilities)
- auth.audit_config: 0.32 (10 responsibilities)
- circle_of_experts.utils.logging: 0.32 (9 responsibilities)
- core.cors_config: 0.32 (7 responsibilities)
- auth.tokens: 0.33 (7 responsibilities)
- mcp.storage.cloud_storage_server: 0.33 (10 responsibilities)
- monitoring.sla: 0.34 (7 responsibilities)
- mcp.devops_servers: 0.35 (11 responsibilities)
- database.utils: 0.35 (11 responsibilities)
- auth.permissions: 0.35 (8 responsibilities)
- core.ssrf_protection: 0.35 (11 responsibilities)
- auth.middleware: 0.35 (10 responsibilities)
- mcp.security.auth_middleware: 0.35 (10 responsibilities)
- mcp.protocols: 0.37 (10 responsibilities)
- core.connection_monitoring: 0.38 (7 responsibilities)
- monitoring.memory_monitor: 0.38 (7 responsibilities)
- mcp.security.scanner_server: 0.38 (12 responsibilities)
- platform.wsl_integration: 0.38 (8 responsibilities)
- auth.api: 0.38 (12 responsibilities)

### Coupling Analysis
- **High Coupling** (≥10): 3 modules
- **Medium Coupling** (5-9): 10 modules
- **Low Coupling** (<5): 119 modules

**High Coupling Modules (Consider Decoupling)**:
- circle_of_experts.core.response_collector: 12 dependencies
- mcp.servers: 11 dependencies
- database: 11 dependencies

## 🔄 DEPENDENCY ANALYSIS

### Circular Dependencies
1. core → core
2. mcp → mcp
3. database → database
4. platform → platform

### Layer Violations
- core.circuit_breaker_monitoring (layer 1) -> mcp (layer 4)
- mcp.manager (layer 4) -> circle_of_experts (layer 5)
- mcp.monitoring.prometheus_server (layer 4) -> circle_of_experts (layer 5)

## 🏛️ SOLID PRINCIPLES COMPLIANCE

| Principle | Score | Status |
|-----------|-------|--------|
| Single Responsibility | 0.15 | ❌ Poor |
| Open/Closed | 0.52 | ⚠️ Needs Improvement |
| Liskov Substitution | 0.79 | ✅ Good |
| Interface Segregation | 0.47 | ❌ Poor |
| Dependency Inversion | 0.54 | ⚠️ Needs Improvement |
| **Overall SOLID Score** | **0.50** | **❌ Poor** |

## 📋 DETAILED MODULE BREAKDOWN


### .
- **Path**: `src/__init__.py`
- **Size**: 9 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 0 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: authentication
- **Internal Dependencies**: 0
- **External Dependencies**: 0

### __main__
- **Path**: `src/__main__.py`
- **Size**: 53 LOC
- **Complexity**: 4
- **Cohesion**: 0.25
- **Coupling**: 3 dependencies
- **Classes**: 0 ()
- **Functions**: 2 (initialize_application, main)
- **Responsibilities**: monitoring, file_io, testing, configuration
- **Internal Dependencies**: 3
- **External Dependencies**: 3

### api
- **Path**: `src/api/__init__.py`
- **Size**: 3 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 0 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: networking
- **Internal Dependencies**: 0
- **External Dependencies**: 0

### api.circuit_breaker_api
- **Path**: `src/api/circuit_breaker_api.py`
- **Size**: 284 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 2 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: networking, database, async, monitoring, configuration, validation
- **Internal Dependencies**: 2
- **External Dependencies**: 3

### auth
- **Path**: `src/auth/__init__.py`
- **Size**: 106 LOC
- **Complexity**: 3
- **Cohesion**: 0.00
- **Coupling**: 0 dependencies
- **Classes**: 0 ()
- **Functions**: 1 (create_auth_system)
- **Responsibilities**: authentication, networking, database, caching, async, security, monitoring, configuration, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 0

### auth.api
- **Path**: `src/auth/api.py`
- **Size**: 517 LOC
- **Complexity**: 15
- **Cohesion**: 0.38
- **Coupling**: 0 dependencies
- **Classes**: 10 (LoginRequest, LoginResponse, RefreshTokenRequest...)
- **Functions**: 3 (get_auth_dependencies, require_permission, dependency)
- **Responsibilities**: authentication, networking, database, testing, caching, async, security, serialization, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 5

### auth.audit
- **Path**: `src/auth/audit.py`
- **Size**: 691 LOC
- **Complexity**: 88
- **Cohesion**: 0.24
- **Coupling**: 0 dependencies
- **Classes**: 4 (AuditEventType, AuditSeverity, AuditEvent...)
- **Functions**: 17 (audit_action, to_dict, to_json...)
- **Responsibilities**: authentication, networking, database, caching, async, security, serialization, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 14

### auth.audit_config
- **Path**: `src/auth/audit_config.py`
- **Size**: 113 LOC
- **Complexity**: 10
- **Cohesion**: 0.32
- **Coupling**: 0 dependencies
- **Classes**: 1 (AuditConfig)
- **Functions**: 10 (get_audit_logger, setup_audit_signing_key, __init__...)
- **Responsibilities**: authentication, networking, testing, caching, async, security, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 5

### auth.experts_integration
- **Path**: `src/auth/experts_integration.py`
- **Size**: 245 LOC
- **Complexity**: 28
- **Cohesion**: 0.06
- **Coupling**: 0 dependencies
- **Classes**: 2 (AuthenticatedExpertContext, AuthenticatedExpertManager)
- **Functions**: 7 (__init__, _register_expert_permissions, get_allowed_experts...)
- **Responsibilities**: authentication, networking, database, async, file_io, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 4

### auth.mcp_integration
- **Path**: `src/auth/mcp_integration.py`
- **Size**: 240 LOC
- **Complexity**: 24
- **Cohesion**: 0.27
- **Coupling**: 0 dependencies
- **Classes**: 3 (AuthenticatedMCPContext, AuthenticatedMCPServer, AuthenticatedMCPManager)
- **Functions**: 10 (__init__, set_context, get_server_info...)
- **Responsibilities**: authentication, networking, database, async, security, monitoring, file_io, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 3

### auth.middleware
- **Path**: `src/auth/middleware.py`
- **Size**: 336 LOC
- **Complexity**: 43
- **Cohesion**: 0.35
- **Coupling**: 0 dependencies
- **Classes**: 2 (AuthMiddleware, RateLimitMiddleware)
- **Functions**: 15 (require_auth, require_permission, __init__...)
- **Responsibilities**: authentication, networking, database, caching, async, security, serialization, monitoring, configuration, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 7

### auth.models
- **Path**: `src/auth/models.py`
- **Size**: 250 LOC
- **Complexity**: 21
- **Cohesion**: 0.46
- **Coupling**: 0 dependencies
- **Classes**: 5 (UserStatus, APIKeyStatus, User...)
- **Functions**: 22 (create, verify_password, update_password...)
- **Responsibilities**: authentication, networking, database, security, monitoring, caching, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 8

### auth.permissions
- **Path**: `src/auth/permissions.py`
- **Size**: 279 LOC
- **Complexity**: 69
- **Cohesion**: 0.35
- **Coupling**: 0 dependencies
- **Classes**: 3 (ResourceType, ResourcePermission, PermissionChecker)
- **Functions**: 17 (require_permission, check_permission, _check_contextual_permission...)
- **Responsibilities**: networking, configuration, database, async, monitoring, file_io, caching, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 7

### auth.rbac
- **Path**: `src/auth/rbac.py`
- **Size**: 311 LOC
- **Complexity**: 45
- **Cohesion**: 0.46
- **Coupling**: 0 dependencies
- **Classes**: 4 (PermissionType, Permission, Role...)
- **Functions**: 22 (__str__, __hash__, __eq__...)
- **Responsibilities**: authentication, networking, security, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 4

### auth.tokens
- **Path**: `src/auth/tokens.py`
- **Size**: 339 LOC
- **Complexity**: 28
- **Cohesion**: 0.33
- **Coupling**: 0 dependencies
- **Classes**: 2 (TokenData, TokenManager)
- **Functions**: 19 (to_dict, from_dict, __init__...)
- **Responsibilities**: authentication, networking, security, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 8

### auth.user_manager
- **Path**: `src/auth/user_manager.py`
- **Size**: 472 LOC
- **Complexity**: 64
- **Cohesion**: 0.43
- **Coupling**: 0 dependencies
- **Classes**: 3 (UserCreationRequest, PasswordResetRequest, UserManager)
- **Functions**: 4 (validate, validate, __init__...)
- **Responsibilities**: authentication, networking, database, async, security, monitoring, file_io, caching, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 10

### circle_of_experts
- **Path**: `src/circle_of_experts/__init__.py`
- **Size**: 25 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 0 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: networking, database
- **Internal Dependencies**: 0
- **External Dependencies**: 0

### circle_of_experts.core
- **Path**: `src/circle_of_experts/core/__init__.py`
- **Size**: 41 LOC
- **Complexity**: 2
- **Cohesion**: 0.00
- **Coupling**: 0 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: monitoring, networking, database, async
- **Internal Dependencies**: 0
- **External Dependencies**: 0

### circle_of_experts.core.connection_pool_integration
- **Path**: `src/circle_of_experts/core/connection_pool_integration.py`
- **Size**: 187 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 5 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: authentication, networking, database, caching, async, serialization, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 5
- **External Dependencies**: 8

### circle_of_experts.core.enhanced_expert_manager
- **Path**: `src/circle_of_experts/core/enhanced_expert_manager.py`
- **Size**: 312 LOC
- **Complexity**: 20
- **Cohesion**: 0.25
- **Coupling**: 3 dependencies
- **Classes**: 2 (EnhancedExpertManager, BatchConsultation)
- **Functions**: 6 (__init__, _check_memory_pressure, _get_current_memory_mb...)
- **Responsibilities**: authentication, networking, database, testing, async, serialization, monitoring, file_io, caching, validation
- **Internal Dependencies**: 3
- **External Dependencies**: 11

### circle_of_experts.core.enhanced_response_collector
- **Path**: `src/circle_of_experts/core/enhanced_response_collector.py`
- **Size**: 83 LOC
- **Complexity**: 10
- **Cohesion**: 0.12
- **Coupling**: 3 dependencies
- **Classes**: 1 (EnhancedResponseCollector)
- **Functions**: 3 (__init__, build_consensus, _map_consensus_score_to_level)
- **Responsibilities**: monitoring, networking, database, testing
- **Internal Dependencies**: 3
- **External Dependencies**: 4

### circle_of_experts.core.expert_manager
- **Path**: `src/circle_of_experts/core/expert_manager.py`
- **Size**: 378 LOC
- **Complexity**: 18
- **Cohesion**: 0.00
- **Coupling**: 8 dependencies
- **Classes**: 1 (ExpertManager)
- **Functions**: 3 (__init__, _cleanup_expired_queries, get_cache_stats)
- **Responsibilities**: authentication, networking, database, testing, async, security, serialization, monitoring, file_io, caching, validation
- **Internal Dependencies**: 8
- **External Dependencies**: 7

### circle_of_experts.core.query_handler
- **Path**: `src/circle_of_experts/core/query_handler.py`
- **Size**: 393 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 6 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: networking, database, async, security, serialization, monitoring, file_io, caching, validation
- **Internal Dependencies**: 6
- **External Dependencies**: 10

### circle_of_experts.core.response_collector
- **Path**: `src/circle_of_experts/core/response_collector.py`
- **Size**: 474 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 12 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: networking, database, async, security, monitoring, file_io, caching, validation
- **Internal Dependencies**: 12
- **External Dependencies**: 6

### circle_of_experts.core.rust_accelerated
- **Path**: `src/circle_of_experts/core/rust_accelerated.py`
- **Size**: 543 LOC
- **Complexity**: 54
- **Cohesion**: 0.45
- **Coupling**: 0 dependencies
- **Classes**: 9 (ConsensusAnalyzer, ResponseAggregator, PatternMatcher...)
- **Functions**: 30 (create_consensus_analyzer, create_response_aggregator, create_pattern_matcher...)
- **Responsibilities**: networking, configuration, async, monitoring, caching
- **Internal Dependencies**: 0
- **External Dependencies**: 9

### circle_of_experts.drive
- **Path**: `src/circle_of_experts/drive/__init__.py`
- **Size**: 3 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 1 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: None identified
- **Internal Dependencies**: 1
- **External Dependencies**: 0

### circle_of_experts.drive.manager
- **Path**: `src/circle_of_experts/drive/manager.py`
- **Size**: 287 LOC
- **Complexity**: 19
- **Cohesion**: 0.50
- **Coupling**: 3 dependencies
- **Classes**: 1 (DriveManager)
- **Functions**: 3 (__init__, service, _build_service)
- **Responsibilities**: authentication, networking, database, async, serialization, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 3
- **External Dependencies**: 11

### circle_of_experts.experts
- **Path**: `src/circle_of_experts/experts/__init__.py`
- **Size**: 48 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 0 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: networking, validation, configuration
- **Internal Dependencies**: 0
- **External Dependencies**: 0

### circle_of_experts.experts.claude_expert
- **Path**: `src/circle_of_experts/experts/claude_expert.py`
- **Size**: 284 LOC
- **Complexity**: 38
- **Cohesion**: 0.14
- **Coupling**: 5 dependencies
- **Classes**: 2 (BaseExpertClient, ClaudeExpertClient)
- **Functions**: 9 (__init__, __init__, _determine_model_for_query...)
- **Responsibilities**: authentication, networking, database, testing, async, security, serialization, monitoring, configuration, validation
- **Internal Dependencies**: 5
- **External Dependencies**: 12

### circle_of_experts.experts.commercial_experts
- **Path**: `src/circle_of_experts/experts/commercial_experts.py`
- **Size**: 740 LOC
- **Complexity**: 99
- **Cohesion**: 0.55
- **Coupling**: 6 dependencies
- **Classes**: 4 (GPT4ExpertClient, GeminiExpertClient, GroqExpertClient...)
- **Functions**: 24 (__init__, _select_model_for_query, _create_messages...)
- **Responsibilities**: authentication, networking, database, testing, async, serialization, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 6
- **External Dependencies**: 11

### circle_of_experts.experts.expert_factory
- **Path**: `src/circle_of_experts/experts/expert_factory.py`
- **Size**: 502 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 3 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: authentication, networking, database, testing, caching, async, monitoring, configuration, validation
- **Internal Dependencies**: 3
- **External Dependencies**: 7

### circle_of_experts.experts.open_source_experts
- **Path**: `src/circle_of_experts/experts/open_source_experts.py`
- **Size**: 416 LOC
- **Complexity**: 38
- **Cohesion**: 0.31
- **Coupling**: 6 dependencies
- **Classes**: 3 (OllamaExpertClient, LocalAIExpertClient, HuggingFaceExpertClient)
- **Functions**: 10 (__init__, _select_model_for_query, _create_prompt...)
- **Responsibilities**: authentication, networking, database, async, serialization, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 6
- **External Dependencies**: 8

### circle_of_experts.experts.openrouter_expert
- **Path**: `src/circle_of_experts/experts/openrouter_expert.py`
- **Size**: 278 LOC
- **Complexity**: 59
- **Cohesion**: 0.05
- **Coupling**: 4 dependencies
- **Classes**: 1 (OpenRouterExpertClient)
- **Functions**: 9 (__init__, _select_optimal_model, _get_fallback_models...)
- **Responsibilities**: authentication, networking, database, testing, async, serialization, monitoring, configuration, validation
- **Internal Dependencies**: 4
- **External Dependencies**: 8

### circle_of_experts.mcp_integration
- **Path**: `src/circle_of_experts/mcp_integration.py`
- **Size**: 246 LOC
- **Complexity**: 13
- **Cohesion**: 0.17
- **Coupling**: 4 dependencies
- **Classes**: 1 (MCPEnhancedExpertManager)
- **Functions**: 2 (__init__, _extract_search_terms)
- **Responsibilities**: networking, database, testing, async, monitoring, configuration
- **Internal Dependencies**: 4
- **External Dependencies**: 6

### circle_of_experts.models
- **Path**: `src/circle_of_experts/models/__init__.py`
- **Size**: 14 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 0 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: networking, database
- **Internal Dependencies**: 0
- **External Dependencies**: 0

### circle_of_experts.models.query
- **Path**: `src/circle_of_experts/models/query.py`
- **Size**: 144 LOC
- **Complexity**: 10
- **Cohesion**: 0.44
- **Coupling**: 0 dependencies
- **Classes**: 4 (QueryPriority, QueryType, ExpertQuery...)
- **Functions**: 4 (validate_deadline, validate_tags, to_markdown...)
- **Responsibilities**: networking, configuration, database, security, serialization, file_io, caching, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 6

### circle_of_experts.models.response
- **Path**: `src/circle_of_experts/models/response.py`
- **Size**: 232 LOC
- **Complexity**: 21
- **Cohesion**: 0.43
- **Coupling**: 0 dependencies
- **Classes**: 6 (ExpertType, ResponseStatus, ExpertResponse...)
- **Functions**: 8 (validate_completed_at, validate_processing_time, validate_code_snippets...)
- **Responsibilities**: networking, database, security, serialization, file_io, configuration, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 6

### circle_of_experts.rust_integration
- **Path**: `src/circle_of_experts/rust_integration.py`
- **Size**: 221 LOC
- **Complexity**: 15
- **Cohesion**: 0.25
- **Coupling**: 1 dependencies
- **Classes**: 2 (ConsensusResult, RustAcceleratedConsensus)
- **Functions**: 8 (get_consensus_processor, process_expert_consensus, __init__...)
- **Responsibilities**: networking, database, testing, monitoring, file_io, configuration
- **Internal Dependencies**: 1
- **External Dependencies**: 5

### circle_of_experts.utils
- **Path**: `src/circle_of_experts/utils/__init__.py`
- **Size**: 39 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 3 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: networking, database, security, monitoring, validation
- **Internal Dependencies**: 3
- **External Dependencies**: 0

### circle_of_experts.utils.logging
- **Path**: `src/circle_of_experts/utils/logging.py`
- **Size**: 142 LOC
- **Complexity**: 12
- **Cohesion**: 0.32
- **Coupling**: 0 dependencies
- **Classes**: 2 (StructuredFormatter, LogContext)
- **Functions**: 9 (setup_logging, get_logger, format...)
- **Responsibilities**: authentication, configuration, database, async, serialization, monitoring, file_io, caching, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 6

### circle_of_experts.utils.retry
- **Path**: `src/circle_of_experts/utils/retry.py`
- **Size**: 149 LOC
- **Complexity**: 13
- **Cohesion**: 0.44
- **Coupling**: 0 dependencies
- **Classes**: 2 (RetryPolicy, RetryableOperation)
- **Functions**: 7 (with_retry, with_retry_sync, calculate_delay...)
- **Responsibilities**: monitoring, async, configuration
- **Internal Dependencies**: 0
- **External Dependencies**: 8

### circle_of_experts.utils.rust_integration
- **Path**: `src/circle_of_experts/utils/rust_integration.py`
- **Size**: 329 LOC
- **Complexity**: 42
- **Cohesion**: 0.11
- **Coupling**: 0 dependencies
- **Classes**: 1 (RustIntegration)
- **Functions**: 13 (get_rust_integration, __init__, _detect_and_load_rust_modules...)
- **Responsibilities**: networking, configuration, testing, monitoring, file_io, caching, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 8

### circle_of_experts.utils.validation
- **Path**: `src/circle_of_experts/utils/validation.py`
- **Size**: 355 LOC
- **Complexity**: 55
- **Cohesion**: 0.25
- **Coupling**: 3 dependencies
- **Classes**: 0 ()
- **Functions**: 10 (validate_not_none, validate_string, validate_enum...)
- **Responsibilities**: networking, database, security, monitoring, file_io, validation
- **Internal Dependencies**: 3
- **External Dependencies**: 4

### core
- **Path**: `src/core/__init__.py`
- **Size**: 51 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 4 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: networking, configuration, database, monitoring, caching, validation
- **Internal Dependencies**: 4
- **External Dependencies**: 0

### core.cache_config
- **Path**: `src/core/cache_config.py`
- **Size**: 259 LOC
- **Complexity**: 26
- **Cohesion**: 0.32
- **Coupling**: 0 dependencies
- **Classes**: 2 (CacheConfiguration, ConfigPresets)
- **Functions**: 17 (get_cache_config, set_cache_config, reset_cache_config...)
- **Responsibilities**: networking, database, testing, caching, security, serialization, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 5

### core.circuit_breaker
- **Path**: `src/core/circuit_breaker.py`
- **Size**: 536 LOC
- **Complexity**: 71
- **Cohesion**: 0.42
- **Coupling**: 1 dependencies
- **Classes**: 6 (CircuitState, CircuitBreakerConfig, CircuitBreakerMetrics...)
- **Functions**: 27 (get_circuit_breaker, get_circuit_breaker_manager, circuit_breaker...)
- **Responsibilities**: networking, database, testing, async, security, serialization, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 1
- **External Dependencies**: 10

### core.circuit_breaker_config
- **Path**: `src/core/circuit_breaker_config.py`
- **Size**: 504 LOC
- **Complexity**: 36
- **Cohesion**: 0.25
- **Coupling**: 1 dependencies
- **Classes**: 2 (EnvironmentConfig, CircuitBreakerConfigManager)
- **Functions**: 12 (get_circuit_breaker_config_manager, get_circuit_breaker_config, __init__...)
- **Responsibilities**: database, testing, security, serialization, monitoring, file_io, configuration
- **Internal Dependencies**: 1
- **External Dependencies**: 6

### core.circuit_breaker_metrics
- **Path**: `src/core/circuit_breaker_metrics.py`
- **Size**: 276 LOC
- **Complexity**: 11
- **Cohesion**: 0.52
- **Coupling**: 0 dependencies
- **Classes**: 5 (CircuitBreakerPrometheusMetrics, Counter, Gauge...)
- **Functions**: 24 (get_circuit_breaker_metrics, reset_metrics, __init__...)
- **Responsibilities**: monitoring, networking, testing, configuration
- **Internal Dependencies**: 0
- **External Dependencies**: 6

### core.circuit_breaker_monitoring
- **Path**: `src/core/circuit_breaker_monitoring.py`
- **Size**: 283 LOC
- **Complexity**: 35
- **Cohesion**: 0.32
- **Coupling**: 2 dependencies
- **Classes**: 3 (CircuitBreakerAlert, MonitoringConfig, CircuitBreakerMonitor)
- **Functions**: 8 (get_monitoring_status, log_alert, to_dict...)
- **Responsibilities**: networking, configuration, testing, async, serialization, monitoring, file_io, caching, validation
- **Internal Dependencies**: 2
- **External Dependencies**: 7

### core.cleanup_scheduler
- **Path**: `src/core/cleanup_scheduler.py`
- **Size**: 394 LOC
- **Complexity**: 45
- **Cohesion**: 0.29
- **Coupling**: 0 dependencies
- **Classes**: 4 (TaskPriority, CleanupTask, CleanupStats...)
- **Functions**: 13 (get_cleanup_scheduler, is_due, should_skip...)
- **Responsibilities**: async, monitoring, file_io, caching, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 10

### core.connection_monitoring
- **Path**: `src/core/connection_monitoring.py`
- **Size**: 288 LOC
- **Complexity**: 35
- **Cohesion**: 0.38
- **Coupling**: 1 dependencies
- **Classes**: 2 (ConnectionPoolMonitor, ConnectionPoolHealthCheck)
- **Functions**: 6 (__init__, _update_metrics, _sanitize_label...)
- **Responsibilities**: networking, database, testing, async, monitoring, caching, validation
- **Internal Dependencies**: 1
- **External Dependencies**: 8

### core.connections
- **Path**: `src/core/connections.py`
- **Size**: 661 LOC
- **Complexity**: 75
- **Cohesion**: 0.48
- **Coupling**: 0 dependencies
- **Classes**: 7 (ConnectionPoolConfig, ConnectionMetrics, HTTPConnectionPool...)
- **Functions**: 18 (add_request, add_error, get_average_wait_time...)
- **Responsibilities**: networking, configuration, database, async, serialization, monitoring, file_io, caching, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 17

### core.cors_config
- **Path**: `src/core/cors_config.py`
- **Size**: 254 LOC
- **Complexity**: 25
- **Cohesion**: 0.32
- **Coupling**: 0 dependencies
- **Classes**: 2 (Environment, SecureCORSConfig)
- **Functions**: 18 (get_cors_config, reset_cors_config, get_fastapi_cors_config...)
- **Responsibilities**: authentication, networking, testing, caching, security, configuration, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 4

### core.exceptions
- **Path**: `src/core/exceptions.py`
- **Size**: 603 LOC
- **Complexity**: 49
- **Cohesion**: 0.70
- **Coupling**: 0 dependencies
- **Classes**: 46 (ErrorCode, BaseDeploymentError, InfrastructureError...)
- **Functions**: 52 (wrap_exception, handle_error, __init__...)
- **Responsibilities**: authentication, networking, database, serialization, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 8

### core.gc_optimization
- **Path**: `src/core/gc_optimization.py`
- **Size**: 200 LOC
- **Complexity**: 12
- **Cohesion**: 0.16
- **Coupling**: 0 dependencies
- **Classes**: 2 (GCMetrics, GCOptimizer)
- **Functions**: 14 (with_gc_optimization, periodic_gc_check, get_v8_flags...)
- **Responsibilities**: monitoring, validation, caching, configuration
- **Internal Dependencies**: 0
- **External Dependencies**: 9

### core.lazy_imports
- **Path**: `src/core/lazy_imports.py`
- **Size**: 309 LOC
- **Complexity**: 21
- **Cohesion**: 0.30
- **Coupling**: 1 dependencies
- **Classes**: 1 (LazyImport)
- **Functions**: 19 (lazy_import, optional_import, conditional_import...)
- **Responsibilities**: networking, database, testing, caching, monitoring, configuration, validation
- **Internal Dependencies**: 1
- **External Dependencies**: 9

### core.lifecycle_gc_integration
- **Path**: `src/core/lifecycle_gc_integration.py`
- **Size**: 348 LOC
- **Complexity**: 41
- **Cohesion**: 0.18
- **Coupling**: 0 dependencies
- **Classes**: 4 (LifecycleEvent, GCTriggerStrategy, LifecycleGCManager...)
- **Functions**: 10 (__init__, _setup_default_strategies, set_strategy...)
- **Responsibilities**: networking, configuration, database, async, monitoring, file_io, caching, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 8

### core.log_sanitization
- **Path**: `src/core/log_sanitization.py`
- **Size**: 316 LOC
- **Complexity**: 26
- **Cohesion**: 0.28
- **Coupling**: 0 dependencies
- **Classes**: 4 (SanitizationLevel, LogSanitizerConfig, LogSanitizer...)
- **Functions**: 16 (sanitize_for_logging, sanitize_dict_for_logging, create_safe_log_record...)
- **Responsibilities**: authentication, networking, async, security, serialization, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 6

### core.logging_config
- **Path**: `src/core/logging_config.py`
- **Size**: 505 LOC
- **Complexity**: 26
- **Cohesion**: 0.49
- **Coupling**: 0 dependencies
- **Classes**: 8 (CorrelationFilter, SensitiveDataFilter, StructuredFormatter...)
- **Functions**: 33 (correlation_context, setup_logging, _configure_specialized_loggers...)
- **Responsibilities**: authentication, networking, database, testing, async, security, serialization, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 12

### core.lru_cache
- **Path**: `src/core/lru_cache.py`
- **Size**: 414 LOC
- **Complexity**: 47
- **Cohesion**: 0.57
- **Coupling**: 0 dependencies
- **Classes**: 5 (CacheConfig, CacheEntry, CacheStats...)
- **Functions**: 44 (create_lru_cache, create_ttl_dict, is_expired...)
- **Responsibilities**: configuration, async, monitoring, file_io, caching, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 11

### core.memory_monitor
- **Path**: `src/core/memory_monitor.py`
- **Size**: 420 LOC
- **Complexity**: 41
- **Cohesion**: 0.42
- **Coupling**: 0 dependencies
- **Classes**: 9 (MemoryPressureLevel, MemoryMetrics, MemoryThresholds...)
- **Functions**: 21 (with_memory_monitoring, is_pressure_high, name...)
- **Responsibilities**: networking, configuration, async, monitoring, file_io, caching, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 11

### core.object_pool
- **Path**: `src/core/object_pool.py`
- **Size**: 324 LOC
- **Complexity**: 27
- **Cohesion**: 0.63
- **Coupling**: 0 dependencies
- **Classes**: 12 (PoolStatistics, Poolable, ObjectPool...)
- **Functions**: 40 (update_hit_rate, reset, is_valid...)
- **Responsibilities**: networking, monitoring, file_io, caching, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 8

### core.parallel_executor
- **Path**: `src/core/parallel_executor.py`
- **Size**: 416 LOC
- **Complexity**: 41
- **Cohesion**: 0.23
- **Coupling**: 1 dependencies
- **Classes**: 4 (TaskType, Task, TaskResult...)
- **Functions**: 11 (task_type, __post_init__, __init__...)
- **Responsibilities**: networking, configuration, async, security, monitoring, file_io, caching, validation
- **Internal Dependencies**: 1
- **External Dependencies**: 13

### core.path_validation
- **Path**: `src/core/path_validation.py`
- **Size**: 150 LOC
- **Complexity**: 23
- **Cohesion**: 0.00
- **Coupling**: 1 dependencies
- **Classes**: 0 ()
- **Functions**: 3 (validate_file_path, is_safe_path, sanitize_filename)
- **Responsibilities**: networking, async, security, monitoring, file_io, validation
- **Internal Dependencies**: 1
- **External Dependencies**: 4

### core.retry
- **Path**: `src/core/retry.py`
- **Size**: 419 LOC
- **Complexity**: 72
- **Cohesion**: 0.28
- **Coupling**: 0 dependencies
- **Classes**: 3 (RetryStrategy, RetryConfig, CircuitBreaker)
- **Functions**: 20 (is_retryable_exception, is_retryable_response, check_memory_pressure...)
- **Responsibilities**: networking, database, testing, caching, async, monitoring, configuration, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 16

### core.ssrf_protection
- **Path**: `src/core/ssrf_protection.py`
- **Size**: 465 LOC
- **Complexity**: 52
- **Cohesion**: 0.35
- **Coupling**: 0 dependencies
- **Classes**: 4 (SSRFThreatLevel, SSRFValidationResult, SSRFProtector...)
- **Functions**: 13 (get_ssrf_protector, validate_url_safe, is_url_safe...)
- **Responsibilities**: authentication, networking, database, testing, caching, async, security, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 9

### core.stream_processor
- **Path**: `src/core/stream_processor.py`
- **Size**: 391 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 0 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: configuration, async, serialization, monitoring, file_io, caching, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 11

### database
- **Path**: `src/database/__init__.py`
- **Size**: 98 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 11 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: configuration, database, async, monitoring, caching
- **Internal Dependencies**: 11
- **External Dependencies**: 0

### database.connection
- **Path**: `src/database/connection.py`
- **Size**: 249 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 3 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: networking, database, async, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 3
- **External Dependencies**: 7

### database.init
- **Path**: `src/database/init.py`
- **Size**: 280 LOC
- **Complexity**: 34
- **Cohesion**: 0.17
- **Coupling**: 6 dependencies
- **Classes**: 1 (DatabaseInitializer)
- **Functions**: 2 (__init__, _get_alembic_config)
- **Responsibilities**: networking, configuration, database, async, serialization, monitoring, file_io, caching, validation
- **Internal Dependencies**: 6
- **External Dependencies**: 9

### database.migrations
- **Path**: `src/database/migrations/__init__.py`
- **Size**: 4 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 0 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: database
- **Internal Dependencies**: 0
- **External Dependencies**: 0

### database.migrations.alembic.env
- **Path**: `src/database/migrations/alembic/env.py`
- **Size**: 73 LOC
- **Complexity**: 3
- **Cohesion**: 0.12
- **Coupling**: 2 dependencies
- **Classes**: 0 ()
- **Functions**: 4 (get_database_url, run_migrations_offline, do_run_migrations...)
- **Responsibilities**: authentication, networking, database, async, monitoring, file_io, configuration
- **Internal Dependencies**: 2
- **External Dependencies**: 7

### database.migrations.alembic.versions.20250531_0001_initial_schema
- **Path**: `src/database/migrations/alembic/versions/20250531_0001_initial_schema.py`
- **Size**: 169 LOC
- **Complexity**: 1
- **Cohesion**: 0.50
- **Coupling**: 0 dependencies
- **Classes**: 0 ()
- **Functions**: 2 (upgrade, downgrade)
- **Responsibilities**: authentication, networking, database, security, serialization, monitoring, configuration
- **Internal Dependencies**: 0
- **External Dependencies**: 2

### database.models
- **Path**: `src/database/models.py`
- **Size**: 286 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 0 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: authentication, networking, database, async, security, serialization, monitoring, configuration
- **Internal Dependencies**: 0
- **External Dependencies**: 7

### database.repositories
- **Path**: `src/database/repositories/__init__.py`
- **Size**: 29 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 7 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: monitoring, database, async, configuration
- **Internal Dependencies**: 7
- **External Dependencies**: 0

### database.repositories.audit_repository
- **Path**: `src/database/repositories/audit_repository.py`
- **Size**: 212 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 3 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: database, async, security, monitoring, configuration
- **Internal Dependencies**: 3
- **External Dependencies**: 3

### database.repositories.base
- **Path**: `src/database/repositories/base.py`
- **Size**: 242 LOC
- **Complexity**: 33
- **Cohesion**: 0.50
- **Coupling**: 2 dependencies
- **Classes**: 4 (AsyncRepository, BaseRepository, SQLAlchemyRepository...)
- **Functions**: 5 (__init__, _serialize_json_fields, _deserialize_json_fields...)
- **Responsibilities**: database, async, serialization, monitoring, configuration
- **Internal Dependencies**: 2
- **External Dependencies**: 6

### database.repositories.configuration_repository
- **Path**: `src/database/repositories/configuration_repository.py`
- **Size**: 259 LOC
- **Complexity**: 23
- **Cohesion**: 0.62
- **Coupling**: 4 dependencies
- **Classes**: 2 (ConfigurationRepository, TortoiseConfigurationRepository)
- **Functions**: 2 (__init__, __init__)
- **Responsibilities**: database, async, serialization, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 4
- **External Dependencies**: 4

### database.repositories.deployment_repository
- **Path**: `src/database/repositories/deployment_repository.py`
- **Size**: 269 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 3 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: database, testing, async, monitoring, configuration
- **Internal Dependencies**: 3
- **External Dependencies**: 3

### database.repositories.metrics_repository
- **Path**: `src/database/repositories/metrics_repository.py`
- **Size**: 355 LOC
- **Complexity**: 38
- **Cohesion**: 0.40
- **Coupling**: 3 dependencies
- **Classes**: 2 (MetricsRepository, TortoiseMetricsRepository)
- **Functions**: 3 (__init__, _check_memory_pressure, __init__)
- **Responsibilities**: configuration, database, testing, async, serialization, monitoring, caching, validation
- **Internal Dependencies**: 3
- **External Dependencies**: 6

### database.repositories.query_repository
- **Path**: `src/database/repositories/query_repository.py`
- **Size**: 230 LOC
- **Complexity**: 19
- **Cohesion**: 0.62
- **Coupling**: 3 dependencies
- **Classes**: 2 (QueryHistoryRepository, TortoiseQueryHistoryRepository)
- **Functions**: 2 (__init__, __init__)
- **Responsibilities**: authentication, networking, database, async, serialization, monitoring, configuration
- **Internal Dependencies**: 3
- **External Dependencies**: 4

### database.repositories.user_repository
- **Path**: `src/database/repositories/user_repository.py`
- **Size**: 236 LOC
- **Complexity**: 20
- **Cohesion**: 0.50
- **Coupling**: 4 dependencies
- **Classes**: 2 (UserRepository, TortoiseUserRepository)
- **Functions**: 4 (__init__, _hash_api_key, __init__...)
- **Responsibilities**: authentication, networking, database, async, security, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 4
- **External Dependencies**: 5

### database.tortoise_config
- **Path**: `src/database/tortoise_config.py`
- **Size**: 61 LOC
- **Complexity**: 3
- **Cohesion**: 0.00
- **Coupling**: 0 dependencies
- **Classes**: 0 ()
- **Functions**: 1 (get_database_url)
- **Responsibilities**: configuration, database, testing, async, caching
- **Internal Dependencies**: 0
- **External Dependencies**: 2

### database.utils
- **Path**: `src/database/utils.py`
- **Size**: 369 LOC
- **Complexity**: 32
- **Cohesion**: 0.35
- **Coupling**: 3 dependencies
- **Classes**: 4 (DatabaseBackup, DatabaseRestore, DatabaseOptimizer...)
- **Functions**: 6 (validate_identifier, validate_table_name, validate_column_name...)
- **Responsibilities**: authentication, networking, database, caching, async, security, serialization, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 3
- **External Dependencies**: 11

### mcp
- **Path**: `src/mcp/__init__.py`
- **Size**: 27 LOC
- **Complexity**: 2
- **Cohesion**: 0.00
- **Coupling**: 4 dependencies
- **Classes**: 0 ()
- **Functions**: 2 (create_mcp_manager, get_server_registry)
- **Responsibilities**: networking, database
- **Internal Dependencies**: 4
- **External Dependencies**: 0

### mcp.base
- **Path**: `src/mcp/base/__init__.py`
- **Size**: 2 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 0 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: networking
- **Internal Dependencies**: 0
- **External Dependencies**: 0

### mcp.client
- **Path**: `src/mcp/client.py`
- **Size**: 323 LOC
- **Complexity**: 51
- **Cohesion**: 0.50
- **Coupling**: 2 dependencies
- **Classes**: 4 (MCPTransport, HTTPTransport, WebSocketTransport...)
- **Functions**: 4 (__init__, __init__, set_notification_handler...)
- **Responsibilities**: networking, configuration, async, serialization, monitoring, caching, validation
- **Internal Dependencies**: 2
- **External Dependencies**: 10

### mcp.communication
- **Path**: `src/mcp/communication/__init__.py`
- **Size**: 8 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 1 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: monitoring, networking
- **Internal Dependencies**: 1
- **External Dependencies**: 0

### mcp.communication.hub_server
- **Path**: `src/mcp/communication/hub_server.py`
- **Size**: 624 LOC
- **Complexity**: 65
- **Cohesion**: 0.25
- **Coupling**: 2 dependencies
- **Classes**: 5 (Priority, Channel, Message...)
- **Functions**: 9 (__init__, get_server_info, get_tools...)
- **Responsibilities**: authentication, networking, async, security, serialization, monitoring, configuration, validation
- **Internal Dependencies**: 2
- **External Dependencies**: 13

### mcp.communication.slack_server
- **Path**: `src/mcp/communication/slack_server.py`
- **Size**: 742 LOC
- **Complexity**: 65
- **Cohesion**: 0.25
- **Coupling**: 4 dependencies
- **Classes**: 4 (AlertPriority, RateLimitConfig, CircuitBreakerConfig...)
- **Functions**: 10 (__init__, get_server_info, get_tools...)
- **Responsibilities**: authentication, networking, async, security, serialization, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 4
- **External Dependencies**: 15

### mcp.devops
- **Path**: `src/mcp/devops/__init__.py`
- **Size**: 2 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 0 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: networking
- **Internal Dependencies**: 0
- **External Dependencies**: 0

### mcp.devops_servers
- **Path**: `src/mcp/devops_servers.py`
- **Size**: 908 LOC
- **Complexity**: 87
- **Cohesion**: 0.35
- **Coupling**: 1 dependencies
- **Classes**: 2 (AzureDevOpsMCPServer, WindowsSystemMCPServer)
- **Functions**: 8 (sanitize_input, validate_command, __init__...)
- **Responsibilities**: authentication, networking, database, testing, async, security, serialization, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 1
- **External Dependencies**: 12

### mcp.infrastructure
- **Path**: `src/mcp/infrastructure/__init__.py`
- **Size**: 7 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 1 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: networking
- **Internal Dependencies**: 1
- **External Dependencies**: 0

### mcp.infrastructure.commander_server
- **Path**: `src/mcp/infrastructure/commander_server.py`
- **Size**: 571 LOC
- **Complexity**: 53
- **Cohesion**: 0.22
- **Coupling**: 2 dependencies
- **Classes**: 2 (CircuitBreaker, InfrastructureCommanderMCP)
- **Functions**: 14 (with_retry, __init__, call_allowed...)
- **Responsibilities**: networking, database, testing, caching, async, security, serialization, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 2
- **External Dependencies**: 17

### mcp.infrastructure_servers
- **Path**: `src/mcp/infrastructure_servers.py`
- **Size**: 1588 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 4 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: authentication, networking, testing, caching, async, security, serialization, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 4
- **External Dependencies**: 11

### mcp.manager
- **Path**: `src/mcp/manager.py`
- **Size**: 489 LOC
- **Complexity**: 55
- **Cohesion**: 0.28
- **Coupling**: 9 dependencies
- **Classes**: 5 (MCPToolCall, MCPContext, MCPManager...)
- **Functions**: 20 (get_mcp_manager, add_tool_call, get_tool_history...)
- **Responsibilities**: networking, configuration, database, async, monitoring, caching, validation
- **Internal Dependencies**: 9
- **External Dependencies**: 7

### mcp.monitoring
- **Path**: `src/mcp/monitoring/__init__.py`
- **Size**: 7 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 1 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: monitoring, networking, file_io, security
- **Internal Dependencies**: 1
- **External Dependencies**: 0

### mcp.monitoring.prometheus_server
- **Path**: `src/mcp/monitoring/prometheus_server.py`
- **Size**: 607 LOC
- **Complexity**: 70
- **Cohesion**: 0.41
- **Coupling**: 6 dependencies
- **Classes**: 6 (RateLimiter, CircuitBreaker, PrometheusMonitoringMCP...)
- **Functions**: 17 (validate_promql, validate_timestamp, __init__...)
- **Responsibilities**: authentication, networking, database, testing, caching, async, security, serialization, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 6
- **External Dependencies**: 14

### mcp.protocols
- **Path**: `src/mcp/protocols.py`
- **Size**: 387 LOC
- **Complexity**: 25
- **Cohesion**: 0.37
- **Coupling**: 1 dependencies
- **Classes**: 15 (MCPMessageType, MCPMethod, MCPToolParameter...)
- **Functions**: 12 (to_claude_format, is_error, raise_for_error...)
- **Responsibilities**: authentication, networking, database, async, security, serialization, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 1
- **External Dependencies**: 8

### mcp.security
- **Path**: `src/mcp/security/__init__.py`
- **Size**: 27 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 2 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: authentication, networking, security
- **Internal Dependencies**: 2
- **External Dependencies**: 0

### mcp.security.auth_middleware
- **Path**: `src/mcp/security/auth_middleware.py`
- **Size**: 450 LOC
- **Complexity**: 52
- **Cohesion**: 0.35
- **Coupling**: 0 dependencies
- **Classes**: 5 (UserRole, Permission, AuthContext...)
- **Functions**: 12 (require_auth, get_auth_middleware, initialize_auth_middleware...)
- **Responsibilities**: authentication, networking, database, caching, async, security, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 14

### mcp.security.sast_server
- **Path**: `src/mcp/security/sast_server.py`
- **Size**: 594 LOC
- **Complexity**: 64
- **Cohesion**: 0.07
- **Coupling**: 2 dependencies
- **Classes**: 1 (SASTMCPServer)
- **Functions**: 6 (__init__, get_server_info, get_tools...)
- **Responsibilities**: authentication, networking, database, testing, caching, async, security, serialization, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 2
- **External Dependencies**: 12

### mcp.security.scanner_server
- **Path**: `src/mcp/security/scanner_server.py`
- **Size**: 604 LOC
- **Complexity**: 94
- **Cohesion**: 0.38
- **Coupling**: 2 dependencies
- **Classes**: 4 (SecurityHardening, RateLimiter, CircuitBreaker...)
- **Functions**: 8 (sanitize_input, calculate_entropy, secure_hash...)
- **Responsibilities**: authentication, networking, database, testing, caching, async, security, serialization, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 2
- **External Dependencies**: 16

### mcp.security.supply_chain_server
- **Path**: `src/mcp/security/supply_chain_server.py`
- **Size**: 731 LOC
- **Complexity**: 95
- **Cohesion**: 0.04
- **Coupling**: 2 dependencies
- **Classes**: 1 (SupplyChainSecurityMCPServer)
- **Functions**: 12 (__init__, _initialize_vulnerability_db, get_server_info...)
- **Responsibilities**: networking, database, testing, caching, async, security, serialization, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 2
- **External Dependencies**: 13

### mcp.servers
- **Path**: `src/mcp/servers.py`
- **Size**: 442 LOC
- **Complexity**: 23
- **Cohesion**: 0.45
- **Coupling**: 11 dependencies
- **Classes**: 2 (BraveMCPServer, MCPServerRegistry)
- **Functions**: 8 (__init__, _get_all_tools, __init__...)
- **Responsibilities**: authentication, networking, database, async, security, serialization, monitoring, configuration, validation
- **Internal Dependencies**: 11
- **External Dependencies**: 7

### mcp.storage
- **Path**: `src/mcp/storage/__init__.py`
- **Size**: 6 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 2 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: networking
- **Internal Dependencies**: 2
- **External Dependencies**: 0

### mcp.storage.cloud_storage_server
- **Path**: `src/mcp/storage/cloud_storage_server.py`
- **Size**: 606 LOC
- **Complexity**: 53
- **Cohesion**: 0.33
- **Coupling**: 3 dependencies
- **Classes**: 5 (StorageProvider, DataClassification, StorageClass...)
- **Functions**: 4 (__init__, get_server_info, get_tools...)
- **Responsibilities**: authentication, networking, caching, async, security, serialization, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 3
- **External Dependencies**: 13

### mcp.storage.s3_server
- **Path**: `src/mcp/storage/s3_server.py`
- **Size**: 391 LOC
- **Complexity**: 30
- **Cohesion**: 0.25
- **Coupling**: 2 dependencies
- **Classes**: 1 (S3StorageMCPServer)
- **Functions**: 3 (__init__, get_server_info, get_tools)
- **Responsibilities**: networking, async, serialization, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 2
- **External Dependencies**: 7

### monitoring
- **Path**: `src/monitoring/__init__.py`
- **Size**: 90 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 0 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: monitoring, networking, validation, async
- **Internal Dependencies**: 0
- **External Dependencies**: 0

### monitoring.alerts
- **Path**: `src/monitoring/alerts.py`
- **Size**: 419 LOC
- **Complexity**: 34
- **Cohesion**: 0.43
- **Coupling**: 0 dependencies
- **Classes**: 5 (AlertSeverity, AlertState, AlertRule...)
- **Functions**: 22 (get_alert_manager, check_alert, resolve_alert...)
- **Responsibilities**: networking, configuration, async, serialization, monitoring, file_io, caching, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 11

### monitoring.api
- **Path**: `src/monitoring/api.py`
- **Size**: 294 LOC
- **Complexity**: 24
- **Cohesion**: 0.00
- **Coupling**: 0 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: networking, database, testing, async, serialization, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 4

### monitoring.enhanced_memory_metrics
- **Path**: `src/monitoring/enhanced_memory_metrics.py`
- **Size**: 571 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 0 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: networking, testing, async, monitoring, file_io, caching, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 15

### monitoring.health
- **Path**: `src/monitoring/health.py`
- **Size**: 346 LOC
- **Complexity**: 37
- **Cohesion**: 0.45
- **Coupling**: 0 dependencies
- **Classes**: 4 (HealthStatus, HealthCheckResult, HealthReport...)
- **Functions**: 17 (get_health_checker, register_health_check, health_check...)
- **Responsibilities**: configuration, async, serialization, monitoring, file_io, caching, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 8

### monitoring.mcp_integration
- **Path**: `src/monitoring/mcp_integration.py`
- **Size**: 306 LOC
- **Complexity**: 36
- **Cohesion**: 0.00
- **Coupling**: 0 dependencies
- **Classes**: 1 (MCPMonitoringIntegration)
- **Functions**: 3 (__init__, _register_mcp_health_checks, _register_alert_handlers)
- **Responsibilities**: networking, database, testing, async, security, serialization, monitoring, file_io, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 3

### monitoring.memory_alerts
- **Path**: `src/monitoring/memory_alerts.py`
- **Size**: 481 LOC
- **Complexity**: 53
- **Cohesion**: 0.28
- **Coupling**: 0 dependencies
- **Classes**: 5 (AlertLevel, AlertType, AlertRule...)
- **Functions**: 13 (__init__, _create_default_rules, _create_alert_message...)
- **Responsibilities**: networking, configuration, async, serialization, monitoring, file_io, caching, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 10

### monitoring.memory_integration
- **Path**: `src/monitoring/memory_integration.py`
- **Size**: 268 LOC
- **Complexity**: 15
- **Cohesion**: 0.12
- **Coupling**: 0 dependencies
- **Classes**: 1 (MemoryMonitoringIntegration)
- **Functions**: 7 (get_memory_integration, get_monitoring_config, __init__...)
- **Responsibilities**: networking, configuration, testing, async, monitoring, caching, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 4

### monitoring.memory_monitor
- **Path**: `src/monitoring/memory_monitor.py`
- **Size**: 355 LOC
- **Complexity**: 46
- **Cohesion**: 0.38
- **Coupling**: 0 dependencies
- **Classes**: 3 (MemorySnapshot, MemoryTrend, MemoryMonitor)
- **Functions**: 17 (get_memory_monitor, shutdown_memory_monitor, pressure_level...)
- **Responsibilities**: networking, configuration, testing, async, monitoring, file_io, caching
- **Internal Dependencies**: 0
- **External Dependencies**: 12

### monitoring.memory_response
- **Path**: `src/monitoring/memory_response.py`
- **Size**: 504 LOC
- **Complexity**: 65
- **Cohesion**: 0.21
- **Coupling**: 0 dependencies
- **Classes**: 5 (ResponseType, ResponseTrigger, ResponseAction...)
- **Functions**: 12 (__post_init__, __post_init__, __init__...)
- **Responsibilities**: networking, configuration, database, async, monitoring, file_io, caching, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 13

### monitoring.metrics
- **Path**: `src/monitoring/metrics.py`
- **Size**: 514 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 0 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: authentication, networking, database, testing, caching, async, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 13

### monitoring.setup_monitoring
- **Path**: `src/monitoring/setup_monitoring.py`
- **Size**: 313 LOC
- **Complexity**: 27
- **Cohesion**: 0.00
- **Coupling**: 0 dependencies
- **Classes**: 0 ()
- **Functions**: 9 (check_dependencies, install_missing_dependencies, setup_custom_health_checks...)
- **Responsibilities**: networking, database, testing, async, security, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 14

### monitoring.sla
- **Path**: `src/monitoring/sla.py`
- **Size**: 342 LOC
- **Complexity**: 23
- **Cohesion**: 0.34
- **Coupling**: 0 dependencies
- **Classes**: 4 (SLAType, SLAObjective, SLAReport...)
- **Functions**: 15 (get_sla_tracker, add_sla_objective, get_sla_report...)
- **Responsibilities**: networking, database, testing, async, serialization, monitoring, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 9

### monitoring.tracing
- **Path**: `src/monitoring/tracing.py`
- **Size**: 308 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 0 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: networking, configuration, database, async, monitoring, caching
- **Internal Dependencies**: 0
- **External Dependencies**: 7

### platform
- **Path**: `src/platform/__init__.py`
- **Size**: 3 LOC
- **Complexity**: 1
- **Cohesion**: 0.00
- **Coupling**: 1 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: None identified
- **Internal Dependencies**: 1
- **External Dependencies**: 0

### platform.wsl_integration
- **Path**: `src/platform/wsl_integration.py`
- **Size**: 363 LOC
- **Complexity**: 54
- **Cohesion**: 0.38
- **Coupling**: 1 dependencies
- **Classes**: 1 (WSLEnvironment)
- **Functions**: 20 (is_wsl, convert_path, run_cross_platform...)
- **Responsibilities**: networking, configuration, testing, serialization, monitoring, file_io, caching, validation
- **Internal Dependencies**: 1
- **External Dependencies**: 9

### utils
- **Path**: `src/utils/__init__.py`
- **Size**: 26 LOC
- **Complexity**: 2
- **Cohesion**: 0.00
- **Coupling**: 0 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: database, security, monitoring, caching, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 0

### utils.__main__
- **Path**: `src/utils/__main__.py`
- **Size**: 9 LOC
- **Complexity**: 2
- **Cohesion**: 0.00
- **Coupling**: 0 dependencies
- **Classes**: 0 ()
- **Functions**: 0 ()
- **Responsibilities**: configuration
- **Internal Dependencies**: 0
- **External Dependencies**: 1

### utils.database
- **Path**: `src/utils/database.py`
- **Size**: 748 LOC
- **Complexity**: 65
- **Cohesion**: 0.18
- **Coupling**: 0 dependencies
- **Classes**: 5 (DatabaseConfig, QueryResult, MigrationResult...)
- **Functions**: 6 (main, __init__, _track_query_performance...)
- **Responsibilities**: authentication, configuration, database, async, serialization, monitoring, file_io, caching
- **Internal Dependencies**: 0
- **External Dependencies**: 16

### utils.git
- **Path**: `src/utils/git.py`
- **Size**: 591 LOC
- **Complexity**: 61
- **Cohesion**: 0.31
- **Coupling**: 0 dependencies
- **Classes**: 4 (GitRemote, GitStatus, PushResult...)
- **Functions**: 20 (main, __init__, _validate_git_repo...)
- **Responsibilities**: authentication, networking, database, testing, caching, async, security, serialization, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 12

### utils.imports
- **Path**: `src/utils/imports.py`
- **Size**: 481 LOC
- **Complexity**: 104
- **Cohesion**: 0.32
- **Coupling**: 0 dependencies
- **Classes**: 3 (ImportIssue, ImportAnalysisResult, ImportManager)
- **Functions**: 16 (main, __post_init__, __init__...)
- **Responsibilities**: networking, configuration, testing, async, serialization, monitoring, file_io, caching, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 9

### utils.integration
- **Path**: `src/utils/integration.py`
- **Size**: 609 LOC
- **Complexity**: 78
- **Cohesion**: 0.19
- **Coupling**: 0 dependencies
- **Classes**: 2 (IntegrationResult, UtilityManager)
- **Functions**: 14 (main, __post_init__, __init__...)
- **Responsibilities**: database, testing, caching, async, security, serialization, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 11

### utils.monitoring
- **Path**: `src/utils/monitoring.py`
- **Size**: 650 LOC
- **Complexity**: 72
- **Cohesion**: 0.23
- **Coupling**: 0 dependencies
- **Classes**: 5 (MemorySnapshot, MemoryLeak, PerformanceMetrics...)
- **Functions**: 21 (main, __init__, start_monitoring...)
- **Responsibilities**: configuration, async, serialization, monitoring, file_io, caching, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 16

### utils.security
- **Path**: `src/utils/security.py`
- **Size**: 1153 LOC
- **Complexity**: 206
- **Cohesion**: 0.17
- **Coupling**: 0 dependencies
- **Classes**: 4 (SecurityVulnerability, SecurityScanResult, ComplianceCheckResult...)
- **Functions**: 43 (main, add_vulnerability, __init__...)
- **Responsibilities**: authentication, networking, database, testing, async, security, serialization, monitoring, file_io, configuration, validation
- **Internal Dependencies**: 0
- **External Dependencies**: 14

## 🎯 RECOMMENDATIONS

### High Priority Issues
- 🔄 **Break Circular Dependencies**: Refactor modules to eliminate circular imports
- 🏗️ **Fix Layer Violations**: Ensure lower layers don't depend on higher layers
- 🔧 **Improve Cohesion**: Refactor 104 modules with low cohesion
- 🔗 **Reduce Coupling**: Decouple 3 highly coupled modules
- 🏛️ **Improve SOLID Compliance**: Focus on dependency injection and interface design

### Architectural Improvements

1. **Dependency Injection**: Implement more dependency injection patterns
2. **Interface Segregation**: Create smaller, more focused interfaces
3. **Plugin Architecture**: Consider plugin systems for extensibility
4. **Configuration Management**: Centralize configuration handling
5. **Error Handling**: Standardize error handling patterns across modules

### Refactoring Priorities

1. **High**: Address circular dependencies and layer violations
2. **Medium**: Improve modules with low cohesion scores
3. **Low**: Optimize module sizes and reduce unnecessary coupling

## 📊 METRICS SUMMARY

| Metric | Value | Target | Status |
|--------|-------|--------|--------|
| Modularity Score | 0.10 | >0.8 | ❌ |
| Interface Quality | 0.47 | >0.7 | ❌ |
| SOLID Compliance | 0.50 | >0.7 | ❌ |
| Circular Dependencies | 4 | 0 | ❌ |
| Layer Violations | 3 | 0 | ❌ |

---
*Generated by AGENT 6: Modularity and Architecture Analysis*
