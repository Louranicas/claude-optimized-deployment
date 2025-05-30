# PRIME DIRECTIVE - CODE Project Context

**Project**: Claude-Optimized Deployment Engine (CODE)  
**Version**: 0.1.0  
**Last Updated**: May 30, 2025  
**Status**: 15% Complete (Circle of Experts functional)

## 🎯 PROJECT REALITY CHECK

**What CODE IS Today**:
- ✅ A functional multi-AI consultation system (Circle of Experts)
- ✅ Video-to-documentation processor
- ✅ Well-documented project structure
- ✅ Git optimization setup

**What CODE IS NOT Yet**:
- ❌ Cannot deploy infrastructure
- ❌ No Terraform/Kubernetes integration
- ❌ No cloud provider connections
- ❌ Natural language deployment is aspirational

## 🏗️ CORE DEVELOPMENT PRINCIPLES

### 1. Language Standards
- **GOLD STANDARD**: Rust 🦀 and Python 🐍
- **Rust**: Performance-critical components, core engine, CLI tools
- **Python**: AI/ML features, data processing, rapid prototyping
- **Others**: Only with strong technical justification + integration plan

### 2. Code Quality Standards
- **Test Coverage**: Minimum 80% for new code
- **Documentation**: Every public function/module documented
- **Type Safety**: Full type hints in Python, strict Rust types
- **Error Handling**: Explicit, never silent failures
- **Performance**: Profile before optimizing

### 3. Architecture Principles
- **Microservices**: Independent, deployable services
- **API-First**: Clear contracts between components
- **Cloud-Native**: Containerized, scalable, resilient
- **Security-First**: Never compromise on security
- **Observable**: Metrics, logs, traces for everything

## 📁 PROJECT STRUCTURE

```
claude_optimized_deployment/
├── .claude/                 # Claude-specific configuration
│   ├── prime.md            # THIS FILE - Primary context
│   ├── Claude.md           # Configuration and guidelines
│   └── commands/           # Custom Claude commands
├── src/                    # Python source code
│   ├── circle_of_experts/  # WORKING: Multi-AI system
│   └── deployment_engine/  # TODO: Core engine
├── rust_core/              # Rust implementation (planned)
├── docs/                   # Documentation
├── scripts/                # Automation scripts
│   └── git/               # Git optimization tools
└── tests/                 # Test suites
```

## 🚀 CURRENT PRIORITIES

### Phase 1: Foundation (Current)
1. **Complete Rust core structure** - Set up Cargo workspace
2. **Basic deployment POC** - Deploy simple Docker container
3. **State management** - Design state tracking system
4. **API design** - Define REST/gRPC interfaces

### Phase 2: Integration (Next 4 weeks)
1. **Terraform wrapper** - Basic Terraform execution
2. **Docker integration** - Container management
3. **Simple CLI** - Basic command interface
4. **Error handling** - Robust error management

### Phase 3: Intelligence (Weeks 5-8)
1. **Connect Circle of Experts** - AI-powered decisions
2. **Natural language parser** - Intent recognition
3. **Cost optimization** - Resource recommendations
4. **Security scanning** - Automated security checks

## 💻 DEVELOPMENT WORKFLOW

### 1. Before Writing Code
```bash
# Always start with research
claude "Research best practices for [FEATURE]"

# Check existing code
git grep -i "related_term"
find . -name "*.py" -o -name "*.rs" | xargs grep -l "pattern"

# Run health check
./scripts/git/git-doctor.sh
```

### 2. Writing Code
```bash
# Use semantic branches
git-feature CODE-XXX feature-description

# Commit with conventional format
git commit -m "feat(scope): add new capability"

# Run tests continuously
pytest --watch  # Python
cargo watch -x test  # Rust
```

### 3. Code Standards

#### Python Example
```python
"""Module documentation with purpose and usage."""
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

class DeploymentEngine:
    """
    Handles infrastructure deployment operations.
    
    Attributes:
        config: Deployment configuration
        state: Current deployment state
    """
    
    def deploy(
        self,
        manifest: Dict[str, Any],
        *,  # Force keyword-only arguments
        dry_run: bool = False,
        parallel: bool = True
    ) -> DeploymentResult:
        """
        Deploy infrastructure from manifest.
        
        Args:
            manifest: Deployment manifest
            dry_run: Simulate deployment only
            parallel: Enable parallel operations
            
        Returns:
            DeploymentResult with status and details
            
        Raises:
            DeploymentError: If deployment fails
        """
        logger.info(f"Starting deployment: dry_run={dry_run}")
        # Implementation
```

#### Rust Example
```rust
//! Core deployment engine module

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Deployment configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentConfig {
    /// Target environment
    pub environment: Environment,
    /// Resource specifications
    pub resources: Vec<Resource>,
}

impl DeploymentEngine {
    /// Create new deployment engine
    pub fn new(config: DeploymentConfig) -> Result<Self> {
        info!("Initializing deployment engine");
        // Implementation
    }
    
    /// Execute deployment with given manifest
    pub async fn deploy(
        &self,
        manifest: Manifest,
        options: DeployOptions,
    ) -> Result<DeploymentResult> {
        info!("Starting deployment: {:?}", options);
        // Implementation
    }
}
```

## 🔧 INTEGRATION PATTERNS

### Service Communication
1. **Internal**: gRPC with protobuf
2. **External**: REST with OpenAPI
3. **Async**: Redis pub/sub or RabbitMQ
4. **Storage**: PostgreSQL + Redis cache

### Deployment Strategy
```yaml
# All services containerized
services:
  rust-core:
    language: rust
    build: multi-stage
    size: <50MB
    
  python-ai:
    language: python
    build: slim
    size: <500MB
    
  web-ui:
    language: typescript
    build: static
    size: <10MB
```

## ⚠️ CRITICAL CONSTRAINTS

1. **Security**: No secrets in code, logs, or errors
2. **Privacy**: No user data in logs or metrics
3. **Cost**: Monitor API usage, especially AI calls
4. **Performance**: <100ms response time goal
5. **Reliability**: 99.9% uptime target

## 📊 SUCCESS METRICS

### Technical KPIs
- Deployment Success Rate: >95%
- Average Deployment Time: <5 minutes
- Test Coverage: >80%
- API Response Time: <100ms p95
- Error Rate: <0.1%

### Business KPIs
- Developer Adoption: >80% of team
- Time to Production: 50% reduction
- Cost Savings: 30% infrastructure costs
- User Satisfaction: >4.5/5

## 🚨 COMMON PITFALLS TO AVOID

1. **Over-engineering**: Start simple, iterate
2. **Premature optimization**: Profile first
3. **Ignoring errors**: Handle every error explicitly
4. **Poor naming**: Be descriptive, not clever
5. **Missing tests**: Test as you code
6. **Assuming state**: Always verify
7. **Tight coupling**: Keep services independent

## 🎯 WHEN HELPING WITH CODE

### Always Consider:
1. **Does this align with Rust/Python gold standard?**
2. **Is this the simplest solution that works?**
3. **Have we tested edge cases?**
4. **Is error handling comprehensive?**
5. **Will this integrate smoothly?**
6. **Is it observable and debuggable?**
7. **Does it follow project conventions?**

### Response Format:
1. **Acknowledge current reality** (15% complete)
2. **Provide working solution** for current state
3. **Suggest future improvements** when relevant
4. **Include tests** with implementation
5. **Document assumptions** clearly

## 🔄 CONTINUOUS IMPROVEMENT

### Daily Practices
- Run `git-doctor` health check
- Review performance metrics
- Update documentation
- Clean up technical debt

### Weekly Reviews
- Architecture decisions
- Performance bottlenecks
- Security vulnerabilities
- Team feedback

## 📝 REMEMBER

> "CODE is a journey from a working Circle of Experts to a full deployment engine. Every commit should move us forward while maintaining what works today."

**Current Focus**: Make deployment work with Docker as POC  
**Next Milestone**: Deploy a container via natural language  
**North Star**: "Deploy my app to production" just works

---

*This is the prime directive. When in doubt, refer back to these principles.*
