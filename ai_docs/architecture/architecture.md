# CODE Architecture Context for Claude

## System Overview

The Claude-Optimized Deployment Engine (CODE) is a natural language infrastructure deployment system that bridges human intent with cloud infrastructure provisioning. It uses AI to interpret deployment requests and orchestrates multiple open-source tools to execute them.

## Core Architecture Principles

### 1. Natural Language First
- Users describe infrastructure needs in plain English
- AI interprets intent and generates deployment specifications
- Fallback to structured commands when needed

### 2. Open Source Foundation
- 100% built on open source tools
- No vendor lock-in
- Community-driven development

### 3. Cross-Platform by Design
- Native WSL2 integration for Windows developers
- Linux-first development approach
- Consistent experience across platforms

## System Components

### 1. Natural Language Interface Layer
```
Purpose: Convert human language to infrastructure specifications
Technologies: 
- Ollama (local LLM deployment)
- LangChain (LLM application framework)
- FastAPI (REST API)

Flow:
User Input → LLM Processing → Intent Recognition → Spec Generation → Validation
```

### 2. Orchestration Engine
```
Purpose: Coordinate deployment across multiple tools
Technologies:
- Python asyncio (parallel execution)
- Kubernetes operators
- GitHub Actions

Key Features:
- Dependency resolution
- Parallel task execution
- State management
- Rollback capabilities
```

### 3. Infrastructure Providers
```
Terraform/OpenTofu Wrapper:
- Infrastructure as Code
- Multi-cloud support (AWS, Azure, GCP)
- State management
- Module system

Kubernetes Client:
- Container orchestration
- Helm chart management
- Service mesh integration
- Auto-scaling configuration
```

### 4. Security Layer
```
Components:
- Falco (runtime security)
- OPA (policy as code)
- Trivy (vulnerability scanning)
- Secret rotation automation

Principles:
- Zero-trust architecture
- Least privilege access
- Continuous compliance checking
- Automated remediation
```

### 5. Monitoring & Observability
```
Stack:
- Prometheus (metrics)
- Grafana (visualization)
- Loki (logs)
- Jaeger (distributed tracing)

Integration:
- Auto-generated dashboards
- Intelligent alerting
- Cost tracking
- Performance optimization
```

## Data Flow

### Deployment Request Flow
```
1. User: "Deploy a web app with database to staging"
2. NLP Layer: Interprets request
3. Specification Generator: Creates deployment spec
4. Validation: Checks security, cost, compliance
5. Orchestrator: Plans execution strategy
6. Providers: Execute in parallel
   - Terraform: Provision infrastructure
   - Kubernetes: Deploy containers
   - Monitoring: Set up observability
7. Feedback: Report status to user
```

### State Management
```
- Git as source of truth (GitOps)
- Terraform state in S3/GCS with locking
- Kubernetes CRDs for application state
- Event sourcing for audit trail
```

## WSL Integration Architecture

### File System Bridge
```
Windows Host:
C:\Users\{user}\Desktop\My Programming\claude_optimized_deployment

WSL Ubuntu:
/mnt/c/Users/{user}/Desktop/My Programming/claude_optimized_deployment

Optimizations:
- Use WSL2 native filesystem for performance
- Symbolic links for frequently accessed files
- Automated path translation
```

### Process Communication
```
Windows → WSL:
- PowerShell cmdlets invoke WSL commands
- Named pipes for real-time communication
- Shared memory for large data transfer

WSL → Windows:
- Windows Terminal integration
- VS Code Remote-WSL
- Docker Desktop integration
```

## Parallel Execution Strategy

### Task Categories
```
1. I/O Bound (use asyncio):
   - API calls
   - File operations
   - Network requests

2. CPU Bound (use multiprocessing):
   - Template rendering
   - Cryptographic operations
   - Data processing

3. Mixed (hybrid approach):
   - Deployment orchestration
   - Build processes
   - Testing
```

### Execution Model
```python
class ParallelExecutor:
    async def execute_stage(self, tasks: List[Task]):
        # Group tasks by dependency
        independent_tasks = self.get_independent_tasks(tasks)
        
        # Execute in parallel
        results = await asyncio.gather(*[
            self.execute_task(task) for task in independent_tasks
        ])
        
        # Process dependent tasks
        for task in self.get_dependent_tasks(tasks):
            await self.execute_task(task, results)
```

## Claude Code Optimization

### Context Management
```
1. Project Context: Architecture, patterns, conventions
2. Session Context: Current task, recent actions
3. Historical Context: Past deployments, learned patterns
```

### Code Generation Patterns
```
1. Explicit Comments:
   # CLAUDE-CONTEXT: This function handles X
   # INPUT: Expected input format
   # OUTPUT: Expected output format
   # DEPENDENCIES: Required services

2. Self-Documenting Code:
   - Descriptive variable names
   - Type hints everywhere
   - Docstrings with examples

3. Error Context:
   - Detailed error messages
   - Suggested fixes
   - Related documentation links
```

## Security Architecture

### Defense in Depth
```
1. Network Security:
   - Service mesh (Istio/Cilium)
   - Network policies
   - TLS everywhere

2. Application Security:
   - OWASP compliance
   - Input validation
   - Output encoding

3. Infrastructure Security:
   - Least privilege IAM
   - Encrypted secrets
   - Audit logging

4. Supply Chain Security:
   - Signed images
   - SBOM generation
   - Vulnerability scanning
```

## Performance Considerations

### Optimization Strategies
```
1. Caching:
   - LLM response caching
   - Terraform plan caching
   - Container image caching

2. Parallel Processing:
   - Concurrent API calls
   - Parallel terraform applies
   - Distributed builds

3. Resource Management:
   - Connection pooling
   - Memory limits
   - CPU throttling
```

## Failure Handling

### Graceful Degradation
```
1. LLM Failure:
   - Fallback to template matching
   - Use cached responses
   - Switch to structured input

2. Provider Failure:
   - Retry with backoff
   - Circuit breaker pattern
   - Alternative providers

3. Partial Failure:
   - Rollback capabilities
   - State recovery
   - Manual intervention hooks
```

## Extension Points

### Plugin Architecture
```
1. Provider Plugins:
   - Custom cloud providers
   - On-premise integration
   - Specialized services

2. Security Plugins:
   - Custom scanners
   - Compliance checkers
   - Policy engines

3. Monitor Plugins:
   - Custom metrics
   - Specialized dashboards
   - Alert channels
```

## Best Practices for Claude

When working with this codebase:
1. Always provide context in comments
2. Use descriptive function and variable names
3. Include type hints for all parameters
4. Write comprehensive docstrings
5. Add examples in documentation
6. Explain complex logic step-by-step
7. Reference related components
8. Include error handling context
