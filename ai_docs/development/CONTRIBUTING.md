# Contributing to CODE

First off, thank you for considering contributing to CODE! We're building an AI-powered deployment engine with MCP integration, Circle of Experts, and advanced security features.

## 🤝 How to Contribute

### Reporting Bugs
- Create detailed bug reports with reproduction steps
- Include environment details (OS, Python version, dependencies)
- Provide logs and error messages when applicable
- Use error codes from our exception hierarchy (see ERROR_HANDLING_BEST_PRACTICES.md)
- Include performance impact if applicable

### Suggesting Enhancements
- Propose enhancements with clear use cases and benefits
- Consider existing functionality and integration points
- Provide implementation suggestions when possible
- Consider NAM/ANAM patterns for optimization
- Evaluate security implications

### Pull Requests
1. Fork the repo and create your branch from `main`
2. If you've added code that should be tested, add tests
3. Ensure the test suite passes
4. Make sure your code follows our style guidelines
5. Run security checks and dependency validation
6. Update documentation if needed
7. Issue that pull request!

## 🛠️ Development Setup

### Prerequisites
- Python 3.10+ (3.11+ recommended for performance)
- Docker Desktop (latest version)
- Git with LFS enabled
- Node.js 16+ (for MCP servers)
- (Optional) Rust toolchain for performance modules
- (Optional) Ollama for local AI models

### Environment Setup
```bash
# Clone the repository
git clone https://github.com/louranicas/claude-optimized-deployment.git
cd claude-optimized-deployment

# Use our automated setup
make dev-setup

# OR manual setup:
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install core dependencies only (recommended)
pip install -e .

# OR install with specific feature sets
pip install -e ".[dev]"  # Development tools
pip install -e ".[ai]"   # AI/ML features (heavy)
pip install -e ".[cloud]" # Cloud provider SDKs

# Set up pre-commit hooks
pre-commit install

# Copy environment template
cp .env.example .env
# Edit .env with your API keys

# Verify installation
make check-env
```

### Running Tests
```bash
# Quick test run
make test

# Full test suite with coverage
make test-all

# Test specific components
make test-integration  # Integration tests
make test-e2e          # End-to-end tests

# Test in watch mode (during development)
make test-watch

# Manual pytest commands
pytest tests/unit -v                    # Unit tests only
pytest tests/integration -v             # Integration tests
pytest --cov=src tests/ --cov-report=html  # With coverage
pytest tests/test_circle_of_experts.py  # Specific file
pytest -k "test_mcp" -v                # Pattern matching

# Performance tests
make performance-test

# Security tests
make security-check
```

### Building Rust Extensions (Optional)
```bash
# Quick build
make rust-build

# OR manual build
cd rust_core
maturin develop --release
cd ..

# Test Rust code
make rust-test

# Run benchmarks
make rust-bench
```

## 📋 Style Guidelines

### Python Code Style
- We use Black for code formatting (line length: 88)
- We use isort for import sorting
- We use Ruff for linting
- Use type hints where possible (required for new code)
- Follow PEP 8 naming conventions
- Use our custom exception hierarchy (see ERROR_HANDLING_BEST_PRACTICES.md)
- Follow memory optimization patterns (see performance docs)

### Code Quality Tools
```bash
# All-in-one quality check
make quality

# Individual checks
make format       # Black + isort
make lint        # Ruff linting
make type-check  # mypy
make security-check  # bandit + safety

# Manual commands
black src/ tests/
isort src/ tests/
ruff check src/ tests/
mypy src/
bandit -r src/
```

### Commit Messages
- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests liberally after the first line

Example:
```
Add Docker deployment capability

- Implement basic container management
- Add state tracking for deployments
- Include rollback functionality

Fixes #123
```

### Documentation
- Update documentation for any changed functionality
- Use clear, concise language
- Include code examples where helpful
- Follow the "Document Reality" principle (see PRIME_DIRECTIVE_DOCUMENT_REALITY.md)

## 🎯 Current Focus Areas

### What Actually Works Today ✅
- Circle of Experts (multi-AI consultation system)
- MCP server integration (27+ servers)
- Security auditing and mitigation matrices
- Performance monitoring and optimization
- Error handling and exception hierarchy
- Comprehensive testing framework

### High Priority Contributions 🚨

#### 1. Actual Infrastructure Deployment
**Status**: Not implemented
- Docker container orchestration
- Kubernetes deployment automation
- Cloud provider integrations (AWS, Azure, GCP)
- Terraform/Pulumi integration
- GitOps workflows

#### 2. Natural Language Processing
**Status**: Framework exists, needs implementation
- Natural language to infrastructure conversion
- Intent parsing and validation
- Configuration generation
- Deployment planning

#### 3. State Management
**Status**: Database models exist, logic needed
- Deployment state tracking
- Rollback capabilities
- Configuration versioning
- Audit trails

### Medium Priority 📊

#### 4. Enterprise Features
- Enhanced RBAC implementation
- Multi-tenant isolation
- Advanced audit logging
- Compliance framework integration

#### 5. Advanced MCP Features
- Custom MCP server development
- Advanced protocol features
- Performance optimization
- Error recovery

### Always Welcome 🧪

#### 6. Testing and Quality
- Integration tests for deployment flow
- Unit tests for new features
- End-to-end testing scenarios
- Performance benchmarks
- Security vulnerability tests

#### 7. Documentation
- Implementation examples
- Architecture diagrams
- Performance optimization guides
- Security best practices

## 🏗️ Architecture Guidelines

### Project Structure
```
src/
├── circle_of_experts/    # ✅ Multi-AI consultation system
│   ├── core/            # Enhanced expert manager
│   ├── experts/         # AI provider implementations
│   ├── models/          # Query/response models
│   └── utils/           # Validation, logging, retry
├── mcp/                 # ✅ Model Context Protocol integration (27+ servers)
│   ├── servers.py       # Server discovery and management
│   ├── client.py        # MCP client implementation
│   └── performance.py   # Performance monitoring
├── auth/               # ✅ Authentication and RBAC
│   ├── rbac.py         # Role-based access control
│   ├── audit.py        # Audit logging
│   └── middleware.py   # Auth middleware
├── core/               # ✅ Core utilities and patterns
│   ├── exceptions.py   # Exception hierarchy
│   ├── circuit_breaker.py  # Circuit breaker pattern
│   ├── memory_monitor.py   # Memory optimization
│   └── retry.py        # Retry logic
├── monitoring/         # ✅ Observability and metrics
│   ├── metrics.py      # Prometheus metrics
│   ├── alerts.py       # Alert definitions
│   └── dashboards/     # Grafana dashboards
├── database/           # ✅ Data persistence layer
│   ├── models.py       # SQLAlchemy models
│   ├── repositories/   # Repository pattern
│   └── migrations/     # Alembic migrations
└── api/               # ⚠️ Basic endpoints only
    └── circuit_breaker_api.py  # Circuit breaker API

# Missing (needs implementation):
# - deployment_engine/   # ❌ Core deployment logic
# - infrastructure/      # ❌ Terraform/K8s integration
# - nlp/                # ❌ Natural language processing
```

### Design Principles
1. **Modular**: Each component should be independent and composable
2. **Async First**: Use async/await for I/O operations
3. **Type Safe**: Use type hints and pydantic models (required)
4. **Testable**: Write code with testing in mind (TDD preferred)
5. **Simple**: Start simple, iterate to complex
6. **Memory Conscious**: Optimize for memory usage (see performance docs)
7. **Error Resilient**: Use our exception hierarchy and circuit breakers
8. **Security First**: Follow security best practices (see security docs)
9. **Observable**: Include metrics, logging, and tracing
10. **NAM/ANAM Compatible**: Follow mathematical optimization patterns

## 📊 Code of Conduct

### Our Pledge
We pledge to make participation in our project a harassment-free experience for everyone, regardless of background or identity.

### Our Standards
- Using welcoming and inclusive language
- Being respectful of differing viewpoints
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

### Our Responsibilities
Project maintainers are responsible for clarifying standards and are expected to take appropriate action in response to any instances of unacceptable behavior.

## 🏆 Recognition

Contributors will be recognized in:
- Our README.md contributors section
- Release notes
- The project wiki
- Special thanks in documentation

Every contribution matters, from fixing typos to implementing major features!

## 📞 Getting Help

- **Documentation**: Check our comprehensive documentation in `docs/` and `ai_docs/`
- **Code Examples**: See `examples/` directory for usage patterns
- **Architecture**: Review `ai_docs/architecture/` for system design
- **Implementation Guides**: Check `ai_docs/implementation/` for detailed guides

## 🚀 Your First Contribution

### Easy Wins (Good First Issues)
1. **Add a new AI expert to Circle of Experts**
   - Implement a new provider in `src/circle_of_experts/experts/`
   - Follow existing patterns (Claude, GPT-4)
   - Add comprehensive tests

2. **Improve existing MCP server integration**
   - Add error handling to MCP clients
   - Implement health checks
   - Add performance monitoring

3. **Write tests for existing functionality**
   - Focus on areas with low coverage
   - Add integration tests
   - Create performance benchmarks

4. **Enhance security features**
   - Implement additional OWASP Top 10 mitigations
   - Add input validation
   - Improve audit logging

5. **Documentation improvements**
   - Add code examples
   - Create architectural diagrams
   - Update API documentation

### Medium Complexity
1. **Implement missing deployment features**
   - Docker container management
   - Basic Kubernetes integration
   - Simple Terraform wrappers

2. **Add new MCP servers**
   - Follow MCP protocol specifications
   - Integrate with existing server manager
   - Add comprehensive tests

3. **Performance optimizations**
   - Memory usage improvements
   - Async optimization
   - Caching strategies

### Advanced Contributions
1. **Natural language processing**
   - Intent parsing
   - Configuration generation
   - Validation logic

2. **Advanced deployment strategies**
   - Blue-green deployments
   - Canary releases
   - Multi-cloud orchestration

3. **Enterprise features**
   - Multi-tenancy
   - Advanced RBAC
   - Compliance frameworks

## 📝 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Remember**: We're building something ambitious together. Every contribution, no matter how small, brings us closer to the goal of natural language infrastructure deployment!

*Thank you for helping make CODE a reality!* 🚀