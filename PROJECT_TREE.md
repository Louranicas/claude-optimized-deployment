# CODE Project - Complete Directory Tree

**Generated**: May 30, 2025  
**Purpose**: Visual representation of entire project structure

```
claude_optimized_deployment/
│
├── .claude/                        # Claude AI configuration
│   ├── Claude.md                  # Configuration and guidelines
│   ├── prime.md                   # Primary directive (context)
│   ├── commands/                  # Custom slash commands
│   ├── tools/                     # Custom Claude tools
│   ├── memory/                    # Memory persistence (gitignored)
│   └── config.yml                 # Claude configuration
│
├── .git-hooks/                     # Git hooks
│   ├── pre-commit                 # Pre-commit checks
│   ├── commit-msg                 # Commit message validation
│   └── pre-push                   # Pre-push validation
│
├── .github/                        # GitHub configuration
│   └── workflows/                 # GitHub Actions
│       ├── ci.yml                 # CI pipeline
│       ├── ci-opensource.yml      # Open source CI
│       ├── claude-code-pr.yml     # Claude PR automation
│       ├── deploy-infrastructure.yml
│       ├── security-audit.yml     # Security scanning
│       └── semantic-release.yml   # Release automation
│
├── ai_docs/                        # AI-generated documentation
│   ├── 00_AI_DOCS_INDEX.md       # Master index
│   ├── 01_INFRASTRUCTURE_*.md    # Infrastructure docs
│   ├── 02_PERFORMANCE_*.md       # Performance docs
│   ├── 03_RUST_PYTHON_*.md       # Integration docs
│   ├── DOCUMENTATION_MINDMAP.md   # Visual mind map
│   │
│   ├── architecture/              # System design
│   │   ├── system_overview.md    # High-level architecture
│   │   ├── microservices_design.md
│   │   ├── api_contracts.md
│   │   ├── data_flow.md
│   │   └── security_architecture.md
│   │
│   ├── research/                  # Technical research
│   │   ├── deployment_strategies.md
│   │   ├── ai_integration.md
│   │   ├── cloud_providers.md
│   │   ├── performance_studies.md
│   │   └── security_analysis.md
│   │
│   ├── implementation/            # Implementation guides
│   │   ├── rust_core/            # Rust implementation
│   │   ├── python_services/      # Python services
│   │   ├── integration_guides/   # Integration docs
│   │   ├── deployment_guides/    # Deployment procedures
│   │   └── troubleshooting/      # Common issues
│   │
│   ├── decisions/                 # Architecture Decision Records
│   │   ├── ADR_template.md       # ADR template
│   │   ├── ADR_001_language_choice.md
│   │   └── ADR_002_microservices.md
│   │
│   ├── analysis/                  # System analysis
│   │   ├── performance_analysis.md
│   │   ├── cost_analysis.md
│   │   ├── risk_analysis.md
│   │   └── scalability_analysis.md
│   │
│   ├── optimization/              # Optimization strategies
│   │   ├── code_optimization.md
│   │   ├── deployment_optimization.md
│   │   ├── resource_optimization.md
│   │   └── cost_optimization.md
│   │
│   ├── testing/                   # Testing documentation
│   │   ├── test_strategies.md
│   │   ├── test_plans/
│   │   ├── performance_tests/
│   │   └── security_tests/
│   │
│   └── deployment/                # Deployment documentation
│       ├── deployment_checklist.md
│       ├── rollout_strategies.md
│       ├── rollback_procedures.md
│       └── monitoring_setup.md
│
├── docs/                          # Human-written documentation
│   ├── git-optimization/         # Git workflow docs
│   │   ├── README.md            # Git optimization guide
│   │   └── quick-reference.md   # Git quick reference
│   ├── production_plan.md        # Production roadmap
│   ├── project_roadmap.md        # Development timeline
│   ├── github_actions_implementation.md
│   ├── CIRCLE_OF_EXPERTS_GUIDE.md
│   ├── VIDEO_TO_DOCUMENTATION_WORKFLOW.md
│   └── LANGUAGE_GUIDELINES.md    # Language selection guide
│
├── examples/                      # Example usage
│   ├── circle_of_experts_usage.py
│   └── video_processing_example.py
│
├── infrastructure/                # Infrastructure as Code
│   ├── terraform/                # Terraform modules
│   ├── kubernetes/               # K8s manifests
│   └── docker/                   # Dockerfiles
│
├── research/                      # Research documents
│   ├── github_integration_research.md
│   ├── cicd_best_practices.md
│   └── copilot_integration_strategy.md
│
├── rust_core/                     # Rust implementation (planned)
│   ├── Cargo.toml                # Rust workspace
│   ├── deployment_engine/        # Core engine
│   ├── cli/                      # CLI tool
│   └── common/                   # Shared libraries
│
├── scripts/                       # Automation scripts
│   ├── git/                      # Git tools
│   │   ├── setup-hooks.sh       # Hook installation
│   │   ├── git-helpers.sh       # Workflow helpers
│   │   ├── git-doctor.sh        # Health check
│   │   ├── git-performance.py   # Performance analysis
│   │   └── version.py           # Version management
│   ├── setup_circle_of_experts.py
│   └── deployment/               # Deployment scripts
│
├── src/                          # Python source code
│   ├── circle_of_experts/       # Multi-AI system (WORKING)
│   │   ├── __init__.py
│   │   ├── expert_manager.py
│   │   ├── consensus_builder.py
│   │   └── models/
│   ├── video_processor/         # Video to docs (WORKING)
│   ├── deployment_engine/       # Core engine (TODO)
│   └── common/                  # Shared utilities
│
├── tests/                        # Test suites
│   ├── unit/                    # Unit tests
│   ├── integration/             # Integration tests
│   ├── e2e/                     # End-to-end tests
│   └── fixtures/                # Test fixtures
│
├── .env.example                  # Environment template
├── .gitattributes               # Git attributes
├── .gitconfig.recommended       # Git configuration
├── .gitignore                   # Git ignore patterns
├── .gitmessage                  # Commit template
├── .lfsconfig                   # Git LFS config
├── CHANGELOG.md                 # Release changelog
├── CLAUDE_CODE_QUICKSTART.md    # Claude Code guide
├── CONTRIBUTING.md              # Contribution guide
├── LICENSE                      # MIT License
├── Makefile                     # Build automation
├── MIGRATION_SUMMARY.md         # Migration notes
├── PRIME_DIRECTIVE_DOCUMENT_REALITY.md
├── PROJECT_STATUS.md            # Current status
├── PROJECT_SUMMARY.md           # Project overview
├── pyproject.toml               # Python project config
├── README.md                    # Main documentation
├── requirements-dev.txt         # Dev dependencies
├── requirements.txt             # Python dependencies
└── VERSION                      # Current version (0.1.0)
```

## 📊 Directory Statistics

| Category | Count | Purpose |
|----------|-------|---------|
| **Documentation** | 50+ files | Comprehensive project docs |
| **Source Code** | 20+ modules | Python implementation |
| **Scripts** | 15+ scripts | Automation and tooling |
| **Tests** | 10+ test files | Quality assurance |
| **Config Files** | 20+ configs | Project configuration |

## 🎯 Key Directories by Function

### Development
- `src/` - Active Python development
- `rust_core/` - Future Rust implementation
- `tests/` - All test suites

### Documentation
- `docs/` - Human-written guides
- `ai_docs/` - AI-generated documentation
- `research/` - Research and analysis

### Operations
- `scripts/` - Automation tools
- `.github/` - CI/CD workflows
- `infrastructure/` - IaC definitions

### Configuration
- `.claude/` - AI assistant config
- `.git-hooks/` - Git automation
- Root config files

## 🔄 File Naming Conventions

1. **Documentation**: `UPPER_CASE.md` for main docs
2. **AI Docs**: Numbered prefix `00_TOPIC.md`
3. **Scripts**: `lowercase-with-dashes.sh`
4. **Python**: `snake_case.py`
5. **Rust**: `snake_case.rs`
6. **Config**: `.lowercase`

---

*This tree represents the complete CODE project structure as of May 30, 2025.*
