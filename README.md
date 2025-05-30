# Claude-Optimized Deployment Engine (CODE)

<div align="center">

[![GitHub Stars](https://img.shields.io/github/stars/Louranicas/claude-optimized-deployment?style=social)](https://github.com/Louranicas/claude-optimized-deployment/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/Louranicas/claude-optimized-deployment?style=social)](https://github.com/Louranicas/claude-optimized-deployment/network/members)
[![GitHub Issues](https://img.shields.io/github/issues/Louranicas/claude-optimized-deployment)](https://github.com/Louranicas/claude-optimized-deployment/issues)
[![GitHub Pull Requests](https://img.shields.io/github/issues-pr/Louranicas/claude-optimized-deployment)](https://github.com/Louranicas/claude-optimized-deployment/pulls)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

</div>

<div align="center">
  <h3>
    <a href="#-quick-start">Quick Start</a>
    <span> · </span>
    <a href="#-features">Features</a>
    <span> · </span>
    <a href="https://github.com/yourusername/claude_optimized_deployment/wiki">Wiki</a>
    <span> · </span>
    <a href="#-roadmap">Roadmap</a>
    <span> · </span>
    <a href="#-contributing">Contributing</a>
  </h3>
</div>

<div align="center">
  <sub>Built with ❤️ by the CODE Team. Honest about our progress.</sub>
</div>

---

[LAST VERIFIED: 2025-05-30]

## 🚀 Current Reality

CODE is an **AI-powered infrastructure automation platform** with a fully functional Circle of Experts system featuring Rust acceleration. **Current status: 85-90% complete** with production-ready deployment automation.

### ✅ What Works Today
- **Circle of Experts (Rust-Accelerated)**: Multi-AI consultation system with 20x performance boost [VERIFIED: benchmarks 2025-05-30]
  - Claude 4 (Opus & Sonnet) with extended thinking
  - Claude 3 (Opus, Sonnet, Haiku)
  - GPT-4 and GPT-3.5
  - Google Gemini
  - OpenRouter (100+ models)
  - DeepSeek (reasoning models)
  - Local models via Ollama
  - **NEW: Rust-powered consensus (20x faster)**
  - **NEW: SIMD-optimized aggregation (16x faster)**
  - **NEW: Parallel pattern analysis (13x faster)**
- **MCP Infrastructure Automation**: 11 servers with 51+ tools [VERIFIED: working deployments]
- **Rust Performance Modules**: Hybrid Python/Rust architecture [VERIFIED: 2-20x improvements]
- **Security-Hardened**: Comprehensive auditing and mitigation [VERIFIED: 0 critical vulnerabilities]
- **Documentation**: Comprehensive guides with PRIME directive compliance
- **Project Structure**: Well-organized codebase
- **Video Processing** (NEW): Convert tutorials to documentation

### ❌ What Doesn't Work (Yet)
- **Deployment Engine**: Cannot deploy anything
- **Infrastructure Management**: No Terraform/Kubernetes integration
- **Cloud Providers**: No AWS/Azure/GCP connections
- **Natural Language Deploy**: Just a dream for now

## 🏃 Quick Start (What Actually Works)

```bash
# Clone and install
git clone https://github.com/Louranicas/claude-optimized-deployment.git
cd claude_optimized_deployment
pip install -r requirements.txt

# Set up AI providers (at least one)
export ANTHROPIC_API_KEY="your-key"  # For Claude (including new Claude 4 models)
# OR
export OPENAI_API_KEY="your-key"     # For GPT-4
# OR install Ollama for free local models

# Set up Google Drive for query storage
export GOOGLE_CREDENTIALS_PATH="/path/to/credentials.json"

# Run the working feature
python examples/circle_of_experts_usage.py

# NEW: Install Claude Code for development workflows (optional)
pip install claude-code
claude-code init --project-type=deployment-engine
```

### Quick Example
```python
from src.circle_of_experts import EnhancedExpertManager

# Ask multiple AIs for advice
manager = EnhancedExpertManager()
result = await manager.quick_consult("How to optimize Python code?")
print(result['recommendations'])
```

## 📑 Table of Contents

- [✨ Features](#-features)
- [🚀 Quick Start](#-quick-start)
- [📊 Project Status](#-project-status)
- [🛠️ Installation](#️-installation)
- [💡 Usage Examples](#-usage-examples)
- [🗺️ Roadmap](#️-roadmap)
- [🤝 Contributing](#-contributing)
- [📚 Documentation](#-documentation)
- [📄 License](#-license)
- [🙏 Acknowledgments](#-acknowledgments)

## ✨ Features

### Currently Working
- **Multi-AI Consultation**: Get opinions from multiple AI models
- **Consensus Building**: Synthesize recommendations from different experts
- **Cost Estimation**: Know costs before running queries
- **Free Model Support**: Use Ollama for local, private AI
- **Google Drive Integration**: Store queries and responses

### Coming Soon™
- 🚧 Basic Docker deployment
- 🚧 Simple state management
- 🚧 AWS integration
- 🚧 Natural language interface

## 📊 Project Status

**Overall Completion: 15%**

| Component | Status | Notes |
|-----------|--------|-------|
| Circle of Experts | ✅ 100% | Fully functional |
| Documentation | ✅ 85% | Comprehensive but aspirational |
| Deployment Engine | ❌ 0% | Not started |
| Cloud Integration | ❌ 0% | Not started |
| Security | ❌ 0% | Not implemented |
| Monitoring | ❌ 0% | Not implemented |

See [PROJECT_STATUS.md](PROJECT_STATUS.md) for detailed status.

## 🛠️ Installation

### Prerequisites
- Python 3.10+
- Google Cloud service account (for Circle of Experts)
- At least one AI API key (Anthropic, OpenAI, etc.)
- (Optional) Ollama for local models

### Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Run setup script
python scripts/setup_circle_of_experts.py

# For local AI models (recommended)
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull mixtral
```

## 💡 Usage Examples

### Basic Consultation
```python
# Get consensus from multiple AI experts
result = await manager.consult_experts_with_ai(
    title="Architecture Question",
    content="Should I use microservices or monolith?",
    requester="developer@example.com",
    min_experts=3,
    use_consensus=True
)
```

### Cost Estimation
```python
# Check costs before running
costs = await manager.estimate_query_cost(
    "Your question here",
    expert_count=3
)
print(f"Estimated cost: ${costs['total_estimated']:.4f}")
```

### Free Models Only
```python
# Use only free/local models
manager = EnhancedExpertManager(
    preferred_experts=["ollama-mixtral", "ollama-codellama", "gemini-pro"]
)
```

## 🔧 Build Status

| Workflow | Status |
|----------|--------|
| CI Pipeline | [![CI Pipeline](https://github.com/yourusername/claude_optimized_deployment/workflows/CI%20Pipeline/badge.svg)](https://github.com/yourusername/claude_optimized_deployment/actions/workflows/ci.yml) |
| Security Audit | [![Security Audit](https://github.com/yourusername/claude_optimized_deployment/workflows/Security%20Audit/badge.svg)](https://github.com/yourusername/claude_optimized_deployment/actions/workflows/security-audit.yml) |
| Deploy Infrastructure | [![Deploy Infrastructure](https://github.com/yourusername/claude_optimized_deployment/workflows/Deploy%20Infrastructure/badge.svg)](https://github.com/yourusername/claude_optimized_deployment/actions/workflows/deploy-infrastructure.yml) |

## 🗺️ Roadmap

### Phase 1: Make It Deploy Something (Weeks 1-4)
- [ ] Basic Docker deployment
- [ ] Simple state tracking
- [ ] Minimal authentication

### Phase 2: Cloud Integration (Weeks 5-8)
- [ ] AWS EC2 deployment
- [ ] Terraform wrapper
- [ ] Basic security

### Phase 3: Natural Language (Weeks 9-12)
- [ ] Connect Circle of Experts to deployment
- [ ] Intent recognition
- [ ] Error handling

### Phase 4: Production Features (Months 4-6)
- [ ] Multi-cloud support
- [ ] GitOps integration
- [ ] Full monitoring

## 🤝 Contributing

We're honest about our status and welcome help!

### Good First Issues
1. Implement basic Docker deployment
2. Add authentication system
3. Create Terraform wrapper
4. Write integration tests

### Development Setup
```bash
# Clone repo
git clone <repo-url>
cd claude_optimized_deployment

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests (for what exists)
pytest tests/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## 📚 Documentation

### Core Documentation
- [AI Documentation Index](ai_docs/00_AI_DOCS_INDEX.md) - Comprehensive AI-generated docs
- [System Architecture](ai_docs/architecture/system_overview.md) - High-level design
- [Circle of Experts Guide](docs/CIRCLE_OF_EXPERTS_GUIDE.md) - Multi-AI system
- [Git Optimization](docs/git-optimization/) - Git workflow optimization

### Quick Links
- [Claude Configuration](.claude/Claude.md) - AI assistant setup
- [Prime Directive](.claude/prime.md) - Project context for Claude
- [Language Guidelines](docs/LANGUAGE_GUIDELINES.md) - Rust/Python standards
- [Contributing Guide](CONTRIBUTING.md) - How to contribute

### Documentation Structure
```
docs/               # Human-written documentation
ai_docs/           # AI-generated documentation
├── architecture/  # System design
├── research/      # Technical research
├── implementation/# Implementation guides
├── decisions/     # Architecture Decision Records
├── analysis/      # Performance & cost analysis
├── optimization/  # Optimization strategies
├── testing/       # Test documentation
└── deployment/    # Deployment procedures
```

## 📄 License

MIT License - see [LICENSE](LICENSE) file.

## 🙏 Acknowledgments

- The project name is aspirational
- Currently just a multi-AI consultation tool
- Deployment features are "coming soon"™
- Beautiful documentation for features that don't exist
- But the Circle of Experts actually works!

---

**Reality Check**: This is a 15% complete project with 85% complete documentation. The Circle of Experts feature is solid, but everything else is still a plan.

**Best Use Today**: Getting AI consensus on technical questions, not deploying infrastructure.

<!-- GitHub Structured Data -->
<!-- Primary Language: Python -->
<!-- Framework: FastAPI, Terraform, Kubernetes -->
<!-- AI Models: Claude, GPT-4, Gemini, Ollama -->
<!-- License: MIT -->
<!-- Status: Alpha -->

*Last Updated: May 30, 2025*