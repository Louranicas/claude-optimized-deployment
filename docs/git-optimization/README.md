# Git Optimization Setup Guide

This directory contains all the Git optimization tools, scripts, and configurations for the CODE project.

## 🚀 Quick Start

1. **Install Git hooks:**
   ```bash
   ./scripts/git/setup-hooks.sh
   ```

2. **Load Git helpers:**
   ```bash
   source ./scripts/git/git-helpers.sh
   ```

3. **Check repository health:**
   ```bash
   ./scripts/git/git-doctor.sh
   ```

## 📁 Directory Structure

```
git-optimization/
├── README.md                    # This file (main guide)
├── .gitconfig.recommended       # Recommended Git configuration
├── .lfsconfig                  # Git LFS configuration
├── VERSION                     # Current project version
├── .git-hooks/                 # Git hooks
│   ├── pre-commit             # Pre-commit checks
│   ├── commit-msg             # Commit message validation
│   └── pre-push               # Pre-push checks
└── scripts/git/               # Git scripts and tools
    ├── setup-hooks.sh         # Hook installation script
    ├── git-helpers.sh         # Workflow helper functions
    ├── git-doctor.sh          # Repository health check
    ├── git-performance.py     # Performance analysis
    └── version.py             # Semantic versioning tool
```

## 🔧 Setup Instructions

### 1. Initial Setup

Run the complete setup:

```bash
# From project root
./scripts/git/setup-hooks.sh

# This will:
# - Install Git hooks
# - Configure Git settings
# - Install required tools
# - Set up secrets scanning
```

### 2. Configure Git

Apply recommended settings:

```bash
# Option 1: Copy recommended config
cp .gitconfig.recommended ~/.gitconfig

# Option 2: Include in existing config
echo "[include]" >> ~/.gitconfig
echo "    path = /path/to/project/.gitconfig.recommended" >> ~/.gitconfig
```

### 3. Enable Git LFS

For large file support:

```bash
# Install Git LFS
git lfs install

# Track large files
git lfs track "*.pkl"
git lfs track "*.h5"
git lfs track "*.mp4"
```

## 📚 Feature Documentation

### Git Hooks

#### Pre-commit Hook
Runs before each commit to ensure code quality:
- ✅ Checks for debug statements
- ✅ Validates Python code with flake8
- ✅ Ensures proper formatting with black
- ✅ Scans for potential secrets
- ✅ Prevents large files (>5MB)
- ✅ Runs basic tests

#### Commit Message Hook
Enforces conventional commit format:
```
<type>(<scope>): <subject>

<body>

<footer>
```

Valid types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`

#### Pre-push Hook
Final checks before pushing:
- ✅ Prevents direct push to protected branches
- ✅ Validates all commit messages
- ✅ Runs security scans
- ✅ Executes full test suite

### Git Helpers

Load the helpers:
```bash
source ./scripts/git/git-helpers.sh
```

Available commands:

| Command | Description |
|---------|-------------|
| `git-feature CODE-123 description` | Create feature branch |
| `git-fix CODE-456 description` | Create fix branch |
| `git-cleanup` | Remove merged branches |
| `git-stats` | Show repository statistics |
| `git-find-large [size]` | Find large files in history |
| `git-graph [count]` | Show branch graph |
| `git-sync-fork` | Sync fork with upstream |
| `git-release <version>` | Start release process |
| `git-undo` | Safely undo last commit |
| `git-file-history <file>` | Show file history |
| `git-today` | Show today's activity |

### Semantic Versioning

Manage versions with the version tool:

```bash
# Show current version
python scripts/git/version.py current

# Bump version (auto-detect type)
python scripts/git/version.py bump

# Bump specific type
python scripts/git/version.py bump --type minor

# Full release
python scripts/git/version.py release

# Dry run
python scripts/git/version.py release --dry-run
```

### Performance Optimization

Analyze and optimize repository performance:

```bash
# Run performance analysis
python scripts/git/git-performance.py

# This will:
# - Benchmark common operations
# - Analyze repository statistics
# - Check for optimizations
# - Generate performance report
```

### Repository Health Check

Regular health checks:

```bash
# Run health check
./scripts/git/git-doctor.sh

# Checks for:
# - Repository corruption
# - Lock files
# - Large files
# - Configuration issues
# - Optimization opportunities
```

## 🎯 Best Practices

### 1. Commit Messages

Follow conventional commits:
```bash
# Feature
git commit -m "feat(deployment): add kubernetes support"

# Bug fix
git commit -m "fix(api): resolve timeout in health check"

# With breaking change
git commit -m "feat(api)!: change response format

BREAKING CHANGE: API responses now use camelCase"
```

### 2. Branch Management

```bash
# Create feature branch
git-feature CODE-123 add-new-feature

# Create fix branch
git-fix CODE-456 fix-memory-leak

# Clean up regularly
git-cleanup
```

### 3. Releases

```bash
# Start release
git-release 1.2.0

# Auto release
python scripts/git/version.py release

# Manual steps
git checkout -b release/1.2.0 develop
# ... make changes ...
git checkout main
git merge --no-ff release/1.2.0
git tag -a v1.2.0 -m "Release v1.2.0"
git checkout develop
git merge --no-ff release/1.2.0
```

## 🛠️ Troubleshooting

### Common Issues

#### "Permission denied" on hooks
```bash
chmod +x .git-hooks/*
chmod +x scripts/git/*.sh
```

#### Hooks not running
```bash
# Check if hooks are installed
ls -la .git/hooks/

# Reinstall
./scripts/git/setup-hooks.sh
```

#### Large repository operations slow
```bash
# Enable performance features
git config core.preloadindex true
git config core.fscache true
git config feature.manyFiles true

# Run optimization
python scripts/git/git-performance.py
```

#### Commit rejected by hook
```bash
# Skip hooks (use sparingly!)
git commit --no-verify

# Fix and retry
git add .
git commit
```

### Emergency Commands

```bash
# Undo last commit (keep changes)
git reset --soft HEAD~1

# Reset to remote state
git fetch origin
git reset --hard origin/main

# Find lost commits
git reflog

# Fix corrupted index
rm .git/index
git reset
```

## 📊 Git Aliases Reference

Key aliases from `.gitconfig.recommended`:

| Alias | Command | Description |
|-------|---------|-------------|
| `git st` | `status -sb` | Short status |
| `git co` | `checkout` | Checkout shortcut |
| `git wip` | Save work in progress | Quick WIP commit |
| `git undo` | `reset --soft HEAD~1` | Undo last commit |
| `git lg` | Pretty log graph | Visual history |
| `git cleanup` | Remove merged branches | Branch cleanup |
| `git recent` | Recent branches | List recent work |

## 🔐 Security Features

### Secret Scanning

Pre-commit automatically scans for:
- API keys and tokens
- AWS credentials
- Private keys
- Generic secrets patterns

### GPG Signing

Enable commit signing:
```bash
# Generate GPG key
gpg --gen-key

# Configure Git
git config --global user.signingkey YOUR_KEY_ID
git config --global commit.gpgsign true
```

## 📈 Monitoring

### Weekly Tasks

1. Run health check:
   ```bash
   ./scripts/git/git-doctor.sh
   ```

2. Clean branches:
   ```bash
   git-cleanup
   ```

3. Check performance:
   ```bash
   python scripts/git/git-performance.py
   ```

### Monthly Tasks

1. Review large files:
   ```bash
   git-find-large 10485760  # 10MB
   ```

2. Optimize repository:
   ```bash
   git gc --aggressive
   git repack -ad
   ```

## 🎓 Learning Resources

### Conventional Commits
- [Specification](https://www.conventionalcommits.org/)
- [Angular Convention](https://github.com/angular/angular/blob/master/CONTRIBUTING.md#commit)

### Git Best Practices
- [Pro Git Book](https://git-scm.com/book)
- [GitHub Flow](https://guides.github.com/introduction/flow/)
- [Git Flight Rules](https://github.com/k88hudson/git-flight-rules)

### Performance
- [Git Performance](https://git-scm.com/docs/git-config#_performance)
- [Large Repository Management](https://www.atlassian.com/git/tutorials/big-repositories)

## 🤝 Contributing

When contributing to Git optimization:

1. Test all scripts thoroughly
2. Document new features
3. Update this README
4. Follow the same conventions
5. Add tests where applicable

---

For questions or improvements, please create an issue or submit a PR!
