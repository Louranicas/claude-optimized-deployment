# Git & GitHub Optimization Guide for Claude Code

## 🎯 Overview

This guide provides a complete Git and GitHub setup optimized for Claude Code integration, enabling AI-assisted development workflows.

## 📋 Table of Contents

1. [Quick Setup](#quick-setup)
2. [Git Configuration](#git-configuration)
3. [Commit Conventions](#commit-conventions)
4. [Branch Strategy](#branch-strategy)
5. [GitHub Features](#github-features)
6. [Claude Code Integration](#claude-code-integration)
7. [Automation & Workflows](#automation--workflows)
8. [Best Practices](#best-practices)

## 🚀 Quick Setup

```bash
# Run the complete setup
make git-setup

# Or manually:
./scripts/setup_git_for_claude.sh

# Install pre-commit hooks
pre-commit install

# Configure commit template
git config commit.template .gitmessage
```

## 📝 Git Configuration

### Aliases for Claude Code

```bash
# AI-powered commit
git ai-commit  # Analyzes changes and creates semantic commit

# Smart PR creation
git ai-pr  # Creates PR with AI-generated description

# Visual history
git visual-log  # Shows commit graph with colors

# Better diff
git smart-diff  # Shows word-level changes
```

### Global Settings

```gitconfig
[user]
    name = Your Name
    email = your.email@example.com
    signingkey = YOUR_GPG_KEY

[commit]
    template = ~/.gitmessage
    gpgsign = true

[pull]
    rebase = true

[rebase]
    autoStash = true

[diff]
    algorithm = histogram
    colorMoved = default

[merge]
    conflictstyle = diff3

[alias]
    # Claude Code aliases
    ai-commit = !git add -A && git commit -m \"$(claude-commit-message)\"
    ai-pr = !git push -u origin HEAD && gh pr create --fill
    smart-diff = diff --color-words --word-diff
    visual-log = log --graph --pretty=format:'%C(yellow)%h%C(reset) - %C(cyan)%an%C(reset) - %C(green)%ar%C(reset) - %C(white)%s%C(reset)' --abbrev-commit
    
    # Useful shortcuts
    co = checkout
    br = branch
    st = status -sb
    last = log -1 HEAD
    unstage = reset HEAD --
    amend = commit --amend --no-edit
    undo = reset --soft HEAD~1
```

## 📋 Commit Conventions

### Semantic Commit Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

| Type | Description | Version Impact |
|------|-------------|----------------|
| `feat` | New feature | Minor |
| `fix` | Bug fix | Patch |
| `docs` | Documentation only | Patch* |
| `style` | Code style (formatting) | None |
| `refactor` | Code refactoring | None |
| `perf` | Performance improvement | Patch |
| `test` | Adding tests | None |
| `build` | Build system changes | None |
| `ci` | CI/CD changes | None |
| `chore` | Maintenance tasks | None |
| `revert` | Revert previous commit | Patch |

*Only if scope is README

### Scopes

- `circle-of-experts` - Circle of Experts feature
- `deployment` - Deployment engine (future)
- `api` - API endpoints
- `cli` - CLI commands
- `devops` - Infrastructure/DevOps
- `security` - Security-related
- `docs` - Documentation
- `deps` - Dependencies

### Examples

```bash
# Features
feat(circle-of-experts): add support for Ollama models
feat(api): implement rate limiting for expert queries

# Fixes
fix(circle-of-experts): handle API timeout gracefully
fix(security): patch SQL injection vulnerability

# Breaking changes
feat(api)!: change response format for expert queries

BREAKING CHANGE: Response format now includes confidence scores

# Multiple scopes
fix(api,cli): synchronize error messages
```

## 🌳 Branch Strategy

### Branch Types

```
main                    # Production-ready code
├── develop            # Integration branch
├── feature/*          # New features
├── fix/*             # Bug fixes
├── hotfix/*          # Emergency fixes
├── release/*         # Release preparation
└── experiment/*      # Experimental work
```

### Branch Naming

```bash
# Features
feature/add-ollama-support
feature/deployment-engine-mvp

# Fixes
fix/circle-of-experts-timeout
fix/issue-123-api-error

# Experiments
experiment/rust-performance-boost
experiment/natural-language-deploy
```

### Branch Protection Rules

```yaml
main:
  - Require PR reviews (2)
  - Require status checks
  - Require up-to-date branches
  - Include administrators
  - Require signed commits

develop:
  - Require PR reviews (1)
  - Require status checks
  - Auto-delete head branches
```

## 🔧 GitHub Features

### Labels

```yaml
# Priority
- P0-critical: "🔴 Mission critical"
- P1-high: "🟡 High priority"
- P2-medium: "🟢 Medium priority"
- P3-low: "🔵 Low priority"

# Type
- bug: "🐛 Something isn't working"
- enhancement: "✨ New feature or request"
- documentation: "📚 Documentation improvements"
- question: "❓ Further information requested"

# Status
- in-progress: "🚧 Work in progress"
- blocked: "🚫 Blocked by dependency"
- needs-review: "👀 Needs review"
- ready-to-merge: "✅ Ready to merge"

# Component
- circle-of-experts: "🤖 Circle of Experts feature"
- deployment-engine: "🚀 Deployment engine"
- api: "🔌 API related"
- devops: "🔧 DevOps/Infrastructure"

# Special
- good-first-issue: "👋 Good for newcomers"
- help-wanted: "🆘 Extra attention needed"
- claude-reviewed: "🤖 Reviewed by Claude Code"
- ai-enhanced: "🧠 AI-enhanced feature"
```

### Issue Templates

1. **Bug Report** - Structured bug reporting
2. **Feature Request** - New feature proposals
3. **Circle of Experts Issue** - Specific to CoE
4. **Documentation** - Doc improvements
5. **Question** - General questions

### PR Template Features

- Automated checklist
- Claude Code analysis section
- Testing requirements
- Deployment notes
- Reviewer guide

## 🤖 Claude Code Integration

### Automated Features

1. **Commit Message Generation**
   ```bash
   # Claude analyzes changes and suggests commit message
   git ai-commit
   ```

2. **PR Description Generation**
   ```bash
   # Claude creates comprehensive PR description
   gh pr create --claude-enhanced
   ```

3. **Code Review Assistance**
   - Auto-comments on PRs
   - Security analysis
   - Performance suggestions
   - Best practice recommendations

4. **Issue Triage**
   - Auto-labeling
   - Priority assignment
   - Component detection
   - Duplicate detection

### Claude Code Commands in PRs

```
@claude-code review      # Detailed code review
@claude-code suggest     # Improvement suggestions
@claude-code security    # Security-focused review
@claude-code performance # Performance analysis
@claude-code docs        # Documentation review
```

## 🔄 Automation & Workflows

### GitHub Actions

1. **CI/CD Pipeline** (`ci.yml`)
   - Linting & formatting
   - Type checking
   - Unit/integration tests
   - Security scanning
   - Docker build

2. **Claude Code PR Assistant** (`claude-code-pr.yml`)
   - Automatic PR analysis
   - Comment with insights
   - Label management
   - Command handling

3. **Semantic Release** (`semantic-release.yml`)
   - Automatic versioning
   - Changelog generation
   - GitHub releases
   - NPM publishing

4. **Dependency Updates** (`dependabot.yml`)
   - Automatic PRs for updates
   - Security patches
   - Version constraints

### Pre-commit Hooks

```yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
      - id: check-merge-conflict

  - repo: https://github.com/psf/black
    hooks:
      - id: black
        language_version: python3.10

  - repo: https://github.com/pycqa/isort
    hooks:
      - id: isort

  - repo: https://github.com/charliermarsh/ruff-pre-commit
    hooks:
      - id: ruff

  - repo: local
    hooks:
      - id: claude-code-check
        name: Claude Code Check
        entry: .github/hooks/pre-commit
        language: script
```

## 📚 Best Practices

### 1. Commit Best Practices

- **Atomic commits**: One logical change per commit
- **Present tense**: "Add feature" not "Added feature"
- **Imperative mood**: "Fix bug" not "Fixes bug"
- **Reference issues**: Include #123 in commit message
- **Sign commits**: Use GPG signing

### 2. PR Best Practices

- **Small PRs**: Easier to review
- **Draft PRs**: For work in progress
- **Link issues**: Closes #123
- **Update often**: Rebase on main
- **Respond promptly**: To review comments

### 3. Branch Best Practices

- **Delete after merge**: Keep repo clean
- **Regular rebasing**: Stay up to date
- **Feature flags**: For long-running features
- **Protection rules**: Enforce quality

### 4. Code Review Best Practices

- **Be constructive**: Focus on code, not person
- **Provide examples**: Show better approaches
- **Ask questions**: Understand intent
- **Approve explicitly**: Use GitHub's review feature
- **Follow up**: Ensure feedback is addressed

## 🛠️ Troubleshooting

### Common Issues

1. **Merge Conflicts**
   ```bash
   # Rebase on main
   git fetch origin
   git rebase origin/main
   
   # Resolve conflicts
   git add .
   git rebase --continue
   ```

2. **Undo Last Commit**
   ```bash
   # Keep changes
   git reset --soft HEAD~1
   
   # Discard changes
   git reset --hard HEAD~1
   ```

3. **Amend Commit Message**
   ```bash
   git commit --amend
   # Edit message and save
   ```

4. **Cherry Pick Commit**
   ```bash
   git cherry-pick <commit-hash>
   ```

## 📊 Metrics & Analytics

Track these metrics for team health:

1. **PR Metrics**
   - Time to review
   - Time to merge
   - PR size (lines changed)
   - Review iterations

2. **Commit Metrics**
   - Commits per day
   - Commit message quality
   - Breaking changes frequency

3. **Issue Metrics**
   - Time to resolution
   - Issue velocity
   - Label distribution

## 🎯 Quick Reference

```bash
# Daily workflow
git pull --rebase origin main
git checkout -b feature/my-feature
# Make changes
git ai-commit
git ai-pr

# Update PR
git add .
git commit --amend --no-edit
git push --force-with-lease

# Finish feature
git checkout main
git pull --rebase
git branch -d feature/my-feature
```

---

*Last Updated: May 30, 2025*  
*Version: 1.0.0*
