#!/usr/bin/env python3
"""
Code Quality Tools Setup Script - AGENT 5 Follow-up
Sets up automated code quality monitoring and analysis tools
"""

import subprocess
import sys
from pathlib import Path

def create_pyproject_config():
    """Create pyproject.toml with code quality tool configurations."""
    
    config_content = """
[tool.black]
line-length = 88
target-version = ['py312']
include = '\\.pyi?$'
extend-exclude = '''
/(
  # directories
  \\.eggs
  | \\.git
  | \\.hg
  | \\.mypy_cache
  | \\.tox
  | \\.venv
  | build
  | dist
  | venv_bulletproof
)/
'''

[tool.isort]
profile = "black"
multi_line_output = 3
line_length = 88
known_first_party = ["src"]

[tool.mypy]
python_version = "3.12"
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
disallow_incomplete_defs = true
check_untyped_defs = true
disallow_untyped_decorators = true
no_implicit_optional = true
warn_redundant_casts = true
warn_unused_ignores = true
warn_no_return = true
warn_unreachable = true
strict_equality = true

[[tool.mypy.overrides]]
module = [
    "src.utils.*",
    "src.mcp.*"
]
# Start with less strict checking for legacy code
disallow_untyped_defs = false
disallow_incomplete_defs = false

[tool.pylint.messages_control]
disable = [
    "missing-module-docstring",
    "missing-class-docstring", 
    "missing-function-docstring",
    "too-many-arguments",
    "too-many-locals",
    "too-many-branches",
    "too-many-statements",
    "line-too-long"
]

[tool.pylint.format]
max-line-length = 88

[tool.bandit]
exclude_dirs = ["tests", "venv_bulletproof"]
skips = ["B101", "B601"]

[tool.coverage.run]
source = ["src"]
omit = [
    "*/tests/*",
    "*/venv_bulletproof/*",
    "*/__pycache__/*"
]

[tool.coverage.report]
exclude_lines = [
    "pragma: no cover",
    "def __repr__",
    "if self.debug:",
    "if settings.DEBUG",
    "raise AssertionError",
    "raise NotImplementedError",
    "if 0:",
    "if __name__ == .__main__.:",
    "class .*\\bProtocol\\):",
    "@(abc\\.)?abstractmethod"
]
"""
    
    pyproject_path = Path("pyproject.toml")
    
    # Check if pyproject.toml exists and has our configs
    if pyproject_path.exists():
        with open(pyproject_path, 'r') as f:
            existing_content = f.read()
        
        if "[tool.black]" in existing_content:
            print("  ℹ️  pyproject.toml already has tool configurations")
            return
    
    # Append our configurations
    with open(pyproject_path, 'a') as f:
        f.write(config_content)
    
    print("  ✅ Added code quality tool configurations to pyproject.toml")

def create_pre_commit_config():
    """Create .pre-commit-config.yaml for git hooks."""
    
    config_content = """repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
      - id: check-merge-conflict
      - id: debug-statements
      - id: check-ast

  - repo: https://github.com/psf/black
    rev: 23.7.0
    hooks:
      - id: black
        language_version: python3.12

  - repo: https://github.com/pycqa/isort
    rev: 5.12.0
    hooks:
      - id: isort
        args: ["--profile", "black"]

  - repo: https://github.com/pycqa/flake8
    rev: 6.0.0
    hooks:
      - id: flake8
        args: [--max-line-length=88, --extend-ignore=E203,W503]

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.5.1
    hooks:
      - id: mypy
        additional_dependencies: [types-all]
        args: [--ignore-missing-imports]

  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.5
    hooks:
      - id: bandit
        args: [--skip, "B101,B601", --exclude, "tests/"]
"""
    
    precommit_path = Path(".pre-commit-config.yaml")
    
    if not precommit_path.exists():
        with open(precommit_path, 'w') as f:
            f.write(config_content)
        print("  ✅ Created .pre-commit-config.yaml")
    else:
        print("  ℹ️  .pre-commit-config.yaml already exists")

def create_makefile_targets():
    """Add code quality targets to Makefile."""
    
    makefile_content = """
# Code Quality Targets (added by AGENT 5)
.PHONY: quality check format lint type-check security test-quality

quality: format lint type-check security  ## Run all code quality checks

check:  ## Quick syntax and import check
	@echo "🔍 Checking syntax..."
	@python3 -m py_compile src/**/*.py
	@echo "✅ Syntax check passed"

format:  ## Format code with black and isort
	@echo "🎨 Formatting code..."
	@source venv_bulletproof/bin/activate && black src/
	@source venv_bulletproof/bin/activate && isort src/
	@echo "✅ Code formatted"

lint:  ## Run linting with flake8 and pylint
	@echo "🔍 Running linters..."
	@source venv_bulletproof/bin/activate && flake8 src/ --max-line-length=88 --extend-ignore=E203,W503 || true
	@echo "✅ Linting complete"

type-check:  ## Run type checking with mypy
	@echo "🏷️  Type checking..."
	@source venv_bulletproof/bin/activate && mypy src/ --ignore-missing-imports || true
	@echo "✅ Type checking complete"

security:  ## Run security analysis with bandit
	@echo "🔐 Security analysis..."
	@source venv_bulletproof/bin/activate && bandit -r src/ -f json -o security_scan.json --skip B101,B601 || true
	@echo "✅ Security analysis complete"

complexity:  ## Analyze code complexity with radon
	@echo "🧮 Complexity analysis..."
	@source venv_bulletproof/bin/activate && radon cc src/ -s || true
	@echo "✅ Complexity analysis complete"

test-quality:  ## Run quality assessment tests
	@echo "🧪 Running quality tests..."
	@python3 focused_quality_analysis.py
	@echo "✅ Quality assessment complete"

fix-syntax:  ## Fix common syntax errors
	@echo "🔧 Fixing syntax errors..."
	@python3 fix_syntax_errors.py
	@echo "✅ Syntax fixes complete"

install-tools:  ## Install code quality tools in virtual environment
	@echo "📦 Installing code quality tools..."
	@source venv_bulletproof/bin/activate && pip install black isort flake8 mypy pylint bandit radon pre-commit
	@echo "✅ Tools installed"

setup-hooks:  ## Set up pre-commit hooks
	@echo "🪝 Setting up pre-commit hooks..."
	@source venv_bulletproof/bin/activate && pre-commit install
	@echo "✅ Pre-commit hooks installed"

"""
    
    makefile_path = Path("Makefile")
    
    if makefile_path.exists():
        with open(makefile_path, 'r') as f:
            existing_content = f.read()
        
        if "# Code Quality Targets" not in existing_content:
            with open(makefile_path, 'a') as f:
                f.write(makefile_content)
            print("  ✅ Added code quality targets to Makefile")
        else:
            print("  ℹ️  Makefile already has code quality targets")
    else:
        with open(makefile_path, 'w') as f:
            f.write(makefile_content)
        print("  ✅ Created Makefile with code quality targets")

def create_github_workflow():
    """Create GitHub Actions workflow for code quality."""
    
    workflow_content = """name: Code Quality

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  quality:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.12'
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install black isort flake8 mypy pylint bandit radon
        if [ -f requirements.txt ]; then pip install -r requirements.txt; fi
    
    - name: Check syntax
      run: python -m py_compile src/**/*.py
    
    - name: Format check
      run: |
        black --check src/
        isort --check-only src/
    
    - name: Lint
      run: flake8 src/ --max-line-length=88 --extend-ignore=E203,W503
    
    - name: Type check
      run: mypy src/ --ignore-missing-imports
      continue-on-error: true
    
    - name: Security check
      run: bandit -r src/ --skip B101,B601
      continue-on-error: true
    
    - name: Complexity check
      run: radon cc src/ -s
      continue-on-error: true
    
    - name: Upload quality report
      uses: actions/upload-artifact@v3
      with:
        name: quality-report
        path: |
          security_scan.json
          focused_quality_report.json
      if: always()
"""
    
    workflows_dir = Path(".github/workflows")
    workflows_dir.mkdir(parents=True, exist_ok=True)
    
    workflow_path = workflows_dir / "code-quality.yml"
    
    if not workflow_path.exists():
        with open(workflow_path, 'w') as f:
            f.write(workflow_content)
        print("  ✅ Created GitHub Actions workflow for code quality")
    else:
        print("  ℹ️  GitHub Actions workflow already exists")

def install_tools():
    """Install code quality tools in the virtual environment."""
    
    venv_path = Path("venv_bulletproof/bin/activate")
    
    if not venv_path.exists():
        print("  ⚠️  Virtual environment not found at venv_bulletproof/")
        return False
    
    tools = [
        "black",
        "isort", 
        "flake8",
        "mypy",
        "pylint",
        "bandit",
        "radon",
        "pre-commit"
    ]
    
    print("  📦 Installing code quality tools...")
    
    for tool in tools:
        try:
            result = subprocess.run(
                [f"source {venv_path} && pip install {tool}"],
                shell=True,
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                print(f"    ✅ {tool}")
            else:
                print(f"    ❌ {tool}: {result.stderr.strip()}")
        except Exception as e:
            print(f"    ❌ {tool}: {e}")
    
    return True

def main():
    """Set up code quality tools and configurations."""
    
    print("🛠️  Setting up Code Quality Tools - AGENT 5 Follow-up")
    print("=" * 60)
    
    print("\n1. Creating tool configurations...")
    create_pyproject_config()
    create_pre_commit_config()
    
    print("\n2. Setting up Makefile targets...")
    create_makefile_targets()
    
    print("\n3. Creating GitHub Actions workflow...")
    create_github_workflow()
    
    print("\n4. Installing tools in virtual environment...")
    install_tools()
    
    print("\n" + "=" * 60)
    print("✅ Code Quality Setup Complete!")
    print("\n🚀 Next Steps:")
    print("1. Fix syntax errors: python3 fix_syntax_errors.py")
    print("2. Check setup: make check")
    print("3. Format code: make format")
    print("4. Run full quality check: make quality")
    print("5. Set up pre-commit hooks: make setup-hooks")
    print("\n📚 Available Commands:")
    print("- make quality     # Run all quality checks")
    print("- make format      # Format code")
    print("- make lint        # Run linters")
    print("- make type-check  # Check types")
    print("- make security    # Security analysis")
    print("- make complexity  # Complexity analysis")

if __name__ == "__main__":
    main()