#!/bin/bash
# Git hooks installer for CODE project
# Run this script to set up all Git hooks

set -e

HOOKS_DIR=".git/hooks"
SCRIPTS_DIR="scripts/git-hooks"

echo "🔧 Installing Git hooks for CODE project..."

# Create hooks directory if it doesn't exist
mkdir -p "$HOOKS_DIR"
mkdir -p "$SCRIPTS_DIR"

# Create pre-commit hook
cat > "$SCRIPTS_DIR/pre-commit" << 'EOF'
#!/bin/bash
set -e

echo "🔍 Running pre-commit checks..."

# 1. Check for large files
MAX_FILE_SIZE=10485760  # 10MB
for file in $(git diff --cached --name-only); do
    if [ -f "$file" ]; then
        file_size=$(wc -c < "$file")
        if [ $file_size -gt $MAX_FILE_SIZE ]; then
            echo "❌ Error: $file exceeds maximum file size (10MB)"
            echo "💡 Consider using Git LFS for large files"
            exit 1
        fi
    fi
done

# 2. Python linting and formatting
if git diff --cached --name-only | grep -q '\.py$'; then
    echo "🐍 Running Python checks..."
    
    # Check if tools are available
    if command -v black &> /dev/null; then
        black --check $(git diff --cached --name-only | grep '\.py$') || {
            echo "💡 Run 'black .' to fix formatting"
            exit 1
        }
    fi
    
    if command -v ruff &> /dev/null; then
        ruff $(git diff --cached --name-only | grep '\.py$') || exit 1
    fi
fi

# 3. Check for secrets
echo "🔒 Checking for secrets..."
if git diff --cached --name-only -z | xargs -0 grep -E "(api_key|secret|password|token)" | grep -v "example\|fake\|test\|TODO"; then
    echo "❌ Potential secrets detected! Please review your changes."
    echo "💡 Use environment variables or .env files for sensitive data"
    exit 1
fi

# 4. Validate JSON files
if git diff --cached --name-only | grep -q '\.json$'; then
    echo "📋 Validating JSON files..."
    for file in $(git diff --cached --name-only | grep '\.json$'); do
        if [ -f "$file" ]; then
            python -m json.tool "$file" > /dev/null || {
                echo "❌ Invalid JSON in $file"
                exit 1
            }
        fi
    done
fi

echo "✅ All pre-commit checks passed!"
EOF

# Create prepare-commit-msg hook
cat > "$SCRIPTS_DIR/prepare-commit-msg" << 'EOF'
#!/bin/bash

# Add issue number from branch name
BRANCH_NAME=$(git symbolic-ref --short HEAD)
ISSUE_NUMBER=$(echo $BRANCH_NAME | grep -oE '[0-9]+' | head -n1)

# Skip if it's a merge, squash, or amend
case "$2" in
    merge|squash|commit)
        exit 0
        ;;
esac

# Add issue reference if not already present
if [ -n "$ISSUE_NUMBER" ] && ! grep -q "#$ISSUE_NUMBER" "$1"; then
    # Read the current message
    MESSAGE=$(cat "$1")
    
    # Check if message is empty or just comments
    if ! echo "$MESSAGE" | grep -qE '^[^#]'; then
        exit 0
    fi
    
    # Add issue reference to the footer
    echo "" >> "$1"
    echo "Related to #$ISSUE_NUMBER" >> "$1"
fi
EOF

# Create commit-msg hook
cat > "$SCRIPTS_DIR/commit-msg" << 'EOF'
#!/bin/bash

# Validate commit message format
commit_regex='^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\(.+\))?: .{1,50}'
commit_msg=$(cat "$1")

# Skip merge commits
if echo "$commit_msg" | grep -q "^Merge"; then
    exit 0
fi

# Check format
if ! echo "$commit_msg" | grep -qE "$commit_regex"; then
    echo "❌ Invalid commit message format!"
    echo ""
    echo "📝 Format: <type>(<scope>): <subject>"
    echo ""
    echo "Types: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert"
    echo ""
    echo "Example: feat(deployment): add natural language parser"
    echo ""
    exit 1
fi

# Check subject line length
subject_line=$(echo "$commit_msg" | head -n1)
if [ ${#subject_line} -gt 72 ]; then
    echo "❌ Commit subject line too long (${#subject_line} > 72 characters)"
    exit 1
fi

echo "✅ Commit message validated"
EOF

# Create pre-push hook
cat > "$SCRIPTS_DIR/pre-push" << 'EOF'
#!/bin/bash

echo "🚀 Running pre-push checks..."

# 1. Check for WIP commits
if git log origin/$(git rev-parse --abbrev-ref HEAD)..HEAD --oneline | grep -i "wip\|work in progress"; then
    echo "❌ Found WIP commits. Please squash or amend before pushing."
    exit 1
fi

# 2. Run tests if available
if [ -f "pytest.ini" ] || [ -d "tests" ]; then
    echo "🧪 Running tests..."
    if command -v pytest &> /dev/null; then
        pytest tests/unit -x || {
            echo "❌ Tests failed. Fix before pushing."
            exit 1
        }
    fi
fi

# 3. Check branch protection
BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [[ "$BRANCH" =~ ^(main|master)$ ]]; then
    echo "⚠️  You're pushing directly to $BRANCH!"
    read -p "Are you sure? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo "✅ All pre-push checks passed!"
EOF

# Create post-commit hook
cat > "$SCRIPTS_DIR/post-commit" << 'EOF'
#!/bin/bash

# Update last commit info
echo "$(date '+%Y-%m-%d %H:%M:%S') - $(git log -1 --pretty=%H)" >> .git/last-commit

# Generate commit stats
STATS=$(git diff HEAD~ --shortstat)
echo "📊 Commit stats: $STATS"
EOF

# Make scripts executable
chmod +x "$SCRIPTS_DIR"/*

# Link hooks to .git/hooks
echo "🔗 Linking hooks..."
for hook in pre-commit prepare-commit-msg commit-msg pre-push post-commit; do
    if [ -f "$SCRIPTS_DIR/$hook" ]; then
        ln -sf "../../$SCRIPTS_DIR/$hook" "$HOOKS_DIR/$hook"
        echo "  ✓ Linked $hook"
    fi
done

# Install git-secrets if available
if command -v git-secrets &> /dev/null; then
    echo "🔒 Setting up git-secrets..."
    git secrets --install -f
    git secrets --register-aws
    echo "  ✓ git-secrets configured"
fi

# Set up Git LFS if needed
if command -v git-lfs &> /dev/null; then
    echo "📦 Initializing Git LFS..."
    git lfs install
    echo "  ✓ Git LFS initialized"
fi

# Configure Git settings
echo "⚙️  Configuring Git settings..."
git config core.hooksPath "$SCRIPTS_DIR"
git config commit.template .gitmessage

echo ""
echo "✅ Git hooks installation complete!"
echo ""
echo "📝 Next steps:"
echo "  1. Run 'git config --global commit.template .gitmessage' for global template"
echo "  2. Install Python tools: pip install black ruff mypy pytest"
echo "  3. Install git-secrets: https://github.com/awslabs/git-secrets"
echo ""
