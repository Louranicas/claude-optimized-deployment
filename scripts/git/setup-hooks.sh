#!/bin/bash
# Setup Git hooks for CODE project

echo "🔧 Setting up Git hooks for CODE project..."

# Get the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
HOOKS_DIR="$PROJECT_ROOT/.git-hooks"
GIT_HOOKS_DIR="$PROJECT_ROOT/.git/hooks"

# Check if we're in a git repository
if [ ! -d "$PROJECT_ROOT/.git" ]; then
    echo "❌ Error: Not in a git repository!"
    echo "Please run this script from the project root."
    exit 1
fi

# Create hooks directory if it doesn't exist
mkdir -p "$GIT_HOOKS_DIR"

# List of hooks to install
HOOKS=(
    "pre-commit"
    "commit-msg"
    "pre-push"
)

echo "📁 Installing hooks from: $HOOKS_DIR"
echo "📁 Installing hooks to: $GIT_HOOKS_DIR"
echo ""

# Install each hook
for hook in "${HOOKS[@]}"; do
    source_hook="$HOOKS_DIR/$hook"
    target_hook="$GIT_HOOKS_DIR/$hook"
    
    if [ -f "$source_hook" ]; then
        echo -n "Installing $hook hook... "
        
        # Backup existing hook if it exists
        if [ -f "$target_hook" ] && [ ! -L "$target_hook" ]; then
            echo -n "(backing up existing) "
            mv "$target_hook" "$target_hook.backup"
        fi
        
        # Create symlink
        ln -sf "$source_hook" "$target_hook"
        
        # Make executable
        chmod +x "$source_hook"
        
        echo "✅"
    else
        echo "⚠️  $hook hook not found at $source_hook"
    fi
done

# Configure git to use hooks
echo ""
echo "Configuring Git settings..."

# Set commit template
if [ -f "$PROJECT_ROOT/.gitmessage" ]; then
    git config commit.template .gitmessage
    echo "✅ Commit template configured"
fi

# Enable commit signing if GPG is available
if command -v gpg &> /dev/null; then
    echo "💡 GPG is available. Consider setting up commit signing:"
    echo "   git config --global user.signingkey YOUR_KEY_ID"
    echo "   git config --global commit.gpgsign true"
fi

# Install additional tools if needed
echo ""
echo "Checking for required tools..."

# Python tools
if command -v pip &> /dev/null; then
    echo -n "Checking Python tools... "
    
    # Check for flake8
    if ! command -v flake8 &> /dev/null; then
        echo ""
        echo "  📦 Installing flake8..."
        pip install flake8
    fi
    
    # Check for black
    if ! command -v black &> /dev/null; then
        echo ""
        echo "  📦 Installing black..."
        pip install black
    fi
    
    # Check for safety
    if ! command -v safety &> /dev/null; then
        echo ""
        echo "  📦 Installing safety..."
        pip install safety
    fi
    
    # Check for detect-secrets
    if ! command -v detect-secrets &> /dev/null; then
        echo ""
        echo "  📦 Installing detect-secrets..."
        pip install detect-secrets
    fi
    
    echo "✅"
fi

# Create initial secrets baseline if detect-secrets is available
if command -v detect-secrets &> /dev/null && [ ! -f "$PROJECT_ROOT/.secrets.baseline" ]; then
    echo "Creating secrets baseline..."
    cd "$PROJECT_ROOT"
    detect-secrets scan --baseline .secrets.baseline
    echo "✅ Secrets baseline created"
fi

# Set up Git LFS if available
if command -v git-lfs &> /dev/null; then
    echo "Setting up Git LFS..."
    git lfs install
    echo "✅ Git LFS configured"
fi

# Apply recommended Git configurations
echo ""
echo "Applying recommended Git configurations..."

git config core.autocrlf input
git config core.whitespace fix,trailing-space,space-before-tab
git config pull.rebase true
git config fetch.prune true
git config rerere.enabled true
git config diff.algorithm histogram

echo "✅ Git configurations applied"

# Create global gitignore if it doesn't exist
GLOBAL_GITIGNORE="$HOME/.gitignore_global"
if [ ! -f "$GLOBAL_GITIGNORE" ]; then
    echo ""
    echo "Creating global gitignore..."
    cat > "$GLOBAL_GITIGNORE" << EOF
# OS files
.DS_Store
Thumbs.db
Desktop.ini

# Editor files
*.swp
*.swo
*~
.idea/
.vscode/
*.sublime-*

# Logs
*.log
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Environment
.env.local
.env.*.local

# Dependencies
node_modules/
__pycache__/
*.pyc
EOF
    
    git config --global core.excludesfile "$GLOBAL_GITIGNORE"
    echo "✅ Global gitignore created"
fi

# Summary
echo ""
echo "✅ Git hooks setup complete!"
echo ""
echo "Installed hooks:"
echo "  • pre-commit  - Runs checks before each commit"
echo "  • commit-msg  - Validates commit message format"
echo "  • pre-push    - Final checks before pushing"
echo ""
echo "💡 Tips:"
echo "  • Use 'git commit --no-verify' to skip hooks (use sparingly!)"
echo "  • Run 'git config --global init.templatedir ~/.git-templates' to use hooks in new repos"
echo "  • Check hook output carefully - they're there to help!"
echo ""
echo "📚 For more information, see: docs/git-optimization/README.md"
