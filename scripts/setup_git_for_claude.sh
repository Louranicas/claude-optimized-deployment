 "claude-reviewed"'
    gh alias set issues-triage 'issue list --label "needs-triage"'
    gh alias set my-prs 'pr list --author @me'
    gh alias set review-requests 'pr list --reviewer @me'
    echo "✅ GitHub CLI aliases configured"
}

# Function to create commit message generator
create_commit_generator() {
    echo -e "\n${GREEN}🤖 Creating commit message generator...${NC}"
    
    mkdir -p scripts
    cat > scripts/generate_commit_message.py << 'EOF'
#!/usr/bin/env python3
"""
Generate semantic commit messages based on staged changes.
This is a placeholder for Claude Code integration.
"""

import subprocess
import sys
import re

def get_staged_files():
    """Get list of staged files."""
    result = subprocess.run(
        ['git', 'diff', '--cached', '--name-only'],
        capture_output=True, text=True
    )
    return result.stdout.strip().split('\n') if result.stdout else []

def analyze_changes():
    """Analyze staged changes to determine commit type and scope."""
    files = get_staged_files()
    if not files:
        return "chore", "general", "empty commit"
    
    # Determine type based on files
    if any('test' in f for f in files):
        type_ = "test"
    elif any('docs' in f or f.endswith('.md') for f in files):
        type_ = "docs"
    elif any('fix' in subprocess.run(['git', 'diff', '--cached'], capture_output=True, text=True).stdout.lower() for f in files):
        type_ = "fix"
    else:
        type_ = "feat"
    
    # Determine scope
    if any('circle_of_experts' in f for f in files):
        scope = "circle-of-experts"
    elif any('deployment' in f for f in files):
        scope = "deployment"
    elif any('api' in f for f in files):
        scope = "api"
    elif any('.github' in f for f in files):
        scope = "ci"
    else:
        scope = "general"
    
    # Generate subject (this would be enhanced with Claude Code)
    subject = "update " + ", ".join(files[:2])
    if len(files) > 2:
        subject += f" and {len(files) - 2} more files"
    
    return type_, scope, subject

def main():
    """Generate commit message."""
    type_, scope, subject = analyze_changes()
    
    # Format message
    if scope != "general":
        message = f"{type_}({scope}): {subject}"
    else:
        message = f"{type_}: {subject}"
    
    print(message)

if __name__ == "__main__":
    main()
EOF
    
    chmod +x scripts/generate_commit_message.py
    echo "✅ Commit message generator created"
}

# Function to setup branch protection
setup_branch_protection() {
    echo -e "\n${GREEN}🔒 Setting up branch protection...${NC}"
    
    if ! command_exists gh; then
        echo -e "${YELLOW}Skipping branch protection (GitHub CLI required)${NC}"
        return
    fi
    
    # Get repository info
    REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner)
    
    echo "Setting up protection for main branch..."
    
    # Create branch protection rules
    gh api repos/$REPO/branches/main/protection \
        --method PUT \
        --field required_status_checks='{"strict":true,"contexts":["ci/lint","ci/test","ci/security"]}' \
        --field enforce_admins=false \
        --field required_pull_request_reviews='{"required_approving_review_count":2,"dismiss_stale_reviews":true,"require_code_owner_reviews":true}' \
        --field restrictions=null \
        --field allow_force_pushes=false \
        --field allow_deletions=false \
        2>/dev/null || echo "⚠️  Branch protection requires admin access"
}

# Function to create labels
create_github_labels() {
    echo -e "\n${GREEN}🏷️  Creating GitHub labels...${NC}"
    
    if ! command_exists gh; then
        echo -e "${YELLOW}Skipping label creation (GitHub CLI required)${NC}"
        return
    fi
    
    # Define labels
    declare -A labels=(
        ["P0-critical"]="d73a4a"
        ["P1-high"]="ff9800"
        ["P2-medium"]="4caf50"
        ["P3-low"]="2196f3"
        ["claude-reviewed"]="7057ff"
        ["circle-of-experts"]="0075ca"
        ["deployment-engine"]="f44336"
        ["needs-deployment-engine"]="e91e63"
        ["ai-enhanced"]="a2eeef"
        ["has-tests"]="0e8a16"
        ["breaking-change"]="d93f0b"
    )
    
    # Create each label
    for label in "${!labels[@]}"; do
        gh label create "$label" --color "${labels[$label]}" 2>/dev/null || \
        echo "  Label '$label' already exists"
    done
    
    echo "✅ Labels configured"
}

# Function to create helper scripts
create_helper_scripts() {
    echo -e "\n${GREEN}📜 Creating helper scripts...${NC}"
    
    mkdir -p scripts/git
    
    # Create PR helper
    cat > scripts/git/create-pr.sh << 'EOF'
#!/bin/bash
# Smart PR creation with Claude Code

# Get current branch
BRANCH=$(git branch --show-current)

# Check if branch has upstream
if ! git rev-parse --abbrev-ref @{u} >/dev/null 2>&1; then
    echo "Pushing branch to origin..."
    git push -u origin HEAD
fi

# Create PR with template
gh pr create \
    --title "$(git log -1 --pretty=%s)" \
    --body-file .github/PULL_REQUEST_TEMPLATE.md \
    --label "claude-reviewed" \
    --web
EOF
    
    # Create release helper
    cat > scripts/git/create-release.sh << 'EOF'
#!/bin/bash
# Create a new release

VERSION_TYPE=${1:-patch}  # patch, minor, or major

echo "Creating $VERSION_TYPE release..."

# Ensure we're on main
git checkout main
git pull --rebase

# Run tests
echo "Running tests..."
make test || exit 1

# Create release
npm version $VERSION_TYPE -m "chore(release): %s"
git push && git push --tags

echo "Release created! CI will handle the rest."
EOF
    
    chmod +x scripts/git/*.sh
    echo "✅ Helper scripts created"
}

# Function to show next steps
show_next_steps() {
    echo -e "\n${BLUE}✨ Setup Complete!${NC}"
    echo "=================="
    echo -e "\n${GREEN}Next steps:${NC}"
    echo "1. Test your setup:"
    echo "   git ai-commit         # AI-powered commit"
    echo "   git visual-log        # See pretty git log"
    echo "   git smart-diff        # Better diffs"
    echo ""
    echo "2. Create your first PR:"
    echo "   git checkout -b feature/amazing-feature"
    echo "   # make changes"
    echo "   git ai-commit"
    echo "   git ai-pr"
    echo ""
    echo "3. Configure GPG signing (recommended):"
    echo "   gpg --full-generate-key"
    echo "   git config --global user.signingkey YOUR_KEY_ID"
    echo "   git config --global commit.gpgsign true"
    echo ""
    echo -e "${YELLOW}📚 Documentation:${NC}"
    echo "   See docs/GIT_GITHUB_GUIDE.md for complete guide"
}

# Main execution
main() {
    echo -e "${YELLOW}This script will configure Git and GitHub for Claude Code integration.${NC}"
    echo -e "${YELLOW}Some steps require GitHub CLI (gh) to be installed and authenticated.${NC}"
    echo ""
    read -p "Continue? (y/n) " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 1
    fi
    
    # Run setup steps
    setup_git_config
    create_commit_generator
    install_precommit
    setup_github_cli
    create_github_labels
    setup_branch_protection
    create_helper_scripts
    
    # Show completion message
    show_next_steps
}

# Run main function
main
