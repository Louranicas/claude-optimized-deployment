#!/bin/bash
# Configure git remotes with actual URLs

echo "🔧 Git Remote Configuration"
echo "=========================="
echo ""

# Get current username from git config or prompt
CURRENT_USER=$(git config user.name 2>/dev/null)
if [ -z "$CURRENT_USER" ]; then
    read -p "Enter your GitHub username: " GITHUB_USER
else
    read -p "Enter your GitHub username [$CURRENT_USER]: " GITHUB_USER
    GITHUB_USER=${GITHUB_USER:-$CURRENT_USER}
fi

# Get repository name
REPO_NAME="claude-optimized-deployment"
read -p "Enter repository name [$REPO_NAME]: " INPUT_REPO
REPO_NAME=${INPUT_REPO:-$REPO_NAME}

echo ""
echo "Configuring remotes for: $GITHUB_USER/$REPO_NAME"
echo ""

# Function to configure a remote
configure_remote() {
    local remote_name=$1
    local url_template=$2
    local url=$(echo "$url_template" | sed "s/{USER}/$GITHUB_USER/g" | sed "s/{REPO}/$REPO_NAME/g")
    
    echo "📌 Configuring $remote_name: $url"
    git remote remove "$remote_name" 2>/dev/null
    git remote add "$remote_name" "$url"
}

# Configure main remotes
configure_remote "origin" "https://github.com/{USER}/{REPO}.git"
configure_remote "github-ssh" "git@github.com:{USER}/{REPO}.git"

# Ask about other services
echo ""
read -p "Do you have a GitLab account? (y/n): " HAS_GITLAB
if [[ $HAS_GITLAB =~ ^[Yy]$ ]]; then
    read -p "GitLab username [$GITHUB_USER]: " GITLAB_USER
    GITLAB_USER=${GITLAB_USER:-$GITHUB_USER}
    configure_remote "gitlab" "https://gitlab.com/$GITLAB_USER/{REPO}.git"
fi

read -p "Do you have a Bitbucket account? (y/n): " HAS_BITBUCKET
if [[ $HAS_BITBUCKET =~ ^[Yy]$ ]]; then
    read -p "Bitbucket username [$GITHUB_USER]: " BITBUCKET_USER
    BITBUCKET_USER=${BITBUCKET_USER:-$GITHUB_USER}
    configure_remote "bitbucket" "https://bitbucket.org/$BITBUCKET_USER/{REPO}.git"
fi

read -p "Do you have a Codeberg account? (y/n): " HAS_CODEBERG
if [[ $HAS_CODEBERG =~ ^[Yy]$ ]]; then
    read -p "Codeberg username [$GITHUB_USER]: " CODEBERG_USER
    CODEBERG_USER=${CODEBERG_USER:-$GITHUB_USER}
    configure_remote "codeberg" "https://codeberg.org/$CODEBERG_USER/{REPO}.git"
fi

# Show configured remotes
echo ""
echo "✅ Configured remotes:"
git remote -v

# Create push all script
cat > push_all_configured.sh << 'EOF'
#!/bin/bash
# Push to all configured remotes in parallel

echo "🚀 Pushing to all configured remotes in parallel..."

# Get all remotes
remotes=$(git remote)

# Function to push to a remote
push_to_remote() {
    local remote=$1
    echo "📤 Pushing to $remote..."
    if git push "$remote" --all 2>&1 | sed "s/^/[$remote] /"; then
        echo "✅ [$remote] Push successful"
        return 0
    else
        echo "❌ [$remote] Push failed"
        return 1
    fi
}

export -f push_to_remote

# Push to all remotes in parallel
echo "$remotes" | xargs -P 5 -I {} bash -c 'push_to_remote "$@"' _ {}

echo ""
echo "🎉 Push operation completed!"
EOF

chmod +x push_all_configured.sh

echo ""
echo "✨ Setup complete!"
echo ""
echo "To push to all configured remotes in parallel, run:"
echo "  ./push_all_configured.sh"
echo ""
echo "To push to a specific remote:"
echo "  git push origin --all"
echo "  git push github-ssh --all"
echo ""
echo "To push current branch to all remotes:"
echo "  git push --all"