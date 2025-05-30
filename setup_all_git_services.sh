#!/bin/bash
# Setup and push to all git services mentioned in GIT_PUSH_INSTRUCTIONS.md

echo "🚀 Setting up multiple git services"
echo "=================================="
echo ""

# Repository details
REPO_NAME="claude-optimized-deployment"
REPO_DESC="Claude-Optimized Deployment Engine (CODE) - AI-powered infrastructure automation platform with Rust-accelerated Circle of Experts system. Features 20x performance boost, 11 MCP servers, 51+ tools, and comprehensive security hardening. 85-90% complete."

# Get GitHub username from existing remote
GITHUB_USER=$(git remote get-url origin | sed -n 's/.*github.com[:/]\([^/]*\)\/.*/\1/p')
echo "GitHub username detected: $GITHUB_USER"
echo ""

# Function to setup a git service
setup_service() {
    local service=$1
    local remote_name=$2
    local url_pattern=$3
    local api_url=$4
    local create_cmd=$5
    
    echo "📦 Setting up $service..."
    
    # Ask if user has account
    read -p "Do you have a $service account? (y/n): " has_account
    if [[ ! $has_account =~ ^[Yy]$ ]]; then
        echo "⏭️  Skipping $service"
        return
    fi
    
    # Get username
    read -p "Enter your $service username [$GITHUB_USER]: " username
    username=${username:-$GITHUB_USER}
    
    # Get token/password
    echo "For $service authentication, you'll need:"
    echo "$create_cmd"
    read -s -p "Enter your $service token/password: " token
    echo ""
    
    # Create repository via API if possible
    if [ ! -z "$api_url" ]; then
        echo "Creating repository on $service..."
        case $service in
            "GitLab")
                curl -H "PRIVATE-TOKEN: $token" -X POST "$api_url" \
                    -d "name=$REPO_NAME" \
                    -d "description=$REPO_DESC" \
                    -d "visibility=public" 2>/dev/null
                ;;
            "Bitbucket")
                curl -u "$username:$token" -X POST "$api_url/$username/$REPO_NAME" \
                    -H "Content-Type: application/json" \
                    -d "{\"scm\": \"git\", \"is_private\": false, \"description\": \"$REPO_DESC\"}" 2>/dev/null
                ;;
        esac
    else
        echo "⚠️  Please create repository manually at: $create_cmd"
        read -p "Press Enter when repository is created..."
    fi
    
    # Configure remote
    local url=$(echo "$url_pattern" | sed "s/{USER}/$username/g" | sed "s/{TOKEN}/$token/g")
    git remote remove "$remote_name" 2>/dev/null
    git remote add "$remote_name" "$url"
    echo "✅ $service remote configured"
    echo ""
}

# GitLab
setup_service "GitLab" "gitlab" \
    "https://{USER}:{TOKEN}@gitlab.com/{USER}/$REPO_NAME.git" \
    "https://gitlab.com/api/v4/projects" \
    "Get token at: https://gitlab.com/-/profile/personal_access_tokens"

# Bitbucket
setup_service "Bitbucket" "bitbucket" \
    "https://{USER}:{TOKEN}@bitbucket.org/{USER}/$REPO_NAME.git" \
    "https://api.bitbucket.org/2.0/repositories" \
    "Get app password at: https://bitbucket.org/account/settings/app-passwords/"

# Codeberg
setup_service "Codeberg" "codeberg" \
    "https://{USER}:{TOKEN}@codeberg.org/{USER}/$REPO_NAME.git" \
    "" \
    "Create repo at: https://codeberg.org/repo/create"

# Show all configured remotes
echo "📍 Configured remotes:"
git remote -v
echo ""

# Create parallel push script
cat > push_to_all_services.sh << 'EOF'
#!/bin/bash
# Push to all configured git services in parallel

echo "🚀 Pushing to all configured services in parallel..."
echo ""

# Function to push to a remote
push_to_remote() {
    local remote=$1
    echo "📤 Pushing to $remote..."
    if git push "$remote" master --force 2>&1 | sed "s/^/[$remote] /"; then
        echo "✅ [$remote] Push successful"
        return 0
    else
        echo "❌ [$remote] Push failed"
        return 1
    fi
}

export -f push_to_remote

# Get all remotes
remotes=$(git remote)

# Count remotes
remote_count=$(echo "$remotes" | wc -l)
echo "Found $remote_count remote(s)"
echo ""

# Push to all remotes in parallel
echo "$remotes" | xargs -P 5 -I {} bash -c 'push_to_remote "$@"' _ {}

echo ""
echo "🎉 All push operations completed!"

# Show repository URLs
echo ""
echo "📌 Your repositories:"
for remote in $remotes; do
    url=$(git remote get-url "$remote" | sed 's/:[^@]*@/@/g')
    echo "- $remote: $url"
done
EOF

chmod +x push_to_all_services.sh

echo "✨ Setup complete!"
echo ""
echo "To push to all services in parallel, run:"
echo "  ./push_to_all_services.sh"
echo ""
echo "Repository description for manual creation:"
echo "$REPO_DESC"
echo ""
echo "Topics/Tags to add:"
echo "ai-automation, infrastructure-as-code, rust-python, deployment-automation,"
echo "circle-of-experts, mcp-protocol, devops, claude-ai, performance-optimization"