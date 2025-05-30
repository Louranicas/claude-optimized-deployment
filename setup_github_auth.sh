#!/bin/bash
# Setup GitHub authentication

echo "🔐 GitHub Authentication Setup"
echo "=============================="
echo ""
echo "Choose authentication method:"
echo "1) Personal Access Token (recommended)"
echo "2) SSH Key"
echo ""
read -p "Enter choice (1 or 2): " AUTH_CHOICE

if [ "$AUTH_CHOICE" = "1" ]; then
    echo ""
    echo "📋 Personal Access Token Setup"
    echo ""
    echo "1. Go to: https://github.com/settings/tokens"
    echo "2. Click 'Generate new token (classic)'"
    echo "3. Give it a name (e.g., 'claude-deployment')"
    echo "4. Select scopes: repo (all), workflow"
    echo "5. Generate and copy the token"
    echo ""
    read -p "Enter your GitHub username: " GH_USER
    read -s -p "Enter your Personal Access Token: " GH_TOKEN
    echo ""
    
    # Configure git to use the token
    git config --global credential.helper store
    git remote set-url origin https://${GH_USER}:${GH_TOKEN}@github.com/${GH_USER}/claude-optimized-deployment.git
    
    echo "✅ Token authentication configured!"
    
elif [ "$AUTH_CHOICE" = "2" ]; then
    echo ""
    echo "🔑 SSH Key Setup"
    echo ""
    
    # Check if SSH key exists
    if [ ! -f ~/.ssh/id_rsa ]; then
        echo "Generating SSH key..."
        ssh-keygen -t rsa -b 4096 -C "your-email@example.com" -f ~/.ssh/id_rsa -N ""
    fi
    
    echo "Your SSH public key:"
    echo ""
    cat ~/.ssh/id_rsa.pub
    echo ""
    echo "📋 Add this key to GitHub:"
    echo "1. Go to: https://github.com/settings/keys"
    echo "2. Click 'New SSH key'"
    echo "3. Paste the key above"
    echo "4. Save"
    echo ""
    read -p "Press Enter after adding the key to GitHub..."
    
    # Configure git to use SSH
    read -p "Enter your GitHub username: " GH_USER
    git remote set-url origin git@github.com:${GH_USER}/claude-optimized-deployment.git
    
    # Test SSH connection
    echo "Testing SSH connection..."
    ssh -T git@github.com
    
    echo "✅ SSH authentication configured!"
fi

echo ""
echo "🚀 Ready to push! Try:"
echo "  git push origin --all"
echo ""
echo "Or push to multiple remotes in parallel:"
echo "  ./push_all_configured.sh"