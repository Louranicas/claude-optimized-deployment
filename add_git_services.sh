#!/bin/bash
# Quick setup for additional git services

echo "🌐 Additional Git Service Setup"
echo "=============================="
echo ""
echo "Your GitHub repository is already set up at:"
echo "https://github.com/Louranicas/claude-optimized-deployment"
echo ""
echo "Here's how to add other services if needed:"
echo ""

# GitLab
echo "📘 GitLab Setup:"
echo "1. Create account at: https://gitlab.com/users/sign_up"
echo "2. Create new project at: https://gitlab.com/projects/new"
echo "3. Get personal access token at: https://gitlab.com/-/profile/personal_access_tokens"
echo "4. Add remote:"
echo "   git remote add gitlab https://YOUR_USERNAME:YOUR_TOKEN@gitlab.com/YOUR_USERNAME/claude-optimized-deployment.git"
echo ""

# Bitbucket
echo "📙 Bitbucket Setup:"
echo "1. Create account at: https://bitbucket.org/account/signup/"
echo "2. Create repository at: https://bitbucket.org/repo/create"
echo "3. Get app password at: https://bitbucket.org/account/settings/app-passwords/"
echo "4. Add remote:"
echo "   git remote add bitbucket https://YOUR_USERNAME:APP_PASSWORD@bitbucket.org/YOUR_USERNAME/claude-optimized-deployment.git"
echo ""

# Codeberg (Open Source Alternative)
echo "📗 Codeberg Setup (Open Source Alternative):"
echo "1. Create account at: https://codeberg.org/user/sign_up"
echo "2. Create repository at: https://codeberg.org/repo/create"
echo "3. Add remote:"
echo "   git remote add codeberg https://YOUR_USERNAME@codeberg.org/YOUR_USERNAME/claude-optimized-deployment.git"
echo ""

# GitHub Mirror (for redundancy)
echo "🔄 GitHub Mirror (using SSH):"
echo "1. Add SSH key to GitHub: https://github.com/settings/keys"
echo "2. Add SSH remote:"
echo "   git remote add github-ssh git@github.com:Louranicas/claude-optimized-deployment.git"
echo ""

# Show current remote
echo "📍 Current remote:"
git remote -v | grep origin | head -1
echo ""

echo "💡 Quick push to GitHub:"
echo "   git push origin master"
echo ""
echo "💡 To push to multiple remotes after setting them up:"
echo "   ./push_to_all_services.sh"