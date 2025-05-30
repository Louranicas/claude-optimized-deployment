#!/bin/bash
# Setup git remotes for multiple services

echo "Setting up git remotes for multiple services..."

# GitHub (primary)
git remote add origin https://github.com/yourusername/claude-optimized-deployment.git 2>/dev/null || git remote set-url origin https://github.com/yourusername/claude-optimized-deployment.git

# GitLab
git remote add gitlab https://gitlab.com/yourusername/claude-optimized-deployment.git 2>/dev/null || git remote set-url gitlab https://gitlab.com/yourusername/claude-optimized-deployment.git

# Bitbucket
git remote add bitbucket https://bitbucket.org/yourusername/claude-optimized-deployment.git 2>/dev/null || git remote set-url bitbucket https://bitbucket.org/yourusername/claude-optimized-deployment.git

# Gitea (self-hosted example)
git remote add gitea https://git.yourdomain.com/yourusername/claude-optimized-deployment.git 2>/dev/null || git remote set-url gitea https://git.yourdomain.com/yourusername/claude-optimized-deployment.git

# Codeberg (open source alternative)
git remote add codeberg https://codeberg.org/yourusername/claude-optimized-deployment.git 2>/dev/null || git remote set-url codeberg https://codeberg.org/yourusername/claude-optimized-deployment.git

echo "Configured remotes:"
git remote -v

echo ""
echo "To push to all remotes at once, use:"
echo "git push --all origin"
echo "git push --all gitlab"
echo "git push --all bitbucket"
echo "git push --all codeberg"
echo ""
echo "Or create an alias to push to all:"
echo "git config alias.pushall '!git push origin --all && git push gitlab --all && git push bitbucket --all && git push codeberg --all'"