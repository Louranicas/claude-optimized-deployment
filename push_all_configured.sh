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
