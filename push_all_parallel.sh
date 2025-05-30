#!/bin/bash
# Push to all git remotes in parallel

echo "🚀 Pushing to all remotes in parallel..."

# Function to push to a remote
push_to_remote() {
    local remote=$1
    echo "📤 Pushing to $remote..."
    git push "$remote" --all 2>&1 | sed "s/^/[$remote] /"
    if [ ${PIPESTATUS[0]} -eq 0 ]; then
        echo "✅ [$remote] Push successful"
    else
        echo "❌ [$remote] Push failed"
    fi
}

# Export the function so it's available to parallel processes
export -f push_to_remote

# Get all remotes
remotes=$(git remote)

# Push to all remotes in parallel
echo "$remotes" | xargs -P 5 -I {} bash -c 'push_to_remote "$@"' _ {}

echo "🎉 All parallel pushes completed!"