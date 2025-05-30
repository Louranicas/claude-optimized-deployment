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
