#!/bin/bash
# Git workflow helper functions for CODE project

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Function to create feature branch with ticket number
git-feature() {
    if [ -z "$1" ]; then
        echo "Usage: git-feature <ticket-number> <description>"
        echo "Example: git-feature CODE-123 add-deployment-api"
        return 1
    fi
    
    ticket="$1"
    shift
    description="$*"
    
    # Convert description to kebab-case
    description_kebab=$(echo "$description" | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
    branch_name="feature/${ticket}-${description_kebab}"
    
    echo -e "${GREEN}Creating feature branch: $branch_name${NC}"
    git checkout -b "$branch_name" develop
}

# Function to create fix branch
git-fix() {
    if [ -z "$1" ]; then
        echo "Usage: git-fix <ticket-number> <description>"
        echo "Example: git-fix CODE-456 memory-leak"
        return 1
    fi
    
    ticket="$1"
    shift
    description="$*"
    
    description_kebab=$(echo "$description" | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
    branch_name="fix/${ticket}-${description_kebab}"
    
    echo -e "${GREEN}Creating fix branch: $branch_name${NC}"
    git checkout -b "$branch_name" develop
}

# Function to clean up merged branches
git-cleanup() {
    echo -e "${YELLOW}🧹 Cleaning up merged branches...${NC}"
    
    # Get current branch
    current_branch=$(git branch --show-current)
    
    # Switch to main if on a branch to be deleted
    if [[ "$current_branch" != "main" && "$current_branch" != "develop" ]]; then
        echo "Switching to main branch for cleanup..."
        git checkout main
    fi
    
    # Delete merged local branches
    echo -e "\n${YELLOW}Local branches to delete:${NC}"
    git branch --merged | grep -v "\*\|main\|develop" | while read -r branch; do
        echo "  - $branch"
    done
    
    if [ -n "$(git branch --merged | grep -v '\*\|main\|develop')" ]; then
        read -p "Delete these branches? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            git branch --merged | grep -v "\*\|main\|develop" | xargs -n 1 git branch -d
            echo -e "${GREEN}✅ Local branches cleaned${NC}"
        fi
    else
        echo -e "${GREEN}No merged branches to clean${NC}"
    fi
    
    # Prune remote branches
    echo -e "\n${YELLOW}Pruning remote branches...${NC}"
    git remote prune origin
    
    # Show remaining branches
    echo -e "\n${YELLOW}Remaining branches:${NC}"
    git branch -a | head -20
}

# Function to show detailed git statistics
git-stats() {
    echo -e "${YELLOW}📊 Git Repository Statistics${NC}"
    echo "============================"
    
    # Top contributors
    echo -e "\n${YELLOW}Top 10 Contributors:${NC}"
    git shortlog -sn --all --no-merges | head -10 | nl
    
    # Commit activity by day
    echo -e "\n${YELLOW}Commits by Day of Week:${NC}"
    git log --date=format:'%A' --pretty=format:'%ad' | sort | uniq -c | sort -nr
    
    # Commit activity by hour
    echo -e "\n${YELLOW}Commits by Hour:${NC}"
    git log --date=format:'%H' --pretty=format:'%ad' | sort -n | uniq -c
    
    # Files with most changes
    echo -e "\n${YELLOW}Files with Most Changes:${NC}"
    git log --pretty=format: --name-only | grep -v '^$' | sort | uniq -c | sort -rg | head -10
    
    # Recent activity
    echo -e "\n${YELLOW}Recent Commit Activity:${NC}"
    for i in {0..6}; do
        date=$(date -d "$i days ago" +%Y-%m-%d)
        count=$(git log --since="$date 00:00" --until="$date 23:59" --oneline 2>/dev/null | wc -l)
        printf "%s: %3d commits\n" "$date" "$count"
    done
    
    # Code churn (last 30 days)
    echo -e "\n${YELLOW}Code Churn (Last 30 Days):${NC}"
    git log --since="30 days ago" --pretty=tformat: --numstat | \
        awk '{ add += $1; subs += $2 } END { printf "Added lines: %s\nDeleted lines: %s\nTotal churn: %s\n", add, subs, add+subs }'
}

# Function to find large files in git history
git-find-large() {
    threshold=${1:-1048576}  # Default 1MB
    
    echo -e "${YELLOW}🔍 Finding files larger than $(($threshold / 1048576))MB in history...${NC}"
    
    # Use git-filter-repo if available, otherwise fallback
    if command -v git-filter-repo &> /dev/null; then
        git-filter-repo --analyze
        echo -e "\n${GREEN}Check .git/filter-repo/analysis for detailed results${NC}"
    else
        # Fallback method
        git rev-list --objects --all |
        git cat-file --batch-check='%(objecttype) %(objectname) %(objectsize) %(rest)' |
        sed -n 's/^blob //p' |
        awk -v threshold="$threshold" '$2 >= threshold' |
        sort -nrk2 |
        head -20 |
        while IFS= read -r line; do
            size=$(echo "$line" | awk '{print $2}')
            size_human=$(numfmt --to=iec --suffix=B "$size" 2>/dev/null || echo "${size}B")
            file=$(echo "$line" | cut -d' ' -f3-)
            printf "%10s %s\n" "$size_human" "$file"
        done
    fi
}

# Function to show branch history graph
git-graph() {
    local count=${1:-20}
    echo -e "${YELLOW}📈 Branch History (last $count commits)${NC}"
    git log --graph --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr) %C(bold blue)<%an>%Creset' --abbrev-commit -n "$count"
}

# Function to sync fork with upstream
git-sync-fork() {
    # Check if upstream is configured
    if ! git remote | grep -q upstream; then
        echo -e "${RED}❌ No upstream remote found${NC}"
        echo "Add upstream with: git remote add upstream <upstream-url>"
        return 1
    fi
    
    echo -e "${YELLOW}🔄 Syncing fork with upstream...${NC}"
    
    # Fetch upstream
    git fetch upstream
    
    # Checkout main
    git checkout main
    
    # Merge upstream/main
    git merge upstream/main
    
    # Push to origin
    git push origin main
    
    # Also sync develop if it exists
    if git show-ref --verify --quiet refs/heads/develop; then
        git checkout develop
        git merge upstream/develop 2>/dev/null || git merge upstream/main
        git push origin develop
    fi
    
    echo -e "${GREEN}✅ Fork synced!${NC}"
}

# Function to create a release
git-release() {
    if [ -z "$1" ]; then
        echo "Usage: git-release <version>"
        echo "Example: git-release 1.2.0"
        return 1
    fi
    
    version=$1
    
    echo -e "${YELLOW}📦 Creating release v$version${NC}"
    
    # Create release branch
    git checkout -b "release/$version" develop
    
    echo -e "\n${GREEN}Release branch created: release/$version${NC}"
    echo "Next steps:"
    echo "1. Update version numbers"
    echo "2. Update CHANGELOG.md"
    echo "3. Run final tests"
    echo "4. Merge to main: git checkout main && git merge --no-ff release/$version"
    echo "5. Tag release: git tag -a v$version -m 'Release v$version'"
    echo "6. Merge back to develop: git checkout develop && git merge --no-ff release/$version"
    echo "7. Push everything: git push --all && git push --tags"
}

# Function to undo last commit safely
git-undo() {
    echo -e "${YELLOW}↩️  Undoing last commit...${NC}"
    
    # Show what will be undone
    echo -e "\nThis commit will be undone:"
    git log -1 --oneline
    
    read -p "Are you sure? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        git reset --soft HEAD~1
        echo -e "${GREEN}✅ Commit undone (changes preserved)${NC}"
    else
        echo -e "${RED}❌ Cancelled${NC}"
    fi
}

# Function to show file history with diffs
git-file-history() {
    if [ -z "$1" ]; then
        echo "Usage: git-file-history <file-path>"
        return 1
    fi
    
    echo -e "${YELLOW}📜 History for: $1${NC}"
    git log --follow --patch -- "$1" | less
}

# Function to find commits by message
git-find-commit() {
    if [ -z "$1" ]; then
        echo "Usage: git-find-commit <search-term>"
        return 1
    fi
    
    echo -e "${YELLOW}🔍 Searching commits for: $1${NC}"
    git log --all --grep="$1" --oneline
}

# Function to show today's work
git-today() {
    echo -e "${YELLOW}📅 Today's Git Activity${NC}"
    echo "====================="
    
    # Today's commits
    echo -e "\n${YELLOW}Commits:${NC}"
    git log --since=midnight --oneline --graph --decorate
    
    # Files changed today
    echo -e "\n${YELLOW}Files changed:${NC}"
    git diff --stat @{midnight}
}

# Export all functions
export -f git-feature
export -f git-fix
export -f git-cleanup
export -f git-stats
export -f git-find-large
export -f git-graph
export -f git-sync-fork
export -f git-release
export -f git-undo
export -f git-file-history
export -f git-find-commit
export -f git-today

# Show available commands
echo -e "${GREEN}Git workflow helpers loaded!${NC}"
echo "Available commands:"
echo "  git-feature <ticket> <desc>  - Create feature branch"
echo "  git-fix <ticket> <desc>      - Create fix branch"
echo "  git-cleanup                  - Clean merged branches"
echo "  git-stats                    - Show repository statistics"
echo "  git-find-large [size]        - Find large files in history"
echo "  git-graph [count]            - Show branch graph"
echo "  git-sync-fork                - Sync fork with upstream"
echo "  git-release <version>        - Start release process"
echo "  git-undo                     - Undo last commit (safe)"
echo "  git-file-history <file>      - Show file history"
echo "  git-find-commit <term>       - Find commits by message"
echo "  git-today                    - Show today's activity"
