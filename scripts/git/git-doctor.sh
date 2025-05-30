#!/bin/bash
# Git Doctor - Repository Health Check and Repair Script
# For CODE Project

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🏥 Git Doctor - Repository Health Check${NC}"
echo "======================================"
echo ""

# Initialize counters
issues_found=0
issues_fixed=0

# Function to check and report issues
check_issue() {
    local check_name=$1
    local check_command=$2
    local fix_command=${3:-""}
    local description=${4:-""}
    
    echo -n "Checking ${check_name}... "
    
    if eval "$check_command" &>/dev/null; then
        echo -e "${GREEN}✅ OK${NC}"
        return 0
    else
        echo -e "${RED}❌ ISSUE FOUND${NC}"
        ((issues_found++))
        
        if [ -n "$description" ]; then
            echo "  ↳ $description"
        fi
        
        if [ -n "$fix_command" ]; then
            echo -n "  ↳ Attempting fix... "
            if eval "$fix_command" &>/dev/null; then
                echo -e "${GREEN}✅ FIXED${NC}"
                ((issues_fixed++))
            else
                echo -e "${RED}❌ FAILED${NC}"
            fi
        fi
        return 1
    fi
}

# 1. Check repository integrity
check_issue "repository integrity" \
    "git fsck --full --no-reflogs" \
    "git fsck --full --no-reflogs --lost-found" \
    "Repository corruption detected"

# 2. Check index
check_issue "index integrity" \
    "git status &>/dev/null" \
    "rm -f .git/index && git reset" \
    "Index corruption detected"

# 3. Check for lock files
echo -n "Checking for lock files... "
lock_files=$(find .git -name "*.lock" 2>/dev/null || true)
if [ -z "$lock_files" ]; then
    echo -e "${GREEN}✅ None found${NC}"
else
    echo -e "${RED}❌ Found lock files${NC}"
    ((issues_found++))
    echo "$lock_files" | while read -r lock; do
        echo "  ↳ Removing: $lock"
        rm -f "$lock"
        ((issues_fixed++))
    done
fi

# 4. Check remote connectivity
echo -n "Checking remote connectivity... "
if git ls-remote &>/dev/null; then
    echo -e "${GREEN}✅ OK${NC}"
else
    echo -e "${YELLOW}⚠️  Cannot reach remote${NC}"
    echo "  ↳ Check your internet connection or remote URL"
fi

# 5. Check for large files not in LFS
echo -n "Checking for large files (>50MB)... "
large_files=$(find . -type f -size +50M -not -path "./.git/*" 2>/dev/null | head -10 || true)
if [ -z "$large_files" ]; then
    echo -e "${GREEN}✅ None found${NC}"
else
    count=$(echo "$large_files" | wc -l)
    echo -e "${YELLOW}⚠️  Found $count large file(s)${NC}"
    echo "$large_files" | while read -r file; do
        size=$(du -h "$file" | cut -f1)
        echo "  ↳ $file ($size)"
    done
    echo "  ↳ Consider using Git LFS for these files"
fi

# 6. Check configuration
check_issue "configuration" \
    "git config --list" \
    "" \
    "Git configuration error"

# 7. Check commit graph
check_issue "commit graph" \
    "test -f .git/objects/info/commit-graph" \
    "git commit-graph write --reachable" \
    "Commit graph missing (affects performance)"

# 8. Check maintenance status
check_issue "automatic maintenance" \
    "test $(git config --get maintenance.auto) = 'true'" \
    "git maintenance start" \
    "Automatic maintenance not enabled"

# 9. Check for uncommitted changes
echo -n "Checking for uncommitted changes... "
if git diff-index --quiet HEAD -- 2>/dev/null; then
    echo -e "${GREEN}✅ Working directory clean${NC}"
else
    echo -e "${YELLOW}⚠️  Uncommitted changes found${NC}"
    changes=$(git status --porcelain | wc -l)
    echo "  ↳ $changes file(s) with changes"
fi

# 10. Check for unpushed commits
echo -n "Checking for unpushed commits... "
if [ -z "$(git log @{u}.. 2>/dev/null)" ]; then
    echo -e "${GREEN}✅ All commits pushed${NC}"
else
    unpushed=$(git log @{u}.. --oneline 2>/dev/null | wc -l)
    echo -e "${YELLOW}⚠️  $unpushed unpushed commit(s)${NC}"
fi

# Performance metrics
echo ""
echo -e "${BLUE}📊 Performance Metrics${NC}"
echo "-------------------"

# Repository size
repo_size=$(du -sh .git 2>/dev/null | cut -f1)
echo "Repository size: $repo_size"

# Object counts
object_info=$(git count-objects -v)
echo "Objects in database: $(echo "$object_info" | grep "^count:" | awk '{print $2}')"
echo "Packs: $(echo "$object_info" | grep "^packs:" | awk '{print $2}')"

# File and commit counts
echo "Tracked files: $(git ls-files 2>/dev/null | wc -l)"
echo "Total commits: $(git rev-list --all --count 2>/dev/null)"
echo "Branches: $(git branch -a 2>/dev/null | wc -l)"
echo "Contributors: $(git log --format='%aN' 2>/dev/null | sort -u | wc -l)"

# Optimization recommendations
echo ""
echo -e "${BLUE}💡 Recommendations${NC}"
echo "-------------------"

recommendations=0

# Check if gc is needed
if [ $(echo "$object_info" | grep "^count:" | awk '{print $2}') -gt 1000 ]; then
    echo "- Run 'git gc' to optimize repository"
    ((recommendations++))
fi

# Check pack count
pack_count=$(echo "$object_info" | grep "^packs:" | awk '{print $2}')
if [ "$pack_count" -gt 5 ]; then
    echo "- Run 'git repack -ad' to consolidate pack files"
    ((recommendations++))
fi

# Check for stale branches
stale_branches=$(git for-each-ref --format='%(refname:short) %(committerdate)' refs/heads/ | \
    awk '$2 < "'$(date -d '90 days ago' '+%Y-%m-%d')'"' | wc -l)
if [ "$stale_branches" -gt 0 ]; then
    echo "- Found $stale_branches stale branches (>90 days). Run cleanup script."
    ((recommendations++))
fi

# Check index version
index_version=$(git config --get index.version || echo "2")
if [ "$index_version" != "4" ]; then
    echo "- Update index version: 'git config index.version 4'"
    ((recommendations++))
fi

if [ $recommendations -eq 0 ]; then
    echo "✨ Repository is well optimized!"
fi

# Summary
echo ""
echo -e "${BLUE}📋 Summary${NC}"
echo "----------"
echo "Issues found: $issues_found"
echo "Issues fixed: $issues_fixed"
echo "Recommendations: $recommendations"

if [ $issues_found -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✅ Repository is healthy!${NC}"
    exit 0
elif [ $issues_found -eq $issues_fixed ]; then
    echo ""
    echo -e "${GREEN}✅ All issues were fixed!${NC}"
    exit 0
else
    echo ""
    echo -e "${YELLOW}⚠️  Some issues remain. Please review above.${NC}"
    exit 1
fi
