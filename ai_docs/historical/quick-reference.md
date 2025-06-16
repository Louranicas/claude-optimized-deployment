# Git Quick Reference Card - CODE Project

## 🚀 Daily Commands

### Status & Navigation
```bash
git st                    # Short status
git co <branch>          # Checkout branch
git co -                 # Return to previous branch
git recent               # Show recent branches
```

### Committing
```bash
git add -p               # Add interactively
git ci -m "message"      # Commit
git amend                # Amend last commit (no message change)
git undo                 # Undo last commit (keep changes)
git wip                  # Quick WIP commit
```

### Viewing History
```bash
git lg                   # Pretty graph log
git today                # Today's commits
git history              # Full history graph
git file-history <file>  # File history
```

## 📝 Semantic Commits

### Format
```
<type>(<scope>): <subject>
```

### Types
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting
- `refactor`: Code restructuring
- `perf`: Performance
- `test`: Tests
- `build`: Build changes
- `ci`: CI/CD changes
- `chore`: Maintenance

### Examples
```bash
git feat "add deployment API"
git fix "resolve memory leak"
git docs "update installation guide"
```

## 🌿 Branch Workflow

### Create Branches
```bash
git-feature CODE-123 api-enhancement
git-fix CODE-456 memory-leak
```

### Clean Up
```bash
git-cleanup              # Remove merged branches
git branch -d <branch>   # Delete local branch
git push origin --delete <branch>  # Delete remote
```

## 🔄 Sync & Merge

### Update Branch
```bash
git pull --rebase        # Update current branch
git fetch --all          # Fetch all remotes
git sync-fork            # Sync with upstream
```

### Merge
```bash
git merge --no-ff <branch>  # Merge with commit
git rebase develop          # Rebase on develop
git ri HEAD~3               # Interactive rebase
```

## 📦 Releases

### Version Management
```bash
python scripts/git/version.py current     # Show version
python scripts/git/version.py bump        # Auto bump
python scripts/git/version.py release     # Full release
```

### Release Process
```bash
git-release 1.2.0        # Start release
git tag -a v1.2.0        # Create tag
git push --follow-tags   # Push with tags
```

## 🚨 Emergency

### Undo Operations
```bash
git reset --soft HEAD~1  # Undo commit, keep changes
git reset --hard HEAD~1  # Undo commit, discard changes
git checkout -- <file>   # Discard file changes
git clean -fd           # Remove untracked files
```

### Recovery
```bash
git reflog              # Find lost commits
git cherry-pick <hash>  # Apply specific commit
git stash               # Save current work
git stash pop           # Restore saved work
```

### Fix Issues
```bash
rm .git/index && git reset  # Fix corrupted index
git gc --prune=now         # Clean up repository
git fsck --full            # Check integrity
```

## 🔍 Search & Find

### Search Content
```bash
git grep "pattern"           # Search in files
git find "search term"       # Search commit messages
git log -S "code"           # Search code changes
```

### Find Files
```bash
git ls-files | grep pattern  # Find tracked files
git-find-large 5242880      # Find files >5MB
```

## 📊 Statistics

### Repository Info
```bash
git-stats               # Detailed statistics
git shortlog -sn        # Contributor summary
git count-objects -vH   # Repository size
```

### Activity
```bash
git log --since="1 week"     # Recent activity
git log --author="name"      # By author
git log --grep="pattern"     # By message
```

## ⚡ Performance

### Enable Optimizations
```bash
git config core.preloadindex true
git config core.fscache true
git config feature.manyFiles true
```

### Maintenance
```bash
git maintenance start    # Enable auto maintenance
git gc --aggressive     # Aggressive cleanup
git repack -ad          # Repack objects
```

## 🛡️ Security

### Check for Secrets
```bash
detect-secrets scan     # Scan for secrets
git log -p | grep -E "(password|key|token)"  # Manual check
```

### Sign Commits
```bash
git config commit.gpgsign true   # Enable signing
git log --show-signature        # Verify signatures
```

## 🎯 Git Aliases

```bash
# Shortcuts
co = checkout
br = branch
ci = commit
st = status -sb

# Workflow
wip = !git add -A && git commit -m "WIP"
undo = reset --soft HEAD~1
amend = commit --amend --no-edit

# View
lg = log --graph --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr) %C(bold blue)<%an>%Creset'
recent = for-each-ref --sort=-committerdate --format='%(refname:short)' refs/heads/ --count=10

# Semantic commits
feat = "!f() { git commit -m \"feat: $1\"; }; f"
fix = "!f() { git commit -m \"fix: $1\"; }; f"
docs = "!f() { git commit -m \"docs: $1\"; }; f"
```

## 🚀 Hook Overrides

```bash
git commit --no-verify   # Skip pre-commit hook
git push --no-verify     # Skip pre-push hook
```

## 📚 Help

```bash
git help <command>       # Git help
git <command> --help     # Command help
./scripts/git/git-doctor.sh  # Check health
```

---
**Remember**: When in doubt, don't use `--force`!
