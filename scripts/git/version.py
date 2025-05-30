#!/usr/bin/env python3
"""
Semantic Version Manager for CODE Project
Handles version bumping, changelog generation, and release management
"""

import json
import re
import subprocess
import sys
from pathlib import Path
from datetime import datetime
from typing import Tuple, Optional, List, Dict
import argparse


class VersionManager:
    """Manages semantic versioning for the project"""
    
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.repo_root = self._find_repo_root()
        self.version_file = self.repo_root / "VERSION"
        self.changelog_file = self.repo_root / "CHANGELOG.md"
        self.package_json = self.repo_root / "package.json"
        self.pyproject_toml = self.repo_root / "pyproject.toml"
        self.cargo_toml = self.repo_root / "Cargo.toml"
        
    def _find_repo_root(self) -> Path:
        """Find the repository root by looking for .git directory"""
        current = Path.cwd()
        while current != current.parent:
            if (current / ".git").is_dir():
                return current
            current = current.parent
        raise ValueError("Not in a git repository")
    
    def get_current_version(self) -> str:
        """Get current version from VERSION file"""
        if self.version_file.exists():
            return self.version_file.read_text().strip()
        return "0.0.0"
    
    def parse_version(self, version: str) -> Tuple[int, int, int]:
        """Parse semantic version string"""
        # Remove 'v' prefix if present
        version = version.lstrip('v')
        
        match = re.match(r"^(\d+)\.(\d+)\.(\d+)", version)
        if not match:
            raise ValueError(f"Invalid version format: {version}")
        
        return int(match.group(1)), int(match.group(2)), int(match.group(3))
    
    def bump_version(self, bump_type: str, current: Optional[str] = None) -> str:
        """Bump version based on type: major, minor, patch"""
        if current is None:
            current = self.get_current_version()
        
        major, minor, patch = self.parse_version(current)
        
        if bump_type == "major":
            major += 1
            minor = 0
            patch = 0
        elif bump_type == "minor":
            minor += 1
            patch = 0
        elif bump_type == "patch":
            patch += 1
        else:
            raise ValueError(f"Invalid bump type: {bump_type}")
        
        return f"{major}.{minor}.{patch}"
    
    def get_conventional_commits(self, since_tag: Optional[str] = None) -> List[Dict[str, str]]:
        """Get conventional commits since last tag"""
        if since_tag:
            cmd = ["git", "log", f"{since_tag}..HEAD", "--pretty=format:%H|%s|%b|%an|%ae"]
        else:
            cmd = ["git", "log", "--pretty=format:%H|%s|%b|%an|%ae"]
        
        try:
            output = subprocess.check_output(cmd, text=True).strip()
            if not output:
                return []
            
            commits = []
            for line in output.split('\n'):
                parts = line.split('|', 4)
                if len(parts) >= 5:
                    commit = {
                        'hash': parts[0],
                        'subject': parts[1],
                        'body': parts[2],
                        'author': parts[3],
                        'email': parts[4]
                    }
                    
                    # Parse conventional commit
                    match = re.match(r'^(\w+)(?:\(([^)]+)\))?: (.+)$', commit['subject'])
                    if match:
                        commit['type'] = match.group(1)
                        commit['scope'] = match.group(2) or ''
                        commit['description'] = match.group(3)
                        
                        # Check for breaking changes
                        commit['breaking'] = ('BREAKING CHANGE' in commit['body'] or 
                                            commit['subject'].startswith('!'))
                        
                        commits.append(commit)
            
            return commits
        except subprocess.CalledProcessError:
            return []
    
    def detect_bump_type(self) -> str:
        """Detect bump type from recent commit messages"""
        try:
            # Get last tag
            last_tag = subprocess.check_output(
                ["git", "describe", "--tags", "--abbrev=0"],
                text=True
            ).strip()
        except subprocess.CalledProcessError:
            last_tag = None
        
        commits = self.get_conventional_commits(last_tag)
        
        # Check for breaking changes
        if any(c.get('breaking', False) for c in commits):
            return "major"
        
        # Check for features
        if any(c.get('type') == 'feat' for c in commits):
            return "minor"
        
        # Default to patch
        return "patch"
    
    def update_files(self, new_version: str):
        """Update version in all relevant files"""
        if self.dry_run:
            print(f"Would update version to {new_version} in:")
            print(f"  - {self.version_file}")
            if self.package_json.exists():
                print(f"  - {self.package_json}")
            if self.pyproject_toml.exists():
                print(f"  - {self.pyproject_toml}")
            if self.cargo_toml.exists():
                print(f"  - {self.cargo_toml}")
            return
        
        # Update VERSION file
        self.version_file.write_text(new_version + "\n")
        print(f"Updated {self.version_file}")
        
        # Update package.json if exists
        if self.package_json.exists():
            data = json.loads(self.package_json.read_text())
            data["version"] = new_version
            self.package_json.write_text(json.dumps(data, indent=2) + "\n")
            print(f"Updated {self.package_json}")
        
        # Update pyproject.toml if exists
        if self.pyproject_toml.exists():
            content = self.pyproject_toml.read_text()
            # Handle both quoted and unquoted versions
            content = re.sub(
                r'version\s*=\s*["\']?[^"\']*["\']?',
                f'version = "{new_version}"',
                content,
                count=1
            )
            self.pyproject_toml.write_text(content)
            print(f"Updated {self.pyproject_toml}")
        
        # Update Cargo.toml if exists
        if self.cargo_toml.exists():
            content = self.cargo_toml.read_text()
            content = re.sub(
                r'^version\s*=\s*"[^"]*"',
                f'version = "{new_version}"',
                content,
                count=1,
                flags=re.MULTILINE
            )
            self.cargo_toml.write_text(content)
            print(f"Updated {self.cargo_toml}")
    
    def generate_changelog_section(self, version: str, commits: List[Dict[str, str]]) -> str:
        """Generate changelog section for a version"""
        date = datetime.now().strftime("%Y-%m-%d")
        
        # Group commits by type
        grouped = {
            'feat': [],
            'fix': [],
            'docs': [],
            'style': [],
            'refactor': [],
            'perf': [],
            'test': [],
            'build': [],
            'ci': [],
            'chore': [],
            'revert': [],
        }
        
        breaking_changes = []
        
        for commit in commits:
            commit_type = commit.get('type', '')
            if commit_type in grouped:
                grouped[commit_type].append(commit)
            
            if commit.get('breaking', False):
                breaking_changes.append(commit)
        
        # Build changelog section
        lines = [f"## [{version}] - {date}", ""]
        
        # Add breaking changes first
        if breaking_changes:
            lines.append("### ⚠️ BREAKING CHANGES")
            lines.append("")
            for commit in breaking_changes:
                desc = commit.get('description', commit.get('subject', ''))
                scope = commit.get('scope', '')
                scope_str = f"**{scope}**: " if scope else ""
                lines.append(f"* {scope_str}{desc}")
            lines.append("")
        
        # Add other changes
        type_names = {
            'feat': '✨ Features',
            'fix': '🐛 Bug Fixes',
            'docs': '📚 Documentation',
            'style': '💎 Styles',
            'refactor': '📦 Code Refactoring',
            'perf': '🚀 Performance Improvements',
            'test': '🚨 Tests',
            'build': '🛠️ Build System',
            'ci': '⚙️ Continuous Integration',
            'chore': '♻️ Chores',
            'revert': '🗑️ Reverts',
        }
        
        for commit_type, type_name in type_names.items():
            type_commits = grouped.get(commit_type, [])
            if type_commits:
                lines.append(f"### {type_name}")
                lines.append("")
                for commit in type_commits:
                    desc = commit.get('description', commit.get('subject', ''))
                    scope = commit.get('scope', '')
                    scope_str = f"**{scope}**: " if scope else ""
                    hash_short = commit['hash'][:7]
                    lines.append(f"* {scope_str}{desc} ([{hash_short}])")
                lines.append("")
        
        return "\n".join(lines)
    
    def update_changelog(self, version: str):
        """Update CHANGELOG.md with new version"""
        try:
            # Get last tag
            last_tag = subprocess.check_output(
                ["git", "describe", "--tags", "--abbrev=0"],
                text=True
            ).strip()
        except subprocess.CalledProcessError:
            last_tag = None
        
        commits = self.get_conventional_commits(last_tag)
        
        if not commits:
            print("No conventional commits found for changelog")
            return
        
        new_section = self.generate_changelog_section(version, commits)
        
        if self.dry_run:
            print("\nWould add to CHANGELOG.md:")
            print("-" * 50)
            print(new_section)
            print("-" * 50)
            return
        
        # Read existing changelog or create new
        if self.changelog_file.exists():
            content = self.changelog_file.read_text()
            
            # Find where to insert (after title and description)
            lines = content.split('\n')
            insert_index = 0
            
            # Skip title and description
            for i, line in enumerate(lines):
                if line.startswith('## '):
                    insert_index = i
                    break
            
            # Insert new section
            lines.insert(insert_index, new_section)
            content = '\n'.join(lines)
        else:
            # Create new changelog
            content = f"""# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

{new_section}
"""
        
        self.changelog_file.write_text(content)
        print(f"Updated {self.changelog_file}")
    
    def create_tag(self, version: str, message: Optional[str] = None):
        """Create annotated git tag"""
        if message is None:
            message = f"Release v{version}"
        
        tag_name = f"v{version}"
        
        if self.dry_run:
            print(f"Would create tag: {tag_name}")
            print(f"Message: {message}")
            return
        
        try:
            subprocess.run(
                ["git", "tag", "-a", tag_name, "-m", message],
                check=True
            )
            print(f"Created tag: {tag_name}")
        except subprocess.CalledProcessError as e:
            print(f"Error creating tag: {e}")
            sys.exit(1)
    
    def commit_changes(self, version: str):
        """Commit version changes"""
        if self.dry_run:
            print("Would commit changes with message: " + f"chore: release v{version}")
            return
        
        try:
            # Add all version files
            files_to_add = ["VERSION"]
            if self.changelog_file.exists():
                files_to_add.append("CHANGELOG.md")
            if self.package_json.exists():
                files_to_add.append("package.json")
            if self.pyproject_toml.exists():
                files_to_add.append("pyproject.toml")
            if self.cargo_toml.exists():
                files_to_add.append("Cargo.toml")
            
            subprocess.run(["git", "add"] + files_to_add, check=True)
            subprocess.run(
                ["git", "commit", "-m", f"chore: release v{version}"],
                check=True
            )
            print("Committed version changes")
        except subprocess.CalledProcessError as e:
            print(f"Error committing changes: {e}")
            sys.exit(1)


def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description="Semantic version management for CODE project",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show current version
  %(prog)s current
  
  # Bump version (auto-detect type)
  %(prog)s bump
  
  # Bump specific version type
  %(prog)s bump --type minor
  
  # Create a release tag
  %(prog)s tag
  
  # Full automatic release
  %(prog)s release
  
  # Dry run (show what would happen)
  %(prog)s release --dry-run
"""
    )
    
    parser.add_argument(
        "action",
        choices=["current", "bump", "tag", "release", "changelog"],
        help="Action to perform"
    )
    
    parser.add_argument(
        "--type",
        choices=["major", "minor", "patch"],
        help="Version bump type (for 'bump' and 'release' actions)"
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without doing it"
    )
    
    parser.add_argument(
        "--no-commit",
        action="store_true",
        help="Don't commit changes (for 'bump' and 'release' actions)"
    )
    
    parser.add_argument(
        "--no-tag",
        action="store_true",
        help="Don't create tag (for 'release' action)"
    )
    
    parser.add_argument(
        "--no-changelog",
        action="store_true",
        help="Don't update changelog (for 'bump' and 'release' actions)"
    )
    
    args = parser.parse_args()
    
    # Create version manager
    vm = VersionManager(dry_run=args.dry_run)
    
    if args.action == "current":
        print(vm.get_current_version())
    
    elif args.action == "bump":
        # Determine bump type
        if not args.type:
            args.type = vm.detect_bump_type()
            print(f"Detected bump type: {args.type}")
        
        current = vm.get_current_version()
        new_version = vm.bump_version(args.type, current)
        
        print(f"Bumping version: {current} → {new_version}")
        
        # Update files
        vm.update_files(new_version)
        
        # Update changelog
        if not args.no_changelog:
            vm.update_changelog(new_version)
        
        # Commit changes
        if not args.no_commit and not args.dry_run:
            vm.commit_changes(new_version)
        
        if not args.dry_run:
            print(f"\n✅ Version bumped to {new_version}")
            if args.no_commit:
                print("   (changes not committed)")
            else:
                print("   Run 'git push' to push changes")
                print("   Run 'python scripts/git/version.py tag' to create release tag")
    
    elif args.action == "tag":
        version = vm.get_current_version()
        vm.create_tag(version)
        
        if not args.dry_run:
            print("\n✅ Tag created")
            print("   Run 'git push --tags' to push tag")
    
    elif args.action == "release":
        # Full release process
        if not args.type:
            args.type = vm.detect_bump_type()
            print(f"Detected bump type: {args.type}")
        
        current = vm.get_current_version()
        new_version = vm.bump_version(args.type, current)
        
        print(f"📦 Releasing: {current} → {new_version} ({args.type})")
        
        # Update files
        vm.update_files(new_version)
        
        # Update changelog
        if not args.no_changelog:
            vm.update_changelog(new_version)
        
        # Commit changes
        if not args.no_commit:
            vm.commit_changes(new_version)
        
        # Create tag
        if not args.no_tag:
            vm.create_tag(new_version)
        
        if not args.dry_run:
            print(f"\n✅ Released v{new_version}")
            print("\nNext steps:")
            print("1. Review the changes")
            print("2. Run 'git push --follow-tags' to push release")
            print("3. Create GitHub release from tag")
    
    elif args.action == "changelog":
        # Just update changelog for current version
        version = vm.get_current_version()
        vm.update_changelog(version)
        
        if not args.dry_run:
            print("\n✅ Changelog updated")


if __name__ == "__main__":
    main()
