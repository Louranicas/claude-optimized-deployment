#!/usr/bin/env python3
"""
Documentation Reality Checker
Scans project documentation for aspirational language and unverified claims.
Part of PRIME DIRECTIVE: DOCUMENT REALITY, NOT ASPIRATION
"""

import os
import re
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple

# Forbidden phrases that indicate marketing/aspirational language
FORBIDDEN_PHRASES = [
    "blazing fast",
    "revolutionary",
    "game-changing",
    "massive improvement",
    "extreme performance",
    "unprecedented",
    "breakthrough",
    "cutting-edge",
    "state-of-the-art",
    "next-generation",
    "lightning fast",
    "supercharge",
    "turbocharge",
]

# Patterns that need verification
UNVERIFIED_PATTERNS = [
    (r'\d+x\s+(?:faster|improvement|speedup|better)', 'Specific multiplier claim'),
    (r'(?:up to|over|more than)\s+\d+%', 'Percentage improvement claim'),
    (r'(?:reduces?|saves?|cuts?)\s+.*\s+by\s+\d+', 'Reduction claim'),
    (r'(?:scales?|handles?)\s+.*(?:millions?|billions?)', 'Scale claim'),
]

# Required tags
REQUIRED_TAGS = {
    'migration': r'\[MIGRATED FROM:.*DATE:.*\]',
    'status': r'\[(?:PLANNED|THEORETICAL|IMPLEMENTED|VERIFIED)\]',
    'verification': r'\[(?:LAST VERIFIED:|UNVERIFIED:|REQUIRES BENCHMARKING)\]'
}

class DocumentationChecker:
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.issues = []
        self.stats = {
            'files_checked': 0,
            'issues_found': 0,
            'forbidden_phrases': 0,
            'unverified_claims': 0,
            'missing_tags': 0
        }
    
    def check_file(self, filepath: Path) -> List[Dict]:
        """Check a single file for documentation issues."""
        issues = []
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            return [{'file': str(filepath), 'type': 'error', 'message': f'Could not read file: {e}'}]
        
        # Check for forbidden phrases
        for phrase in FORBIDDEN_PHRASES:
            pattern = re.compile(re.escape(phrase), re.IGNORECASE)
            for i, line in enumerate(lines):
                if pattern.search(line):
                    issues.append({
                        'file': str(filepath.relative_to(self.project_root)),
                        'line': i + 1,
                        'type': 'forbidden_phrase',
                        'text': line.strip(),
                        'issue': f'Contains forbidden phrase: "{phrase}"'
                    })
                    self.stats['forbidden_phrases'] += 1
        
        # Check for unverified patterns
        for pattern, description in UNVERIFIED_PATTERNS:
            regex = re.compile(pattern, re.IGNORECASE)
            for i, line in enumerate(lines):
                match = regex.search(line)
                if match:
                    # Check if it's already marked as unverified
                    if not re.search(r'\[(?:UNVERIFIED|THEORETICAL|CLAIMED)\]', line):
                        issues.append({
                            'file': str(filepath.relative_to(self.project_root)),
                            'line': i + 1,
                            'type': 'unverified_claim',
                            'text': line.strip(),
                            'issue': f'{description}: "{match.group()}" - needs verification or qualifier'
                        })
                        self.stats['unverified_claims'] += 1
        
        # Check for required tags in certain files
        if filepath.suffix == '.md':
            if '[LAST VERIFIED:' not in content and '[MIGRATED FROM:' not in content:
                issues.append({
                    'file': str(filepath.relative_to(self.project_root)),
                    'line': 1,
                    'type': 'missing_tag',
                    'text': 'File header',
                    'issue': 'Missing verification timestamp or migration tag'
                })
                self.stats['missing_tags'] += 1
        
        return issues
    
    def check_directory(self, directory: Path, extensions: List[str] = None) -> None:
        """Recursively check all files in a directory."""
        if extensions is None:
            extensions = ['.md', '.py', '.rst', '.txt']
        
        for filepath in directory.rglob('*'):
            if filepath.is_file() and filepath.suffix in extensions:
                # Skip certain directories
                if any(skip in str(filepath) for skip in ['.git', '__pycache__', 'venv', '.pytest_cache']):
                    continue
                
                self.stats['files_checked'] += 1
                file_issues = self.check_file(filepath)
                self.issues.extend(file_issues)
                self.stats['issues_found'] += len(file_issues)
    
    def generate_report(self) -> str:
        """Generate a markdown report of all issues found."""
        report = [
            "# Documentation Reality Check Report",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## Summary",
            f"- Files checked: {self.stats['files_checked']}",
            f"- Total issues: {self.stats['issues_found']}",
            f"- Forbidden phrases: {self.stats['forbidden_phrases']}",
            f"- Unverified claims: {self.stats['unverified_claims']}",
            f"- Missing tags: {self.stats['missing_tags']}",
            ""
        ]
        
        if not self.issues:
            report.append("✅ No issues found!")
        else:
            # Group issues by type
            issues_by_type = {}
            for issue in self.issues:
                issue_type = issue['type']
                if issue_type not in issues_by_type:
                    issues_by_type[issue_type] = []
                issues_by_type[issue_type].append(issue)
            
            # Report each type
            for issue_type, issues in issues_by_type.items():
                report.append(f"## {issue_type.replace('_', ' ').title()}")
                report.append("")
                
                for issue in issues:
                    report.append(f"### {issue['file']}:{issue.get('line', 'N/A')}")
                    report.append(f"**Issue**: {issue['issue']}")
                    if 'text' in issue:
                        report.append(f"**Text**: `{issue['text'][:100]}...`" if len(issue['text']) > 100 else f"**Text**: `{issue['text']}`")
                    report.append("")
        
        return '\n'.join(report)
    
    def fix_common_issues(self, dry_run: bool = True) -> List[Tuple[Path, str, str]]:
        """Attempt to fix common issues automatically."""
        fixes = []
        
        for issue in self.issues:
            if issue['type'] == 'unverified_claim':
                filepath = self.project_root / issue['file']
                with open(filepath, 'r') as f:
                    lines = f.readlines()
                
                line_num = issue['line'] - 1
                original = lines[line_num]
                
                # Add [UNVERIFIED] tag
                if '[' not in original:
                    fixed = original.rstrip() + ' [UNVERIFIED]\n'
                else:
                    fixed = original.replace('\n', ' [UNVERIFIED]\n')
                
                if not dry_run:
                    lines[line_num] = fixed
                    with open(filepath, 'w') as f:
                        f.writelines(lines)
                
                fixes.append((filepath, original.strip(), fixed.strip()))
        
        return fixes


def main():
    """Run the documentation checker."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Check documentation for reality vs aspiration')
    parser.add_argument('path', nargs='?', default='.', help='Path to check (default: current directory)')
    parser.add_argument('--fix', action='store_true', help='Attempt to fix common issues')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be fixed without changing files')
    
    args = parser.parse_args()
    
    project_root = Path(args.path).resolve()
    checker = DocumentationChecker(project_root)
    
    print(f"Checking documentation in: {project_root}")
    checker.check_directory(project_root)
    
    # Generate and print report
    report = checker.generate_report()
    print(report)
    
    # Save report
    report_path = project_root / 'documentation_check_report.md'
    with open(report_path, 'w') as f:
        f.write(report)
    print(f"\nReport saved to: {report_path}")
    
    # Fix issues if requested
    if args.fix or args.dry_run:
        fixes = checker.fix_common_issues(dry_run=args.dry_run)
        if fixes:
            print(f"\n{'Would fix' if args.dry_run else 'Fixed'} {len(fixes)} issues:")
            for filepath, original, fixed in fixes[:5]:  # Show first 5
                print(f"\nFile: {filepath}")
                print(f"Original: {original}")
                print(f"Fixed: {fixed}")
            if len(fixes) > 5:
                print(f"\n... and {len(fixes) - 5} more")


if __name__ == '__main__':
    main()
