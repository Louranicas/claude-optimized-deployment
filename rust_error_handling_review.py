#!/usr/bin/env python3
"""
Review and categorize Rust error handling patterns for manual review.
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Tuple
import json

class ErrorHandlingReviewer:
    def __init__(self, rust_core_path: str):
        self.rust_core_path = Path(rust_core_path)
        self.categorized_issues = {
            "safe_unwraps": [],      # Unwraps that are likely safe (tests, lazy_static, etc.)
            "fixable_unwraps": [],   # Unwraps that should be replaced with ?
            "needs_expect": [],      # Unwraps that need expect() with message
            "needs_refactor": [],    # Code that needs structural changes
            "good_practices": [],    # Examples of good error handling
        }
        
    def categorize_unwrap(self, file_path: Path, line_num: int, line: str, context: List[str]) -> str:
        """Categorize an unwrap() call based on context."""
        
        # Check if in test or example code
        if self._is_test_context(file_path, context):
            return "safe_unwraps"
            
        # Check if in lazy_static or once_cell initialization
        if self._is_static_init(context):
            return "needs_expect"  # Should use expect() instead
            
        # Check if in a function that returns Result
        if self._returns_result(context):
            return "fixable_unwraps"
            
        # Check for specific patterns
        if 'Regex::new' in line:
            return "needs_expect"  # Regex compilation errors should have messages
            
        if any(pattern in line for pattern in ['.lock().unwrap()', '.read().unwrap()', '.write().unwrap()']):
            return "needs_expect"  # Lock poisoning should be documented
            
        if '.get(' in line and '.unwrap()' in line:
            return "needs_refactor"  # Should use get_or_else or pattern matching
            
        return "fixable_unwraps"  # Default: should be fixed
    
    def _is_test_context(self, file_path: Path, context: List[str]) -> bool:
        """Check if code is in test context."""
        if 'tests' in str(file_path) or '_test.rs' in str(file_path):
            return True
            
        for line in context:
            if any(marker in line for marker in ['#[test]', '#[cfg(test)]', 'mod tests']):
                return True
                
        return False
    
    def _is_static_init(self, context: List[str]) -> bool:
        """Check if in static initialization context."""
        for line in context:
            if any(marker in line for marker in ['Lazy::new', 'lazy_static!', 'OnceCell::new']):
                return True
        return False
    
    def _returns_result(self, context: List[str]) -> bool:
        """Check if the function returns a Result."""
        for line in context:
            if '-> Result<' in line or '-> anyhow::Result' in line:
                return True
            if '-> Option<' in line:
                return False  # Option-returning functions need different handling
        return False
    
    def analyze_file(self, file_path: Path) -> Dict:
        """Analyze a single file and categorize issues."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            return {}
            
        relative_path = str(file_path.relative_to(self.rust_core_path))
        
        # Find all unwrap() calls
        for i, line in enumerate(lines):
            if '.unwrap()' in line:
                # Get surrounding context (5 lines before and after)
                start = max(0, i - 5)
                end = min(len(lines), i + 6)
                context = lines[start:end]
                
                category = self.categorize_unwrap(file_path, i + 1, line, context)
                
                self.categorized_issues[category].append({
                    "file": relative_path,
                    "line": i + 1,
                    "code": line.strip(),
                    "context": [l.rstrip() for l in context],
                    "suggestion": self._get_suggestion(category, line)
                })
        
        # Look for good error handling examples
        content = ''.join(lines)
        if '.context(' in content or '.with_context(' in content:
            self.categorized_issues["good_practices"].append({
                "file": relative_path,
                "pattern": "Uses error context (anyhow)",
                "example": self._find_example(lines, '.context(')
            })
            
        if 'map_err(' in content:
            self.categorized_issues["good_practices"].append({
                "file": relative_path,
                "pattern": "Custom error mapping",
                "example": self._find_example(lines, 'map_err(')
            })
            
        return self.categorized_issues
    
    def _get_suggestion(self, category: str, line: str) -> str:
        """Get fix suggestion based on category."""
        suggestions = {
            "safe_unwraps": "Safe in test context - no action needed",
            "fixable_unwraps": "Replace .unwrap() with ? for error propagation",
            "needs_expect": "Replace with .expect(\"descriptive error message\")",
            "needs_refactor": "Consider using pattern matching or combinators",
        }
        
        base_suggestion = suggestions.get(category, "Review needed")
        
        # Add specific suggestions
        if 'Regex::new' in line:
            pattern = re.search(r'Regex::new\(r?"([^"]+)"\)', line)
            if pattern:
                return f'Use .expect("Invalid regex pattern: {pattern.group(1)[:20]}...")'
                
        if '.lock().unwrap()' in line:
            return 'Use .expect("Mutex poisoned") or handle poisoning explicitly'
            
        if '.get(' in line:
            return 'Use .get().ok_or_else(|| Error::NotFound)? or pattern matching'
            
        return base_suggestion
    
    def _find_example(self, lines: List[str], pattern: str) -> str:
        """Find an example of a pattern in the code."""
        for i, line in enumerate(lines):
            if pattern in line:
                # Return the line and possibly the next line if it's a continuation
                example = line.strip()
                if i + 1 < len(lines) and lines[i + 1].strip().startswith('.'):
                    example += ' ' + lines[i + 1].strip()
                return example
        return ""
    
    def generate_review_report(self) -> str:
        """Generate a comprehensive review report."""
        report = []
        report.append("# Rust Error Handling Review Report\n")
        report.append("This report categorizes error handling patterns for manual review.\n")
        
        # Summary
        report.append("## Summary\n")
        for category, issues in self.categorized_issues.items():
            if category != "good_practices":
                report.append(f"- {category.replace('_', ' ').title()}: {len(issues)} occurrences")
        report.append("")
        
        # Safe unwraps (no action needed)
        report.append("## Safe Unwraps (No Action Needed)\n")
        report.append("These unwrap() calls are in test code or other safe contexts:\n")
        for issue in self.categorized_issues["safe_unwraps"][:5]:
            report.append(f"- `{issue['file']}:{issue['line']}` - {issue['suggestion']}")
        if len(self.categorized_issues["safe_unwraps"]) > 5:
            report.append(f"- ... and {len(self.categorized_issues['safe_unwraps']) - 5} more\n")
        
        # Easily fixable unwraps
        report.append("\n## Easily Fixable (Replace with ?)\n")
        report.append("These can be fixed by replacing .unwrap() with ?:\n")
        for issue in self.categorized_issues["fixable_unwraps"][:10]:
            report.append(f"### {issue['file']}:{issue['line']}")
            report.append("```rust")
            report.append(f"// Current:")
            report.append(f"{issue['code']}")
            report.append(f"// Suggested:")
            report.append(f"{issue['code'].replace('.unwrap()', '?')}")
            report.append("```\n")
        
        # Needs expect with message
        report.append("\n## Needs Descriptive Error Messages\n")
        report.append("Replace these with .expect() with meaningful messages:\n")
        for issue in self.categorized_issues["needs_expect"][:10]:
            report.append(f"### {issue['file']}:{issue['line']}")
            report.append("```rust")
            report.append(issue['code'])
            report.append(f"// Suggestion: {issue['suggestion']}")
            report.append("```\n")
        
        # Needs refactoring
        report.append("\n## Needs Refactoring\n")
        report.append("These require structural changes for better error handling:\n")
        for issue in self.categorized_issues["needs_refactor"][:10]:
            report.append(f"### {issue['file']}:{issue['line']}")
            report.append("```rust")
            report.append(issue['code'])
            report.append(f"// {issue['suggestion']}")
            report.append("```\n")
        
        # Good practices found
        report.append("\n## Good Error Handling Examples\n")
        report.append("Examples of good error handling patterns found:\n")
        for example in self.categorized_issues["good_practices"][:10]:
            report.append(f"### {example['file']}")
            report.append(f"**Pattern**: {example['pattern']}")
            if example.get('example'):
                report.append(f"```rust\n{example['example']}\n```\n")
        
        # Recommendations
        report.append("\n## Recommendations\n")
        report.append("1. **Priority 1**: Fix 'Easily Fixable' unwraps in Result-returning functions")
        report.append("2. **Priority 2**: Add descriptive messages to expect() calls")
        report.append("3. **Priority 3**: Refactor complex error handling patterns")
        report.append("4. **Consider**: Adopting anyhow for application-level errors")
        report.append("5. **Consider**: Using thiserror for library-level errors\n")
        
        return "\n".join(report)

def main():
    rust_core_path = "/home/louranicas/projects/claude-optimized-deployment/rust_core"
    reviewer = ErrorHandlingReviewer(rust_core_path)
    
    print("Reviewing Rust error handling patterns...")
    
    # Analyze all source files
    src_path = Path(rust_core_path) / "src"
    for rs_file in src_path.rglob("*.rs"):
        reviewer.analyze_file(rs_file)
    
    # Generate report
    report = reviewer.generate_review_report()
    
    # Save report
    with open("rust_error_handling_review.md", "w") as f:
        f.write(report)
    
    # Save detailed categorization
    with open("rust_error_handling_categorized.json", "w") as f:
        # Convert to serializable format
        serializable = {}
        for category, issues in reviewer.categorized_issues.items():
            serializable[category] = issues
        json.dump(serializable, f, indent=2)
    
    print("\nReview complete!")
    print("- Review report: rust_error_handling_review.md")
    print("- Categorized issues: rust_error_handling_categorized.json")
    
    # Print summary
    print("\nSummary:")
    for category, issues in reviewer.categorized_issues.items():
        if category != "good_practices":
            print(f"- {category}: {len(issues)} occurrences")

if __name__ == "__main__":
    main()