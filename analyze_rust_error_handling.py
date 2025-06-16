#!/usr/bin/env python3
"""
Analyze Rust error handling patterns in the codebase.
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Tuple
import json

class RustErrorAnalyzer:
    def __init__(self, rust_core_path: str):
        self.rust_core_path = Path(rust_core_path)
        self.issues = {
            "unwrap_calls": [],
            "panic_calls": [],
            "expect_calls": [],
            "missing_error_propagation": [],
            "custom_error_types": [],
            "good_patterns": [],
            "error_messages": []
        }
        
    def analyze_file(self, file_path: Path) -> Dict:
        """Analyze a single Rust file for error handling patterns."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            return {}
            
        relative_path = file_path.relative_to(self.rust_core_path)
        
        # Check for unwrap() calls
        unwrap_pattern = re.compile(r'\.unwrap\(\)')
        for i, line in enumerate(lines, 1):
            if unwrap_pattern.search(line) and not self._is_test_code(file_path, i, lines):
                self.issues["unwrap_calls"].append({
                    "file": str(relative_path),
                    "line": i,
                    "code": line.strip(),
                    "context": self._get_context(lines, i)
                })
        
        # Check for panic! calls
        panic_pattern = re.compile(r'panic!\s*\(')
        for i, line in enumerate(lines, 1):
            if panic_pattern.search(line) and not self._is_test_code(file_path, i, lines):
                self.issues["panic_calls"].append({
                    "file": str(relative_path),
                    "line": i,
                    "code": line.strip(),
                    "context": self._get_context(lines, i)
                })
        
        # Check for expect() calls
        expect_pattern = re.compile(r'\.expect\s*\(')
        for i, line in enumerate(lines, 1):
            if expect_pattern.search(line) and not self._is_test_code(file_path, i, lines):
                # Check if expect has a meaningful message
                expect_msg = re.search(r'\.expect\s*\(\s*"([^"]+)"', line)
                if expect_msg:
                    msg = expect_msg.group(1)
                    if len(msg) < 10 or msg.lower() in ["error", "failed", "unwrap"]:
                        self.issues["expect_calls"].append({
                            "file": str(relative_path),
                            "line": i,
                            "code": line.strip(),
                            "issue": "Generic or unhelpful error message",
                            "context": self._get_context(lines, i)
                        })
                else:
                    self.issues["expect_calls"].append({
                        "file": str(relative_path),
                        "line": i,
                        "code": line.strip(),
                        "issue": "No error message provided",
                        "context": self._get_context(lines, i)
                    })
        
        # Check for proper error propagation with ?
        result_return_pattern = re.compile(r'fn\s+\w+.*->\s*Result<')
        error_prop_pattern = re.compile(r'\?(?:\s*;|\s*\)|$)')
        
        # Find custom error types
        error_type_pattern = re.compile(r'(?:struct|enum)\s+(\w*Error\w*)')
        for match in error_type_pattern.finditer(content):
            self.issues["custom_error_types"].append({
                "file": str(relative_path),
                "type": match.group(1),
                "definition": self._find_error_impl(content, match.group(1))
            })
        
        # Check for good error handling patterns
        if content.find('thiserror::Error') > -1:
            self.issues["good_patterns"].append({
                "file": str(relative_path),
                "pattern": "Uses thiserror for error derivation"
            })
            
        if content.find('anyhow::Result') > -1 or content.find('anyhow::Error') > -1:
            self.issues["good_patterns"].append({
                "file": str(relative_path),
                "pattern": "Uses anyhow for error handling"
            })
            
        # Check for context in error messages
        context_pattern = re.compile(r'\.context\s*\(|\.with_context\s*\(')
        if context_pattern.search(content):
            self.issues["good_patterns"].append({
                "file": str(relative_path),
                "pattern": "Provides error context"
            })
            
        return self.issues
    
    def _is_test_code(self, file_path: Path, line_num: int, lines: List[str]) -> bool:
        """Check if the code is in a test module or test function."""
        # Check if file is in tests directory
        if 'tests' in file_path.parts or file_path.name.endswith('_test.rs'):
            return True
            
        # Check if within a test module or function
        for i in range(max(0, line_num - 20), line_num):
            if i < len(lines):
                line = lines[i]
                if '#[test]' in line or '#[cfg(test)]' in line or 'mod tests' in line:
                    return True
                    
        return False
    
    def _get_context(self, lines: List[str], line_num: int, context_lines: int = 2) -> List[str]:
        """Get surrounding context for a line."""
        start = max(0, line_num - context_lines - 1)
        end = min(len(lines), line_num + context_lines)
        return lines[start:end]
    
    def _find_error_impl(self, content: str, error_type: str) -> Dict:
        """Find implementation details for an error type."""
        impl_pattern = re.compile(rf'impl\s+(?:std::)?(?:error::)?Error\s+for\s+{error_type}')
        display_pattern = re.compile(rf'impl\s+(?:std::)?fmt::Display\s+for\s+{error_type}')
        
        has_error_impl = bool(impl_pattern.search(content))
        has_display_impl = bool(display_pattern.search(content))
        
        return {
            "has_error_impl": has_error_impl,
            "has_display_impl": has_display_impl,
            "uses_thiserror": f"#[derive(Error" in content and error_type in content
        }
    
    def analyze_directory(self, directory: Path):
        """Recursively analyze all Rust files in a directory."""
        for rs_file in directory.rglob("*.rs"):
            self.analyze_file(rs_file)
    
    def generate_report(self) -> str:
        """Generate a comprehensive error handling report."""
        report = []
        report.append("# Rust Error Handling Analysis Report\n")
        
        # Summary
        report.append("## Summary\n")
        report.append(f"- Total unwrap() calls: {len(self.issues['unwrap_calls'])}")
        report.append(f"- Total panic! calls: {len(self.issues['panic_calls'])}")
        report.append(f"- Total expect() calls with issues: {len(self.issues['expect_calls'])}")
        report.append(f"- Custom error types found: {len(self.issues['custom_error_types'])}")
        report.append(f"- Good patterns identified: {len(self.issues['good_patterns'])}\n")
        
        # Critical Issues
        report.append("## Critical Issues (unwrap() calls)\n")
        if self.issues['unwrap_calls']:
            for issue in self.issues['unwrap_calls'][:10]:  # Show first 10
                report.append(f"### {issue['file']}:{issue['line']}")
                report.append(f"```rust\n{issue['code']}\n```")
                report.append("**Context:**")
                for line in issue['context']:
                    report.append(f"  {line}")
                report.append("")
        else:
            report.append("No unwrap() calls found in non-test code! ✅\n")
        
        # Panic calls
        report.append("## Panic! Calls\n")
        if self.issues['panic_calls']:
            for issue in self.issues['panic_calls'][:5]:
                report.append(f"### {issue['file']}:{issue['line']}")
                report.append(f"```rust\n{issue['code']}\n```\n")
        else:
            report.append("No panic! calls found in non-test code! ✅\n")
        
        # Expect calls with issues
        report.append("## Expect() Calls with Poor Messages\n")
        if self.issues['expect_calls']:
            for issue in self.issues['expect_calls'][:5]:
                report.append(f"### {issue['file']}:{issue['line']}")
                report.append(f"**Issue:** {issue['issue']}")
                report.append(f"```rust\n{issue['code']}\n```\n")
        else:
            report.append("All expect() calls have good error messages! ✅\n")
        
        # Custom error types
        report.append("## Custom Error Types\n")
        for error_type in self.issues['custom_error_types']:
            report.append(f"### {error_type['type']} in {error_type['file']}")
            impl_info = error_type['definition']
            status = []
            if impl_info['uses_thiserror']:
                status.append("✅ Uses thiserror")
            elif impl_info['has_error_impl']:
                status.append("✅ Implements Error trait")
            else:
                status.append("❌ Missing Error trait implementation")
                
            if impl_info['has_display_impl']:
                status.append("✅ Implements Display")
            else:
                status.append("❌ Missing Display implementation")
                
            report.append(" | ".join(status) + "\n")
        
        # Good patterns
        report.append("## Good Error Handling Patterns Found\n")
        pattern_counts = {}
        for pattern in self.issues['good_patterns']:
            key = pattern['pattern']
            if key not in pattern_counts:
                pattern_counts[key] = []
            pattern_counts[key].append(pattern['file'])
            
        for pattern, files in pattern_counts.items():
            report.append(f"- **{pattern}**: {len(files)} files")
            for file in files[:3]:  # Show first 3 files
                report.append(f"  - {file}")
            if len(files) > 3:
                report.append(f"  - ... and {len(files) - 3} more")
            report.append("")
        
        return "\n".join(report)
    
    def save_json_report(self, output_path: str):
        """Save detailed report as JSON."""
        with open(output_path, 'w') as f:
            json.dump(self.issues, f, indent=2)

def main():
    rust_core_path = "/home/louranicas/projects/claude-optimized-deployment/rust_core"
    analyzer = RustErrorAnalyzer(rust_core_path)
    
    print("Analyzing Rust error handling patterns...")
    analyzer.analyze_directory(Path(rust_core_path) / "src")
    
    # Generate reports
    report = analyzer.generate_report()
    
    # Save text report
    with open("rust_error_handling_report.md", "w") as f:
        f.write(report)
    
    # Save JSON report for detailed analysis
    analyzer.save_json_report("rust_error_handling_details.json")
    
    print("\nAnalysis complete!")
    print(f"- Text report: rust_error_handling_report.md")
    print(f"- Detailed JSON: rust_error_handling_details.json")
    
    # Print summary
    print("\nQuick Summary:")
    print(f"- unwrap() calls found: {len(analyzer.issues['unwrap_calls'])}")
    print(f"- panic! calls found: {len(analyzer.issues['panic_calls'])}")
    print(f"- expect() issues found: {len(analyzer.issues['expect_calls'])}")
    print(f"- Custom error types: {len(analyzer.issues['custom_error_types'])}")

if __name__ == "__main__":
    main()