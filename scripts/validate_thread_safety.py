#!/usr/bin/env python3
"""
Thread Safety Validation Script for Rust Code

This script analyzes Rust code for thread safety issues including:
1. Shared state access patterns
2. Mutex/RwLock usage
3. Potential race conditions
4. Send + Sync implementations
5. Atomic operations
"""

import os
import re
import sys
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

@dataclass
class ThreadSafetyIssue:
    """Represents a potential thread safety issue"""
    file_path: str
    line_number: int
    issue_type: str
    description: str
    severity: str  # "critical", "high", "medium", "low"
    code_snippet: str = ""
    suggestion: str = ""

@dataclass
class ThreadSafetyReport:
    """Thread safety analysis report"""
    issues: List[ThreadSafetyIssue] = field(default_factory=list)
    shared_state_locations: Dict[str, List[int]] = field(default_factory=dict)
    mutex_usage: Dict[str, List[int]] = field(default_factory=dict)
    rwlock_usage: Dict[str, List[int]] = field(default_factory=dict)
    atomic_usage: Dict[str, List[int]] = field(default_factory=dict)
    unsafe_blocks: Dict[str, List[int]] = field(default_factory=dict)
    send_sync_impls: Dict[str, List[int]] = field(default_factory=dict)

class ThreadSafetyValidator:
    """Validates thread safety in Rust code"""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.report = ThreadSafetyReport()
        
        # Patterns for detecting thread safety issues
        self.patterns = {
            'shared_state': [
                (r'static\s+mut\s+', 'Global mutable static', 'critical'),
                (r'lazy_static!\s*\{[^}]*mut\s+', 'Mutable lazy_static', 'high'),
                (r'Arc<RefCell<', 'Arc<RefCell> combination (not thread-safe)', 'critical'),
                (r'Rc<', 'Rc usage (not thread-safe)', 'high'),
            ],
            'mutex_patterns': [
                (r'\.lock\(\)\.unwrap\(\)', 'Mutex lock with unwrap (can panic)', 'medium'),
                (r'\.lock\(\)\.expect\(', 'Mutex lock with expect (can panic)', 'medium'),
                (r'while.*\.try_lock\(\)', 'Busy-wait on try_lock', 'medium'),
                (r'\.lock\(\)[^?]*\.lock\(\)', 'Nested locks (potential deadlock)', 'critical'),
            ],
            'unsafe_patterns': [
                (r'unsafe\s*\{[^}]*static\s+mut', 'Unsafe mutable static access', 'critical'),
                (r'unsafe\s*\{[^}]*\*\s*mut\s*', 'Unsafe raw pointer dereference', 'high'),
                (r'unsafe\s*\{[^}]*transmute', 'Unsafe transmute', 'high'),
            ],
            'race_conditions': [
                (r'if\s+.*\.load\(.*\)\s*{[^}]*\.store\(', 'Check-then-act pattern', 'high'),
                (r'\.clone\(\).*spawn.*move', 'Cloning before spawn (check ownership)', 'medium'),
            ],
            'atomics': [
                (r'Ordering::Relaxed', 'Relaxed ordering (may be too weak)', 'low'),
                (r'compare_and_swap\(', 'Deprecated compare_and_swap', 'medium'),
            ]
        }
        
        # Patterns for good practices
        self.good_patterns = {
            'mutex': re.compile(r'Mutex<|RwLock<|Arc<Mutex<|Arc<RwLock<'),
            'atomic': re.compile(r'Atomic[UIN]\d+|AtomicBool|AtomicPtr'),
            'send_sync': re.compile(r'unsafe\s+impl\s+(?:Send|Sync)\s+for'),
            'channel': re.compile(r'mpsc::|channel\(\)|Sender<|Receiver<'),
        }

    def validate_project(self) -> ThreadSafetyReport:
        """Validate thread safety across the entire project"""
        print("🔍 Starting thread safety validation...")
        
        # Find all Rust files
        rust_files = list(self.project_root.rglob("*.rs"))
        rust_files = [f for f in rust_files if 'target' not in str(f)]
        
        print(f"Found {len(rust_files)} Rust files to analyze")
        
        # Analyze each file
        for rust_file in rust_files:
            self.analyze_file(rust_file)
        
        # Run additional checks
        self.check_send_sync_implementations()
        self.check_lock_ordering()
        self.run_thread_sanitizer_tests()
        self.analyze_concurrent_tests()
        
        # Generate report
        self.generate_report()
        
        return self.report

    def analyze_file(self, file_path: Path):
        """Analyze a single Rust file for thread safety issues"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
            
            # Check for shared state patterns
            self.check_patterns(file_path, lines, 'shared_state')
            
            # Check mutex usage
            self.check_patterns(file_path, lines, 'mutex_patterns')
            
            # Check unsafe blocks
            self.check_patterns(file_path, lines, 'unsafe_patterns')
            
            # Check for race conditions
            self.check_patterns(file_path, lines, 'race_conditions')
            
            # Check atomic operations
            self.check_patterns(file_path, lines, 'atomics')
            
            # Track good patterns
            self.track_good_patterns(file_path, content)
            
            # Check for specific anti-patterns
            self.check_antipatterns(file_path, lines)
            
        except Exception as e:
            print(f"Error analyzing {file_path}: {e}")

    def check_patterns(self, file_path: Path, lines: List[str], pattern_type: str):
        """Check for specific patterns in the code"""
        patterns = self.patterns.get(pattern_type, [])
        
        for line_no, line in enumerate(lines, 1):
            for pattern, description, severity in patterns:
                if re.search(pattern, line):
                    # Get context (3 lines before and after)
                    start = max(0, line_no - 4)
                    end = min(len(lines), line_no + 3)
                    context = '\n'.join(f"{i+1}: {lines[i]}" for i in range(start, end))
                    
                    issue = ThreadSafetyIssue(
                        file_path=str(file_path),
                        line_number=line_no,
                        issue_type=pattern_type,
                        description=description,
                        severity=severity,
                        code_snippet=context,
                        suggestion=self.get_suggestion(pattern_type, description)
                    )
                    self.report.issues.append(issue)

    def check_antipatterns(self, file_path: Path, lines: List[str]):
        """Check for specific anti-patterns"""
        content = '\n'.join(lines)
        
        # Check for double-checked locking
        dcl_pattern = r'if\s+.*\.load\([^)]*\)\s*{[^}]*lock\(\)'
        if re.search(dcl_pattern, content, re.MULTILINE | re.DOTALL):
            for line_no, line in enumerate(lines, 1):
                if '.load(' in line and line_no + 5 < len(lines):
                    # Check next few lines for lock
                    next_lines = '\n'.join(lines[line_no:line_no+5])
                    if '.lock()' in next_lines:
                        issue = ThreadSafetyIssue(
                            file_path=str(file_path),
                            line_number=line_no,
                            issue_type='antipattern',
                            description='Double-checked locking pattern detected',
                            severity='critical',
                            suggestion='Use proper synchronization or once_cell/lazy_static'
                        )
                        self.report.issues.append(issue)
        
        # Check for lock ordering issues
        locks = re.findall(r'(\w+)\.lock\(\)', content)
        if len(set(locks)) > 1:
            # Multiple different locks in same file
            lock_pairs = []
            for i in range(len(locks) - 1):
                if locks[i] != locks[i + 1]:
                    lock_pairs.append((locks[i], locks[i + 1]))
            
            if lock_pairs:
                issue = ThreadSafetyIssue(
                    file_path=str(file_path),
                    line_number=0,
                    issue_type='lock_ordering',
                    description=f'Multiple locks acquired: {lock_pairs}',
                    severity='high',
                    suggestion='Ensure consistent lock ordering to prevent deadlocks'
                )
                self.report.issues.append(issue)

    def track_good_patterns(self, file_path: Path, content: str):
        """Track usage of good thread safety patterns"""
        for pattern_name, pattern in self.good_patterns.items():
            matches = pattern.finditer(content)
            for match in matches:
                line_no = content[:match.start()].count('\n') + 1
                
                if pattern_name == 'mutex':
                    self.report.mutex_usage.setdefault(str(file_path), []).append(line_no)
                elif pattern_name == 'atomic':
                    self.report.atomic_usage.setdefault(str(file_path), []).append(line_no)
                elif pattern_name == 'send_sync':
                    self.report.send_sync_impls.setdefault(str(file_path), []).append(line_no)

    def check_send_sync_implementations(self):
        """Check for custom Send/Sync implementations"""
        print("Checking Send/Sync implementations...")
        
        for file_path, line_numbers in self.report.send_sync_impls.items():
            with open(file_path, 'r') as f:
                lines = f.readlines()
            
            for line_no in line_numbers:
                # Get the impl block
                impl_lines = []
                brace_count = 0
                found_start = False
                
                for i in range(line_no - 1, min(line_no + 50, len(lines))):
                    line = lines[i]
                    impl_lines.append(line)
                    
                    if '{' in line:
                        found_start = True
                        brace_count += line.count('{')
                    if '}' in line:
                        brace_count -= line.count('}')
                    
                    if found_start and brace_count == 0:
                        break
                
                impl_block = ''.join(impl_lines)
                
                # Check if the impl has proper justification
                if '// SAFETY:' not in impl_block and '//SAFETY:' not in impl_block:
                    issue = ThreadSafetyIssue(
                        file_path=file_path,
                        line_number=line_no,
                        issue_type='send_sync',
                        description='Send/Sync impl without SAFETY comment',
                        severity='high',
                        suggestion='Add SAFETY comment explaining why the impl is correct'
                    )
                    self.report.issues.append(issue)

    def check_lock_ordering(self):
        """Analyze potential lock ordering issues across files"""
        print("Analyzing lock ordering...")
        
        # Build a graph of lock acquisitions
        lock_graph = defaultdict(set)
        
        for file_path in self.report.mutex_usage:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Find functions that acquire multiple locks
            function_pattern = r'fn\s+(\w+)[^{]*\{([^}]*\.lock\(\)[^}]*\.lock\(\)[^}]*)\}'
            matches = re.finditer(function_pattern, content, re.MULTILINE | re.DOTALL)
            
            for match in matches:
                func_name = match.group(1)
                func_body = match.group(2)
                
                # Extract lock names
                locks = re.findall(r'(\w+)\.lock\(\)', func_body)
                
                # Add edges to lock graph
                for i in range(len(locks) - 1):
                    lock_graph[locks[i]].add(locks[i + 1])
        
        # Check for cycles (potential deadlocks)
        cycles = self.find_cycles(lock_graph)
        
        if cycles:
            for cycle in cycles:
                issue = ThreadSafetyIssue(
                    file_path='multiple files',
                    line_number=0,
                    issue_type='deadlock',
                    description=f'Potential deadlock cycle: {" -> ".join(cycle)}',
                    severity='critical',
                    suggestion='Establish a global lock ordering to prevent deadlocks'
                )
                self.report.issues.append(issue)

    def find_cycles(self, graph: Dict[str, Set[str]]) -> List[List[str]]:
        """Find cycles in a directed graph using DFS"""
        cycles = []
        visited = set()
        rec_stack = set()
        
        def dfs(node, path):
            visited.add(node)
            rec_stack.add(node)
            path.append(node)
            
            for neighbor in graph.get(node, []):
                if neighbor not in visited:
                    if dfs(neighbor, path[:]):
                        return True
                elif neighbor in rec_stack:
                    # Found a cycle
                    cycle_start = path.index(neighbor)
                    cycles.append(path[cycle_start:] + [neighbor])
            
            rec_stack.remove(node)
            return False
        
        for node in graph:
            if node not in visited:
                dfs(node, [])
        
        return cycles

    def run_thread_sanitizer_tests(self):
        """Run tests with thread sanitizer if available"""
        print("Attempting to run thread sanitizer tests...")
        
        # Check if we can run with thread sanitizer
        try:
            # Try to compile a simple test with thread sanitizer
            test_result = subprocess.run(
                ['cargo', 'test', '--', '--test-threads=1', '--nocapture'],
                env={**os.environ, 'RUSTFLAGS': '-Z sanitizer=thread'},
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if 'ThreadSanitizer' in test_result.stderr:
                # Parse thread sanitizer output
                tsan_errors = re.findall(
                    r'WARNING: ThreadSanitizer: ([^\n]+)',
                    test_result.stderr
                )
                
                for error in tsan_errors:
                    issue = ThreadSafetyIssue(
                        file_path='detected by thread sanitizer',
                        line_number=0,
                        issue_type='data_race',
                        description=f'ThreadSanitizer: {error}',
                        severity='critical',
                        suggestion='Fix the data race detected by thread sanitizer'
                    )
                    self.report.issues.append(issue)
        except Exception as e:
            print(f"Could not run thread sanitizer: {e}")

    def analyze_concurrent_tests(self):
        """Analyze tests that use concurrency"""
        print("Analyzing concurrent tests...")
        
        test_files = list(self.project_root.rglob("*test*.rs"))
        
        for test_file in test_files:
            try:
                with open(test_file, 'r') as f:
                    content = f.read()
                
                # Look for concurrent test patterns
                if any(pattern in content for pattern in ['thread::spawn', 'tokio::spawn', 'async_std::task']):
                    # Check for proper synchronization in tests
                    if 'thread::spawn' in content and not any(sync in content for sync in ['join()', 'Arc<', 'Mutex<', 'channel']):
                        issue = ThreadSafetyIssue(
                            file_path=str(test_file),
                            line_number=0,
                            issue_type='test_synchronization',
                            description='Concurrent test without proper synchronization',
                            severity='medium',
                            suggestion='Ensure spawned threads are joined or use proper synchronization'
                        )
                        self.report.issues.append(issue)
                    
                    # Check for race conditions in test assertions
                    if re.search(r'assert.*spawn.*assert', content, re.DOTALL):
                        issue = ThreadSafetyIssue(
                            file_path=str(test_file),
                            line_number=0,
                            issue_type='test_race',
                            description='Potential race condition in test assertions',
                            severity='medium',
                            suggestion='Use proper synchronization before assertions in concurrent tests'
                        )
                        self.report.issues.append(issue)
                        
            except Exception as e:
                print(f"Error analyzing test {test_file}: {e}")

    def get_suggestion(self, issue_type: str, description: str) -> str:
        """Get suggestions for fixing issues"""
        suggestions = {
            'Global mutable static': 'Use thread_local!, lazy_static with Mutex, or once_cell',
            'Arc<RefCell> combination': 'Use Arc<Mutex<T>> or Arc<RwLock<T>> instead',
            'Rc usage': 'Use Arc instead of Rc for thread-safe reference counting',
            'Mutex lock with unwrap': 'Use ? operator or handle PoisonError explicitly',
            'Nested locks': 'Restructure code to avoid nested locks or use a single Mutex',
            'Check-then-act pattern': 'Use compare_exchange or fetch_* operations',
            'Relaxed ordering': 'Consider if stronger ordering (Acquire/Release/SeqCst) is needed',
            'Deprecated compare_and_swap': 'Use compare_exchange or compare_exchange_weak',
        }
        
        for key, suggestion in suggestions.items():
            if key in description:
                return suggestion
        
        return "Review and fix the thread safety issue"

    def generate_report(self):
        """Generate a detailed report"""
        print("\n" + "="*80)
        print("THREAD SAFETY VALIDATION REPORT")
        print("="*80)
        
        # Summary
        critical = sum(1 for i in self.report.issues if i.severity == 'critical')
        high = sum(1 for i in self.report.issues if i.severity == 'high')
        medium = sum(1 for i in self.report.issues if i.severity == 'medium')
        low = sum(1 for i in self.report.issues if i.severity == 'low')
        
        print(f"\nTotal Issues Found: {len(self.report.issues)}")
        print(f"  Critical: {critical}")
        print(f"  High: {high}")
        print(f"  Medium: {medium}")
        print(f"  Low: {low}")
        
        # Good practices summary
        print(f"\nGood Practices Found:")
        print(f"  Files using Mutex/RwLock: {len(self.report.mutex_usage)}")
        print(f"  Files using Atomics: {len(self.report.atomic_usage)}")
        print(f"  Custom Send/Sync impls: {len(self.report.send_sync_impls)}")
        
        # Critical issues
        if critical > 0:
            print("\n⚠️  CRITICAL ISSUES:")
            for issue in self.report.issues:
                if issue.severity == 'critical':
                    print(f"\n📍 {issue.file_path}:{issue.line_number}")
                    print(f"   Type: {issue.issue_type}")
                    print(f"   Description: {issue.description}")
                    print(f"   Suggestion: {issue.suggestion}")
                    if issue.code_snippet:
                        print(f"   Code:\n{issue.code_snippet}")
        
        # High severity issues
        if high > 0:
            print("\n⚠️  HIGH SEVERITY ISSUES:")
            for issue in self.report.issues[:5]:  # Show first 5
                if issue.severity == 'high':
                    print(f"\n📍 {issue.file_path}:{issue.line_number}")
                    print(f"   Description: {issue.description}")
                    print(f"   Suggestion: {issue.suggestion}")
        
        # Save detailed report
        self.save_json_report()
        self.save_sarif_report()

    def save_json_report(self):
        """Save detailed JSON report"""
        report_data = {
            'summary': {
                'total_issues': len(self.report.issues),
                'critical': sum(1 for i in self.report.issues if i.severity == 'critical'),
                'high': sum(1 for i in self.report.issues if i.severity == 'high'),
                'medium': sum(1 for i in self.report.issues if i.severity == 'medium'),
                'low': sum(1 for i in self.report.issues if i.severity == 'low'),
                'files_analyzed': len(set(i.file_path for i in self.report.issues)),
            },
            'issues': [
                {
                    'file': issue.file_path,
                    'line': issue.line_number,
                    'type': issue.issue_type,
                    'description': issue.description,
                    'severity': issue.severity,
                    'suggestion': issue.suggestion,
                }
                for issue in self.report.issues
            ],
            'good_practices': {
                'mutex_usage': self.report.mutex_usage,
                'atomic_usage': self.report.atomic_usage,
                'send_sync_impls': self.report.send_sync_impls,
            }
        }
        
        with open('thread_safety_report.json', 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"\n✅ Detailed report saved to thread_safety_report.json")

    def save_sarif_report(self):
        """Save report in SARIF format for IDE integration"""
        sarif_report = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Thread Safety Validator",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/project/thread-safety-validator",
                        "rules": self.generate_sarif_rules()
                    }
                },
                "results": self.generate_sarif_results()
            }]
        }
        
        with open('thread_safety_report.sarif', 'w') as f:
            json.dump(sarif_report, f, indent=2)
        
        print(f"✅ SARIF report saved to thread_safety_report.sarif")

    def generate_sarif_rules(self) -> List[Dict]:
        """Generate SARIF rules"""
        rules = []
        rule_types = set((i.issue_type, i.description) for i in self.report.issues)
        
        for idx, (issue_type, description) in enumerate(rule_types):
            rules.append({
                "id": f"TS{idx:03d}",
                "name": issue_type,
                "shortDescription": {"text": description},
                "fullDescription": {"text": f"Thread safety issue: {description}"},
                "defaultConfiguration": {
                    "level": "error" if any(i.severity in ['critical', 'high'] for i in self.report.issues if i.issue_type == issue_type) else "warning"
                }
            })
        
        return rules

    def generate_sarif_results(self) -> List[Dict]:
        """Generate SARIF results"""
        results = []
        
        for issue in self.report.issues:
            results.append({
                "ruleId": f"TS{hash(issue.issue_type) % 1000:03d}",
                "level": "error" if issue.severity in ['critical', 'high'] else "warning",
                "message": {"text": issue.description},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": issue.file_path},
                        "region": {
                            "startLine": issue.line_number,
                            "startColumn": 1
                        }
                    }
                }],
                "fixes": [{
                    "description": {"text": issue.suggestion}
                }]
            })
        
        return results


def main():
    """Main entry point"""
    project_root = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    
    validator = ThreadSafetyValidator(project_root)
    report = validator.validate_project()
    
    # Exit with error if critical issues found
    critical_count = sum(1 for i in report.issues if i.severity == 'critical')
    if critical_count > 0:
        sys.exit(1)
    
    sys.exit(0)


if __name__ == "__main__":
    main()