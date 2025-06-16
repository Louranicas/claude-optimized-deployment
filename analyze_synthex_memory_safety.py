#!/usr/bin/env python3
"""Analyze SYNTHEX module for memory safety issues."""

import os
import re
import json
from pathlib import Path
from typing import List, Dict, Any

class SynthexMemorySafetyAnalyzer:
    def __init__(self, synthex_path: str):
        self.synthex_path = Path(synthex_path)
        self.issues = []
        
    def analyze(self) -> Dict[str, Any]:
        """Perform comprehensive memory safety analysis."""
        results = {
            'unsafe_blocks': self.analyze_unsafe_blocks(),
            'arc_mutex_patterns': self.analyze_arc_mutex_patterns(),
            'lifetime_issues': self.analyze_lifetime_issues(),
            'memory_leaks': self.analyze_potential_leaks(),
            'borrowing_violations': self.analyze_borrowing_violations(),
            'summary': {}
        }
        
        # Generate summary
        total_issues = sum(len(v) for v in results.values() if isinstance(v, list))
        results['summary'] = {
            'total_issues': total_issues,
            'critical_issues': self.count_critical_issues(results),
            'recommendations': self.generate_recommendations(results)
        }
        
        return results
    
    def analyze_unsafe_blocks(self) -> List[Dict[str, Any]]:
        """Analyze unsafe blocks for memory safety."""
        unsafe_issues = []
        
        for rust_file in self.synthex_path.rglob("*.rs"):
            if "tests" in str(rust_file):
                continue
                
            content = rust_file.read_text()
            
            # Find unsafe blocks
            unsafe_matches = re.finditer(r'unsafe\s*\{([^}]+)\}', content, re.DOTALL)
            
            for match in unsafe_matches:
                unsafe_code = match.group(1)
                line_num = content[:match.start()].count('\n') + 1
                
                issues = []
                
                # Check for transmute
                if 'transmute' in unsafe_code:
                    issues.append({
                        'type': 'unsafe_transmute',
                        'severity': 'high',
                        'description': 'Using std::mem::transmute can lead to undefined behavior',
                        'recommendation': 'Use TryFrom or safe conversions'
                    })
                
                # Check for raw pointer operations
                if re.search(r'\*\s*(const|mut)', unsafe_code):
                    issues.append({
                        'type': 'raw_pointer_deref',
                        'severity': 'medium',
                        'description': 'Raw pointer dereference without null check',
                        'recommendation': 'Add null checks or use safe alternatives'
                    })
                
                # Check for from_raw_parts
                if 'from_raw_parts' in unsafe_code:
                    issues.append({
                        'type': 'unsafe_slice_creation',
                        'severity': 'high',
                        'description': 'Creating slice from raw parts can violate memory safety',
                        'recommendation': 'Ensure proper lifetime and alignment'
                    })
                
                # Check for unaligned reads
                if 'read_unaligned' in unsafe_code:
                    issues.append({
                        'type': 'unaligned_read',
                        'severity': 'medium',
                        'description': 'Unaligned reads can cause issues on some architectures',
                        'recommendation': 'Consider using aligned reads or byte-by-byte copying'
                    })
                
                if issues:
                    unsafe_issues.append({
                        'file': str(rust_file.relative_to(self.synthex_path)),
                        'line': line_num,
                        'code': unsafe_code.strip()[:100] + '...' if len(unsafe_code) > 100 else unsafe_code.strip(),
                        'issues': issues
                    })
        
        return unsafe_issues
    
    def analyze_arc_mutex_patterns(self) -> List[Dict[str, Any]]:
        """Analyze Arc<Mutex<T>> patterns for deadlock potential."""
        arc_mutex_issues = []
        
        for rust_file in self.synthex_path.rglob("*.rs"):
            if "tests" in str(rust_file):
                continue
                
            content = rust_file.read_text()
            
            # Check for nested locks
            nested_lock_pattern = r'\.lock\(\).*\.lock\(\)'
            if re.search(nested_lock_pattern, content, re.DOTALL):
                arc_mutex_issues.append({
                    'file': str(rust_file.relative_to(self.synthex_path)),
                    'type': 'potential_deadlock',
                    'severity': 'high',
                    'description': 'Nested lock() calls detected - potential deadlock',
                    'recommendation': 'Use try_lock() or restructure to avoid nested locks'
                })
            
            # Check for lock ordering
            lock_calls = re.findall(r'(\w+)\.(?:write|read|lock)\(\)', content)
            if len(set(lock_calls)) > 1:
                arc_mutex_issues.append({
                    'file': str(rust_file.relative_to(self.synthex_path)),
                    'type': 'lock_ordering',
                    'severity': 'medium',
                    'description': 'Multiple locks without clear ordering',
                    'recommendation': 'Establish consistent lock ordering to prevent deadlocks'
                })
        
        return arc_mutex_issues
    
    def analyze_lifetime_issues(self) -> List[Dict[str, Any]]:
        """Analyze lifetime annotations and potential issues."""
        lifetime_issues = []
        
        for rust_file in self.synthex_path.rglob("*.rs"):
            if "tests" in str(rust_file):
                continue
                
            content = rust_file.read_text()
            
            # Check for self-referential structs
            if re.search(r"struct\s+\w+<'(\w+)>.*\{[^}]*&'\1\s+(?:mut\s+)?Self", content, re.DOTALL):
                lifetime_issues.append({
                    'file': str(rust_file.relative_to(self.synthex_path)),
                    'type': 'self_referential',
                    'severity': 'high',
                    'description': 'Self-referential struct detected',
                    'recommendation': 'Use Pin or restructure to avoid self-references'
                })
            
            # Check for missing lifetime bounds
            generic_refs = re.findall(r"<T>.*&T", content)
            if generic_refs:
                lifetime_issues.append({
                    'file': str(rust_file.relative_to(self.synthex_path)),
                    'type': 'missing_lifetime_bound',
                    'severity': 'low',
                    'description': 'Generic reference without lifetime bound',
                    'recommendation': 'Add lifetime bounds to generic parameters'
                })
        
        return lifetime_issues
    
    def analyze_potential_leaks(self) -> List[Dict[str, Any]]:
        """Analyze potential memory leaks."""
        leak_issues = []
        
        for rust_file in self.synthex_path.rglob("*.rs"):
            if "tests" in str(rust_file):
                continue
                
            content = rust_file.read_text()
            
            # Check for mem::forget
            if 'mem::forget' in content:
                leak_issues.append({
                    'file': str(rust_file.relative_to(self.synthex_path)),
                    'type': 'explicit_forget',
                    'severity': 'medium',
                    'description': 'Using mem::forget can cause resource leaks',
                    'recommendation': 'Ensure resources are properly cleaned up'
                })
            
            # Check for Rc cycles
            if re.search(r'Rc<RefCell<.*Rc<', content):
                leak_issues.append({
                    'file': str(rust_file.relative_to(self.synthex_path)),
                    'type': 'rc_cycle_potential',
                    'severity': 'high',
                    'description': 'Potential Rc cycle detected',
                    'recommendation': 'Use Weak references to break cycles'
                })
            
            # Check for spawned tasks without joins
            if re.search(r'tokio::spawn\([^)]+\)(?!\.await)', content):
                leak_issues.append({
                    'file': str(rust_file.relative_to(self.synthex_path)),
                    'type': 'detached_task',
                    'severity': 'low',
                    'description': 'Spawned task without join',
                    'recommendation': 'Consider storing JoinHandle for cleanup'
                })
        
        return leak_issues
    
    def analyze_borrowing_violations(self) -> List[Dict[str, Any]]:
        """Analyze potential borrowing rule violations."""
        borrowing_issues = []
        
        for rust_file in self.synthex_path.rglob("*.rs"):
            if "tests" in str(rust_file):
                continue
                
            content = rust_file.read_text()
            
            # Check for multiple mutable borrows
            if re.search(r'&mut\s+\w+.*&mut\s+\w+', content):
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if re.search(r'&mut\s+\w+.*&mut\s+\w+', line):
                        borrowing_issues.append({
                            'file': str(rust_file.relative_to(self.synthex_path)),
                            'line': i + 1,
                            'type': 'multiple_mut_borrow',
                            'severity': 'medium',
                            'description': 'Potential multiple mutable borrows',
                            'recommendation': 'Restructure to avoid simultaneous mutable borrows'
                        })
        
        return borrowing_issues
    
    def count_critical_issues(self, results: Dict[str, Any]) -> int:
        """Count critical severity issues."""
        count = 0
        for category, issues in results.items():
            if isinstance(issues, list):
                for issue in issues:
                    if isinstance(issue, dict):
                        severity = issue.get('severity')
                        if severity == 'high':
                            count += 1
                        elif 'issues' in issue:
                            for sub_issue in issue['issues']:
                                if sub_issue.get('severity') == 'high':
                                    count += 1
        return count
    
    def generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []
        
        if results['unsafe_blocks']:
            recommendations.append("Replace unsafe transmute with safe type conversions")
            recommendations.append("Add safety documentation for all unsafe blocks")
            recommendations.append("Consider using bytemuck for safe transmutations")
        
        if results['arc_mutex_patterns']:
            recommendations.append("Use parking_lot for better deadlock detection")
            recommendations.append("Implement consistent lock ordering across the codebase")
            recommendations.append("Consider lock-free data structures where possible")
        
        if results['lifetime_issues']:
            recommendations.append("Review and fix self-referential structures")
            recommendations.append("Add explicit lifetime annotations where needed")
        
        if results['memory_leaks']:
            recommendations.append("Replace Rc cycles with Weak references")
            recommendations.append("Implement proper cleanup for spawned tasks")
        
        return recommendations


def main():
    synthex_path = "/home/louranicas/projects/claude-optimized-deployment/rust_core/src/synthex"
    analyzer = SynthexMemorySafetyAnalyzer(synthex_path)
    
    print("Analyzing SYNTHEX module for memory safety issues...")
    results = analyzer.analyze()
    
    # Print results
    print("\n=== SYNTHEX Memory Safety Analysis Report ===\n")
    
    print(f"Total Issues Found: {results['summary']['total_issues']}")
    print(f"Critical Issues: {results['summary']['critical_issues']}")
    
    if results['unsafe_blocks']:
        print(f"\n## Unsafe Blocks ({len(results['unsafe_blocks'])} found)")
        for issue in results['unsafe_blocks']:
            print(f"\n  File: {issue['file']}, Line: {issue['line']}")
            print(f"  Code: {issue['code']}")
            for sub_issue in issue['issues']:
                print(f"    - {sub_issue['type']}: {sub_issue['description']}")
                print(f"      Recommendation: {sub_issue['recommendation']}")
    
    if results['arc_mutex_patterns']:
        print(f"\n## Arc/Mutex Patterns ({len(results['arc_mutex_patterns'])} found)")
        for issue in results['arc_mutex_patterns']:
            print(f"\n  File: {issue['file']}")
            print(f"  Issue: {issue['description']}")
            print(f"  Recommendation: {issue['recommendation']}")
    
    if results['lifetime_issues']:
        print(f"\n## Lifetime Issues ({len(results['lifetime_issues'])} found)")
        for issue in results['lifetime_issues']:
            print(f"\n  File: {issue['file']}")
            print(f"  Issue: {issue['description']}")
            print(f"  Recommendation: {issue['recommendation']}")
    
    if results['memory_leaks']:
        print(f"\n## Potential Memory Leaks ({len(results['memory_leaks'])} found)")
        for issue in results['memory_leaks']:
            print(f"\n  File: {issue['file']}")
            print(f"  Issue: {issue['description']}")
            print(f"  Recommendation: {issue['recommendation']}")
    
    print("\n## Recommendations:")
    for rec in results['summary']['recommendations']:
        print(f"  - {rec}")
    
    # Save detailed report
    with open('synthex_memory_safety_report.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print("\n\nDetailed report saved to synthex_memory_safety_report.json")


if __name__ == "__main__":
    main()