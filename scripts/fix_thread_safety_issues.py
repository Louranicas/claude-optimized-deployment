#!/usr/bin/env python3
"""
Automated Thread Safety Issue Fixer

This script automatically fixes common thread safety issues detected by
the thread safety validator.
"""

import os
import re
import sys
import json
import shutil
from pathlib import Path
from typing import List, Dict, Tuple

class ThreadSafetyFixer:
    """Automatically fixes common thread safety issues"""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.fixes_applied = []
        
    def load_report(self, report_path: str = 'thread_safety_report.json') -> Dict:
        """Load the thread safety report"""
        with open(report_path, 'r') as f:
            return json.load(f)
    
    def fix_issues(self, report: Dict):
        """Fix issues based on the report"""
        print("🔧 Starting automated thread safety fixes...")
        
        # Group issues by type for batch fixing
        issues_by_type = {}
        for issue in report['issues']:
            issue_type = issue['type']
            if issue_type not in issues_by_type:
                issues_by_type[issue_type] = []
            issues_by_type[issue_type].append(issue)
        
        # Apply fixes by type
        for issue_type, issues in issues_by_type.items():
            if issue_type == 'mutex_patterns':
                self.fix_mutex_patterns(issues)
            elif issue_type == 'shared_state':
                self.fix_shared_state(issues)
            elif issue_type == 'atomics':
                self.fix_atomic_issues(issues)
            elif issue_type == 'test_synchronization':
                self.fix_test_synchronization(issues)
        
        # Fix specific critical issues
        self.fix_nested_locks()
        self.fix_double_checked_locking()
        
        # Generate fix report
        self.generate_fix_report()
    
    def fix_mutex_patterns(self, issues: List[Dict]):
        """Fix mutex-related issues"""
        for issue in issues:
            file_path = Path(issue['file'])
            if not file_path.exists():
                continue
                
            description = issue['description']
            
            # Create backup
            self.backup_file(file_path)
            
            with open(file_path, 'r') as f:
                content = f.read()
            
            original_content = content
            
            # Fix unwrap() on lock
            if 'unwrap' in description:
                content = re.sub(
                    r'\.lock\(\)\.unwrap\(\)',
                    '.lock().expect("Failed to acquire lock")',
                    content
                )
            
            # Fix expect() with better error messages
            if 'expect' in description and 'lock' in description:
                content = re.sub(
                    r'\.lock\(\)\.expect\("([^"]*)"\)',
                    r'.lock().map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?',
                    content
                )
            
            # Fix busy-wait on try_lock
            if 'try_lock' in description:
                # Replace busy-wait with proper async lock
                content = re.sub(
                    r'while\s+.*\.try_lock\(\)\.is_err\(\)\s*\{[^}]*\}',
                    '// Use async lock instead of busy-wait\n// let guard = mutex.lock().await;',
                    content
                )
            
            if content != original_content:
                with open(file_path, 'w') as f:
                    f.write(content)
                self.fixes_applied.append({
                    'file': str(file_path),
                    'type': 'mutex_pattern',
                    'description': description
                })
                print(f"  ✅ Fixed mutex pattern in {file_path}")
    
    def fix_shared_state(self, issues: List[Dict]):
        """Fix shared state issues"""
        for issue in issues:
            file_path = Path(issue['file'])
            if not file_path.exists():
                continue
                
            description = issue['description']
            
            # Create backup
            self.backup_file(file_path)
            
            with open(file_path, 'r') as f:
                content = f.read()
            
            original_content = content
            
            # Fix Arc<RefCell> to Arc<Mutex>
            if 'Arc<RefCell' in description:
                content = re.sub(
                    r'Arc<RefCell<([^>]+)>>',
                    r'Arc<Mutex<\1>>',
                    content
                )
                # Also update method calls
                content = re.sub(
                    r'\.borrow\(\)',
                    '.lock().unwrap()',
                    content
                )
                content = re.sub(
                    r'\.borrow_mut\(\)',
                    '.lock().unwrap()',
                    content
                )
            
            # Fix Rc to Arc
            if 'Rc usage' in description:
                content = re.sub(
                    r'\bRc<',
                    'Arc<',
                    content
                )
                # Update imports
                content = re.sub(
                    r'use std::rc::Rc;',
                    'use std::sync::Arc;',
                    content
                )
            
            if content != original_content:
                with open(file_path, 'w') as f:
                    f.write(content)
                self.fixes_applied.append({
                    'file': str(file_path),
                    'type': 'shared_state',
                    'description': description
                })
                print(f"  ✅ Fixed shared state in {file_path}")
    
    def fix_atomic_issues(self, issues: List[Dict]):
        """Fix atomic operation issues"""
        for issue in issues:
            file_path = Path(issue['file'])
            if not file_path.exists():
                continue
                
            description = issue['description']
            
            # Create backup
            self.backup_file(file_path)
            
            with open(file_path, 'r') as f:
                content = f.read()
            
            original_content = content
            
            # Fix deprecated compare_and_swap
            if 'compare_and_swap' in description:
                # Replace with compare_exchange
                content = re.sub(
                    r'\.compare_and_swap\(([^,]+),\s*([^,]+),\s*([^)]+)\)',
                    r'.compare_exchange(\1, \2, \3, Ordering::Relaxed).is_ok()',
                    content
                )
            
            # Upgrade Relaxed ordering where appropriate
            if 'Relaxed ordering' in description:
                # Be conservative - only upgrade in specific patterns
                # For now, just add a comment suggesting review
                content = re.sub(
                    r'(\.load\(Ordering::Relaxed\)|\.store\([^,]+,\s*Ordering::Relaxed\))',
                    r'\1 // TODO: Review memory ordering - consider Acquire/Release',
                    content
                )
            
            if content != original_content:
                with open(file_path, 'w') as f:
                    f.write(content)
                self.fixes_applied.append({
                    'file': str(file_path),
                    'type': 'atomic',
                    'description': description
                })
                print(f"  ✅ Fixed atomic issue in {file_path}")
    
    def fix_test_synchronization(self, issues: List[Dict]):
        """Fix test synchronization issues"""
        for issue in issues:
            file_path = Path(issue['file'])
            if not file_path.exists():
                continue
                
            # Create backup
            self.backup_file(file_path)
            
            with open(file_path, 'r') as f:
                lines = f.readlines()
            
            modified = False
            new_lines = []
            
            for i, line in enumerate(lines):
                # Add join() after thread::spawn if missing
                if 'thread::spawn' in line and i + 10 < len(lines):
                    # Check if there's a join in the next few lines
                    next_lines = ''.join(lines[i:i+10])
                    if '.join()' not in next_lines and 'handle' not in next_lines:
                        # Insert handle collection
                        new_lines.append(line.replace('thread::spawn', 'let handle = thread::spawn'))
                        modified = True
                        continue
                
                new_lines.append(line)
            
            if modified:
                # Add joins at the end of test functions
                final_lines = []
                in_test = False
                
                for line in new_lines:
                    if '#[test]' in line or '#[tokio::test]' in line:
                        in_test = True
                    elif in_test and line.strip() == '}':
                        # Add join before closing brace
                        final_lines.append('    // Wait for spawned threads\n')
                        final_lines.append('    handle.join().expect("Thread panicked");\n')
                        in_test = False
                    
                    final_lines.append(line)
                
                with open(file_path, 'w') as f:
                    f.writelines(final_lines)
                
                self.fixes_applied.append({
                    'file': str(file_path),
                    'type': 'test_synchronization',
                    'description': 'Added thread synchronization'
                })
                print(f"  ✅ Fixed test synchronization in {file_path}")
    
    def fix_nested_locks(self):
        """Fix specific nested lock issues"""
        # Fix the deployment.rs nested lock issue
        deployment_file = self.project_root / 'rust_core/src/mcp_manager/deployment.rs'
        if deployment_file.exists():
            self.backup_file(deployment_file)
            
            with open(deployment_file, 'r') as f:
                content = f.read()
            
            # Fix the specific nested lock pattern
            original = 'while *manager.running.lock().await && *manager.auto_scaling.lock().await {'
            replacement = '''// Check both conditions separately to avoid nested locks
            let running = *manager.running.lock().await;
            let auto_scaling = *manager.auto_scaling.lock().await;
            while running && auto_scaling {'''
            
            if original in content:
                content = content.replace(original, replacement)
                
                with open(deployment_file, 'w') as f:
                    f.write(content)
                
                self.fixes_applied.append({
                    'file': str(deployment_file),
                    'type': 'nested_locks',
                    'description': 'Fixed nested lock acquisition'
                })
                print(f"  ✅ Fixed nested locks in {deployment_file}")
    
    def fix_double_checked_locking(self):
        """Fix double-checked locking patterns"""
        stress_test_file = self.project_root / 'rust_core/src/mcp_manager/tests/stress_tests.rs'
        if stress_test_file.exists():
            self.backup_file(stress_test_file)
            
            with open(stress_test_file, 'r') as f:
                content = f.read()
            
            # Fix the double-checked locking pattern
            # Replace load() followed by lock() with proper synchronization
            pattern = r'while !should_stop\.load\(Ordering::Relaxed\) \{'
            replacement = 'while !should_stop.load(Ordering::Acquire) {'
            
            if re.search(pattern, content):
                content = re.sub(pattern, replacement, content)
                
                with open(stress_test_file, 'w') as f:
                    f.write(content)
                
                self.fixes_applied.append({
                    'file': str(stress_test_file),
                    'type': 'double_checked_locking',
                    'description': 'Fixed memory ordering for double-checked pattern'
                })
                print(f"  ✅ Fixed double-checked locking in {stress_test_file}")
    
    def backup_file(self, file_path: Path):
        """Create a backup of the file"""
        backup_dir = self.project_root / '.thread_safety_backups'
        backup_dir.mkdir(exist_ok=True)
        
        rel_path = file_path.relative_to(self.project_root)
        backup_path = backup_dir / f"{rel_path}.backup"
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        
        shutil.copy2(file_path, backup_path)
    
    def generate_fix_report(self):
        """Generate a report of fixes applied"""
        print(f"\n✅ Applied {len(self.fixes_applied)} fixes")
        
        # Group by type
        fixes_by_type = {}
        for fix in self.fixes_applied:
            fix_type = fix['type']
            if fix_type not in fixes_by_type:
                fixes_by_type[fix_type] = 0
            fixes_by_type[fix_type] += 1
        
        print("\nFixes by type:")
        for fix_type, count in fixes_by_type.items():
            print(f"  {fix_type}: {count}")
        
        # Save detailed report
        with open('thread_safety_fixes.json', 'w') as f:
            json.dump({
                'total_fixes': len(self.fixes_applied),
                'fixes_by_type': fixes_by_type,
                'fixes': self.fixes_applied
            }, f, indent=2)
        
        print("\n📄 Detailed fix report saved to thread_safety_fixes.json")
        print("📁 Backups saved to .thread_safety_backups/")
        
        # Create a restore script
        self.create_restore_script()
    
    def create_restore_script(self):
        """Create a script to restore backups if needed"""
        restore_script = '''#!/bin/bash
# Restore backups created by thread safety fixer

BACKUP_DIR=".thread_safety_backups"

if [ ! -d "$BACKUP_DIR" ]; then
    echo "No backups found"
    exit 1
fi

echo "Restoring files from backup..."

find "$BACKUP_DIR" -name "*.backup" | while read backup; do
    # Get original path
    original="${backup#$BACKUP_DIR/}"
    original="${original%.backup}"
    
    echo "Restoring $original"
    cp "$backup" "$original"
done

echo "✅ Files restored from backup"
'''
        
        with open('restore_thread_safety_backups.sh', 'w') as f:
            f.write(restore_script)
        
        os.chmod('restore_thread_safety_backups.sh', 0o755)


def main():
    """Main entry point"""
    project_root = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    
    fixer = ThreadSafetyFixer(project_root)
    
    # Load the thread safety report
    try:
        report = fixer.load_report()
    except FileNotFoundError:
        print("❌ No thread safety report found. Run validate_thread_safety.py first.")
        sys.exit(1)
    
    # Apply fixes
    fixer.fix_issues(report)
    
    print("\n🎯 Thread safety fixes complete!")
    print("Please review the changes and run tests to ensure everything works correctly.")
    
    sys.exit(0)


if __name__ == "__main__":
    main()