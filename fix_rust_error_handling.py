#!/usr/bin/env python3
"""
Fix Rust error handling issues by replacing unwrap() calls with proper error handling.
"""

import re
from pathlib import Path
from typing import List, Tuple, Optional
import json

class RustErrorFixer:
    def __init__(self, rust_core_path: str):
        self.rust_core_path = Path(rust_core_path)
        self.fixes_applied = []
        
    def fix_unwrap_in_file(self, file_path: Path) -> List[Tuple[int, str, str]]:
        """Fix unwrap() calls in a single file."""
        fixes = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            return fixes
            
        modified_lines = lines.copy()
        
        for i, line in enumerate(lines):
            # Skip test code
            if self._is_test_line(file_path, i, lines):
                continue
                
            # Pattern 1: Simple .unwrap() calls
            if '.unwrap()' in line:
                # Check the context to determine the best fix
                context = self._analyze_context(lines, i)
                
                if context['in_async_function']:
                    # In async context, use ?
                    new_line = line.replace('.unwrap()', '?')
                elif context['in_result_function']:
                    # In Result-returning function, use ?
                    new_line = line.replace('.unwrap()', '?')
                elif context['is_regex']:
                    # For regex compilation, use expect with meaningful message
                    new_line = self._fix_regex_unwrap(line)
                elif context['is_lazy_static']:
                    # Lazy static initialization - these are typically safe
                    new_line = self._fix_lazy_static_unwrap(line)
                else:
                    # General case - use expect with context
                    new_line = self._fix_general_unwrap(line, context)
                
                if new_line != line:
                    modified_lines[i] = new_line
                    fixes.append((i + 1, line.strip(), new_line.strip()))
        
        # Write back if fixes were made
        if fixes:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(modified_lines)
            self.fixes_applied.extend([(str(file_path), fix) for fix in fixes])
            
        return fixes
    
    def _is_test_line(self, file_path: Path, line_num: int, lines: List[str]) -> bool:
        """Check if the line is in test code."""
        # Check file path
        if 'tests' in file_path.parts or file_path.name.endswith('_test.rs'):
            return True
            
        # Check for test attributes
        for i in range(max(0, line_num - 10), line_num):
            if '#[test]' in lines[i] or '#[cfg(test)]' in lines[i]:
                return True
                
        return False
    
    def _analyze_context(self, lines: List[str], line_num: int) -> dict:
        """Analyze the context of an unwrap() call."""
        context = {
            'in_async_function': False,
            'in_result_function': False,
            'is_regex': False,
            'is_lazy_static': False,
            'function_name': None,
            'variable_name': None
        }
        
        # Look backwards for function signature
        for i in range(line_num, max(0, line_num - 20), -1):
            line = lines[i - 1]
            
            # Check for async function
            if 'async fn' in line:
                context['in_async_function'] = True
                
            # Check for Result return type
            if '-> Result<' in line or '-> anyhow::Result<' in line:
                context['in_result_function'] = True
                
            # Extract function name
            fn_match = re.search(r'fn\s+(\w+)', line)
            if fn_match:
                context['function_name'] = fn_match.group(1)
                break
        
        # Check current line context
        current_line = lines[line_num]
        
        # Check if it's a regex
        if 'Regex::new' in current_line:
            context['is_regex'] = True
            
        # Check if it's in lazy_static
        for i in range(max(0, line_num - 5), line_num):
            if 'Lazy::new' in lines[i] or 'lazy_static!' in lines[i]:
                context['is_lazy_static'] = True
                break
                
        # Try to extract variable name
        var_match = re.search(r'let\s+(\w+)\s*=', current_line)
        if var_match:
            context['variable_name'] = var_match.group(1)
            
        return context
    
    def _fix_regex_unwrap(self, line: str) -> str:
        """Fix regex unwrap calls with meaningful expect messages."""
        # Extract the regex pattern
        pattern_match = re.search(r'Regex::new\(r?"([^"]+)"\)', line)
        if pattern_match:
            pattern = pattern_match.group(1)
            # Truncate long patterns
            if len(pattern) > 30:
                pattern = pattern[:27] + "..."
            return line.replace('.unwrap()', f'.expect("Failed to compile regex: {pattern}")')
        return line.replace('.unwrap()', '.expect("Failed to compile regex")')
    
    def _fix_lazy_static_unwrap(self, line: str) -> str:
        """Fix unwrap in lazy static context."""
        # For lazy static, panicking is often acceptable, but we should provide context
        if 'Regex::new' in line:
            return self._fix_regex_unwrap(line)
        return line.replace('.unwrap()', '.expect("Failed to initialize static value")')
    
    def _fix_general_unwrap(self, line: str, context: dict) -> str:
        """Fix general unwrap calls based on context."""
        # Try to determine what's being unwrapped
        if '.get(' in line and '.unwrap()' in line:
            return line.replace('.unwrap()', '.ok_or_else(|| CoreError::NotFound("Key not found in map".to_string()))?')
        elif '.acquire()' in line and '.unwrap()' in line:
            return line.replace('.unwrap()', '.expect("Failed to acquire semaphore permit")')
        elif 'lock()' in line and '.unwrap()' in line:
            return line.replace('.unwrap()', '.expect("Failed to acquire lock")')
        elif 'parse()' in line and '.unwrap()' in line:
            return line.replace('.unwrap()', '.expect("Failed to parse value")')
        else:
            # Generic fix
            func_context = f" in {context['function_name']}" if context['function_name'] else ""
            return line.replace('.unwrap()', f'.expect("Operation failed{func_context}")')
    
    def add_error_handling_imports(self, file_path: Path):
        """Add necessary imports for error handling."""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Check if we need to add imports
        needs_anyhow = '?' in content and 'use anyhow' not in content
        
        if needs_anyhow:
            # Add anyhow import after other use statements
            lines = content.split('\n')
            insert_pos = 0
            
            for i, line in enumerate(lines):
                if line.startswith('use '):
                    insert_pos = i + 1
                elif not line.strip() and insert_pos > 0:
                    break
                    
            lines.insert(insert_pos, 'use anyhow::Result;')
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))
    
    def fix_error_types(self, file_path: Path):
        """Ensure error types implement necessary traits."""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Find error types that need fixing
        error_pattern = re.compile(r'(pub\s+)?enum\s+(\w*Error\w*)\s*\{')
        
        for match in error_pattern.finditer(content):
            error_type = match.group(2)
            
            # Check if it already has derives
            start_pos = match.start()
            # Look backwards for derive
            before_enum = content[:start_pos]
            lines_before = before_enum.split('\n')
            
            has_error_derive = False
            for line in reversed(lines_before[-5:]):
                if '#[derive(' in line and 'Error' in line:
                    has_error_derive = True
                    break
                    
            if not has_error_derive:
                # Add thiserror derive
                derive_line = '#[derive(Debug, thiserror::Error)]'
                # Find where to insert
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if error_type in line and 'enum' in line:
                        lines.insert(i, derive_line)
                        break
                        
                content = '\n'.join(lines)
                
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)

def main():
    rust_core_path = "/home/louranicas/projects/claude-optimized-deployment/rust_core"
    fixer = RustErrorFixer(rust_core_path)
    
    # Read the detailed analysis
    with open("rust_error_handling_details.json", "r") as f:
        issues = json.load(f)
    
    print("Fixing Rust error handling issues...")
    
    # Group unwrap calls by file
    unwrap_by_file = {}
    for issue in issues['unwrap_calls']:
        file_path = issue['file']
        if file_path not in unwrap_by_file:
            unwrap_by_file[file_path] = []
        unwrap_by_file[file_path].append(issue)
    
    # Fix files with the most issues first
    sorted_files = sorted(unwrap_by_file.items(), key=lambda x: len(x[1]), reverse=True)
    
    total_fixes = 0
    for file_path, issues in sorted_files[:10]:  # Fix top 10 files first
        full_path = Path(rust_core_path) / "src" / file_path
        if full_path.exists():
            print(f"\nFixing {file_path} ({len(issues)} issues)...")
            fixes = fixer.fix_unwrap_in_file(full_path)
            total_fixes += len(fixes)
            
            if fixes:
                # Add necessary imports
                fixer.add_error_handling_imports(full_path)
                
                print(f"  Applied {len(fixes)} fixes")
                for line_num, old, new in fixes[:3]:  # Show first 3 fixes
                    print(f"  Line {line_num}:")
                    print(f"    - {old}")
                    print(f"    + {new}")
    
    # Fix error types
    print("\nFixing error type implementations...")
    for error_info in issues['custom_error_types']:
        if not error_info['definition']['uses_thiserror']:
            file_path = Path(rust_core_path) / "src" / error_info['file']
            if file_path.exists():
                print(f"  Fixing {error_info['type']} in {error_info['file']}")
                fixer.fix_error_types(file_path)
    
    print(f"\nTotal fixes applied: {total_fixes}")
    
    # Save fix report
    with open("rust_error_handling_fixes.json", "w") as f:
        json.dump({
            "total_fixes": total_fixes,
            "fixes_by_file": {str(k): v for k, v in fixer.fixes_applied}
        }, f, indent=2)

if __name__ == "__main__":
    main()