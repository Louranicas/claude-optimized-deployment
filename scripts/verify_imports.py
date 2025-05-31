#!/usr/bin/env python3
"""
Verify that all imports in the codebase are working correctly.
"""

import sys
import ast
import importlib
from pathlib import Path
from typing import List, Tuple, Set

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

class ImportChecker(ast.NodeVisitor):
    """AST visitor to extract import statements."""
    
    def __init__(self):
        self.imports: List[Tuple[str, int]] = []
        self.from_imports: List[Tuple[str, str, int]] = []
    
    def visit_Import(self, node):
        """Visit import statements."""
        for alias in node.names:
            self.imports.append((alias.name, node.lineno))
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node):
        """Visit from ... import statements."""
        if node.module:
            for alias in node.names:
                self.from_imports.append((node.module, alias.name, node.lineno))
        self.generic_visit(node)

def extract_imports(filepath: Path) -> Tuple[List[Tuple[str, int]], List[Tuple[str, str, int]]]:
    """Extract all imports from a Python file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read(), filename=str(filepath))
        
        checker = ImportChecker()
        checker.visit(tree)
        return checker.imports, checker.from_imports
    except Exception as e:
        print(f"Error parsing {filepath}: {e}")
        return [], []

def check_import(module_name: str) -> Tuple[bool, str]:
    """Check if an import can be resolved."""
    try:
        # Skip certain modules that require special handling
        skip_modules = {
            'rust_accelerated',  # Rust extension
            'src.circle_of_experts.core.rust_accelerated',  # Rust extension
        }
        
        if module_name in skip_modules:
            return True, "Skipped (Rust extension)"
        
        # Try to import the module
        importlib.import_module(module_name)
        return True, "OK"
    except ImportError as e:
        return False, str(e)
    except Exception as e:
        return False, f"Unexpected error: {e}"

def verify_file_imports(filepath: Path) -> List[str]:
    """Verify all imports in a single file."""
    errors = []
    imports, from_imports = extract_imports(filepath)
    
    # Check regular imports
    for module_name, line_no in imports:
        success, error = check_import(module_name)
        if not success:
            errors.append(f"{filepath}:{line_no} - import {module_name} - {error}")
    
    # Check from imports
    checked_modules = set()
    for module_name, _, line_no in from_imports:
        if module_name not in checked_modules:
            success, error = check_import(module_name)
            if not success:
                errors.append(f"{filepath}:{line_no} - from {module_name} import ... - {error}")
            checked_modules.add(module_name)
    
    return errors

def main():
    """Verify all imports in the codebase."""
    print("🔍 Verifying imports in CODE project...")
    print("=" * 60)
    
    # Find all Python files
    python_files = []
    for directory in ['src', 'tests', 'examples']:
        dir_path = PROJECT_ROOT / directory
        if dir_path.exists():
            python_files.extend(dir_path.rglob('*.py'))
    
    # Add root-level test files
    python_files.extend(PROJECT_ROOT.glob('test_*.py'))
    
    # Skip virtual environment and other directories
    skip_dirs = {'venv', 'venv_linux', '__pycache__', '.git', 'node_modules', 'target'}
    python_files = [
        f for f in python_files 
        if not any(skip_dir in str(f) for skip_dir in skip_dirs)
    ]
    
    all_errors = []
    checked_count = 0
    
    for filepath in sorted(python_files):
        errors = verify_file_imports(filepath)
        if errors:
            all_errors.extend(errors)
        checked_count += 1
    
    # Report results
    print(f"\n✅ Checked {checked_count} files")
    
    if all_errors:
        print(f"\n❌ Found {len(all_errors)} import errors:\n")
        for error in all_errors:
            print(f"  • {error}")
        
        # Group errors by type
        print("\n📊 Error Summary:")
        error_types = {}
        for error in all_errors:
            if "No module named" in error:
                module = error.split("No module named")[1].split("'")[1]
                error_types.setdefault("Missing modules", set()).add(module)
            elif "cannot import name" in error:
                error_types.setdefault("Import name errors", set()).add(error.split(" - ")[1])
        
        for error_type, items in error_types.items():
            print(f"\n{error_type}:")
            for item in sorted(items):
                print(f"  • {item}")
        
        return 1
    else:
        print("\n✨ All imports verified successfully!")
        return 0

if __name__ == "__main__":
    sys.exit(main())