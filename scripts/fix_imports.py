#!/usr/bin/env python3
"""
Fix all imports in the codebase to use absolute imports from src/
"""

import os
import re
from pathlib import Path

# Define the project root
PROJECT_ROOT = Path(__file__).parent.parent
SRC_DIR = PROJECT_ROOT / "src"

# Patterns to replace
IMPORT_PATTERNS = [
    # Relative imports in src/circle_of_experts
    (r'from \.\.models\.query import', 'from src.circle_of_experts.models.query import'),
    (r'from \.\.models\.response import', 'from src.circle_of_experts.models.response import'),
    (r'from \.\.utils\.rust_integration import', 'from src.circle_of_experts.utils.rust_integration import'),
    (r'from \.\.utils\.logging import', 'from src.circle_of_experts.utils.logging import'),
    (r'from \.\.utils\.validation import', 'from src.circle_of_experts.utils.validation import'),
    (r'from \.\.utils\.retry import', 'from src.circle_of_experts.utils.retry import'),
    (r'from \.\.drive\.manager import', 'from src.circle_of_experts.drive.manager import'),
    (r'from \.\.experts\.expert_factory import', 'from src.circle_of_experts.experts.expert_factory import'),
    (r'from \.\.experts import', 'from src.circle_of_experts.experts import'),
    (r'from \.\.mcp_integration import', 'from src.circle_of_experts.mcp_integration import'),
    (r'from \.\.core import', 'from src.circle_of_experts.core import'),
    (r'from \.models import', 'from src.circle_of_experts.models import'),
    (r'from \.utils import', 'from src.circle_of_experts.utils import'),
    (r'from \.experts import', 'from src.circle_of_experts.experts import'),
    (r'from \.core import', 'from src.circle_of_experts.core import'),
    
    # Non-src imports that should have src prefix
    (r'^from circle_of_experts import', 'from src.circle_of_experts import'),
    (r'^from circle_of_experts\.', 'from src.circle_of_experts.'),
    (r'^from mcp import', 'from src.mcp import'),
    (r'^from mcp\.', 'from src.mcp.'),
    (r'^import circle_of_experts', 'import src.circle_of_experts'),
    (r'^import mcp', 'import src.mcp'),
    
    # Fix rust_accelerated imports
    (r'from src.circle_of_experts.core.rust_accelerated import', 'from src.circle_of_experts.core.rust_accelerated import'),
    (r'import src.circle_of_experts.core.rust_accelerated', 'import src.circle_of_experts.core.rust_accelerated'),
]

def fix_file_imports(filepath: Path) -> bool:
    """Fix imports in a single file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Apply all replacement patterns
        for pattern, replacement in IMPORT_PATTERNS:
            content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
        
        # Write back only if changed
        if content != original_content:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        return False
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return False

def main():
    """Fix all imports in the project."""
    print("Fixing imports in the codebase...")
    
    # Find all Python files
    python_files = []
    for pattern in ['src/**/*.py', 'tests/**/*.py', 'examples/**/*.py', 'scripts/**/*.py']:
        python_files.extend(PROJECT_ROOT.glob(pattern))
    
    # Also include test files in root
    python_files.extend(PROJECT_ROOT.glob('test_*.py'))
    python_files.extend(PROJECT_ROOT.glob('*_test.py'))
    
    # Fix imports
    fixed_count = 0
    for filepath in python_files:
        if fix_file_imports(filepath):
            print(f"Fixed imports in: {filepath.relative_to(PROJECT_ROOT)}")
            fixed_count += 1
    
    print(f"\nFixed imports in {fixed_count} files.")
    
    # Report on remaining issues
    print("\nChecking for remaining import issues...")
    
    # Check for relative imports
    relative_import_count = 0
    for filepath in python_files:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        if re.search(r'from \.\.', content):
            relative_import_count += 1
            print(f"  Still has relative imports: {filepath.relative_to(PROJECT_ROOT)}")
    
    # Check for non-src imports
    non_src_count = 0
    for filepath in python_files:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        if re.search(r'^(from|import) (circle_of_experts|mcp)(?!\s*$)', content, re.MULTILINE):
            # Check if it's not already with src prefix
            if not re.search(r'^(from|import) src\.(circle_of_experts|mcp)', content, re.MULTILINE):
                non_src_count += 1
                print(f"  Still missing src prefix: {filepath.relative_to(PROJECT_ROOT)}")
    
    print(f"\nSummary:")
    print(f"  Files with relative imports: {relative_import_count}")
    print(f"  Files missing src prefix: {non_src_count}")
    
    if relative_import_count == 0 and non_src_count == 0:
        print("\n✅ All imports are now using absolute paths from src/")
    else:
        print("\n⚠️  Some import issues remain. Please check the files listed above.")

if __name__ == "__main__":
    main()