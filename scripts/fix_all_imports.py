#!/usr/bin/env python3
"""
Fix all import statements to use absolute imports from src/.
"""

import os
import re
from pathlib import Path

# Define the root directory
ROOT_DIR = Path(__file__).parent.parent

# Map of relative imports to absolute imports
IMPORT_REPLACEMENTS = [
    # MCP server imports
    (r'from \.\.servers import', 'from src.mcp.servers import'),
    (r'from \.\.protocols import', 'from src.mcp.protocols import'),
    (r'from \.\.manager import', 'from src.mcp.manager import'),
    
    # Circle of Experts imports
    (r'from \.\.core\.expert_manager import', 'from src.circle_of_experts.core.expert_manager import'),
    (r'from \.\.mcp\.manager import', 'from src.mcp.manager import'),
    
    # Nested imports
    (r'from \.\.\.circle_of_experts\.utils\.logging import', 'from src.circle_of_experts.utils.logging import'),
    (r'from \.\.\.circle_of_experts\.models\.query import', 'from src.circle_of_experts.models.query import'),
    (r'from \.\.\.circle_of_experts\.models\.response import', 'from src.circle_of_experts.models.response import'),
]

def fix_imports_in_file(filepath: Path) -> bool:
    """Fix imports in a single file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Apply all replacements
        for pattern, replacement in IMPORT_REPLACEMENTS:
            content = re.sub(pattern, replacement, content)
        
        # Write back if changed
        if content != original_content:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        return False
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return False

def main():
    """Fix imports in all Python files."""
    print("🔧 Fixing imports in all Python files...")
    
    # Find all Python files in src/, tests/, and examples/
    python_files = []
    for directory in ['src', 'tests', 'examples']:
        dir_path = ROOT_DIR / directory
        if dir_path.exists():
            python_files.extend(dir_path.rglob('*.py'))
    
    # Add root-level test files
    python_files.extend(ROOT_DIR.glob('test_*.py'))
    
    fixed_count = 0
    for filepath in python_files:
        if fix_imports_in_file(filepath):
            print(f"✅ Fixed imports in: {filepath.relative_to(ROOT_DIR)}")
            fixed_count += 1
    
    print(f"\n✨ Fixed imports in {fixed_count} files")

if __name__ == "__main__":
    main()