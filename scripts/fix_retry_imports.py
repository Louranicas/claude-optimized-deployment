#!/usr/bin/env python3
"""
Fix all retry_api_call imports to use the correct module.
"""

import os
import re
from pathlib import Path

# Define the root directory
ROOT_DIR = Path(__file__).parent.parent

# The correct import statement
CORRECT_IMPORT = "from src.core.retry import retry_api_call, RetryConfig, RetryStrategy"
INCORRECT_PATTERN = r"from src\.circle_of_experts\.utils\.retry import retry_api_call.*"

def fix_imports_in_file(filepath: Path) -> bool:
    """Fix imports in a single file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Replace the incorrect import
        content = re.sub(INCORRECT_PATTERN, CORRECT_IMPORT, content)
        
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
    """Fix retry imports in all Python files."""
    print("🔧 Fixing retry_api_call imports...")
    
    # Find all Python files
    python_files = list(ROOT_DIR.rglob('*.py'))
    
    fixed_count = 0
    for filepath in python_files:
        if 'venv' in str(filepath) or '__pycache__' in str(filepath):
            continue
            
        if fix_imports_in_file(filepath):
            print(f"✅ Fixed imports in: {filepath.relative_to(ROOT_DIR)}")
            fixed_count += 1
    
    print(f"\n✨ Fixed imports in {fixed_count} files")

if __name__ == "__main__":
    main()