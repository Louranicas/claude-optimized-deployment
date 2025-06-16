#\!/usr/bin/env python3
"""
Fix syntax errors in import statements caused by escaped newlines.
"""

import os
import re
from pathlib import Path

def fix_file(file_path):
    """Fix escaped newlines in a single file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Fix the specific pattern: \\n in import statements
        content = re.sub(r'\\n\s*', '\n    ', content)
        
        if content \!= original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"Fixed: {file_path}")
            return True
    except Exception as e:
        print(f"Error fixing {file_path}: {e}")
    
    return False

def main():
    """Fix all files with syntax errors."""
    files_to_fix = [
        "src/auth/models.py",
        "src/auth/tokens.py", 
        "src/mcp/client.py"
    ]
    
    fixed_count = 0
    for file_path in files_to_fix:
        if os.path.exists(file_path):
            if fix_file(file_path):
                fixed_count += 1
    
    print(f"Fixed {fixed_count} files.")

if __name__ == "__main__":
    main()
EOF < /dev/null
