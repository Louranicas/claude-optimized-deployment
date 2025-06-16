#!/usr/bin/env python3
import re
import os

def fix_file(filepath):
    try:
        with open(filepath, 'r') as f:
            content = f.read()
        
        # Fix escaped newlines in imports
        original = content
        content = content.replace('\\n', '\n')
        
        if content != original:
            with open(filepath, 'w') as f:
                f.write(content)
            print(f"Fixed {filepath}")
            return True
    except Exception as e:
        print(f"Error with {filepath}: {e}")
    return False

# Fix known problematic files
files = [
    "src/auth/models.py",
    "src/auth/tokens.py", 
    "src/mcp/client.py"
]

for f in files:
    if os.path.exists(f):
        fix_file(f)