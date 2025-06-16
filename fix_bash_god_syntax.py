#!/usr/bin/env python3
"""
FIX SCRIPT - Fix syntax issues in bash god server
"""

import re
from pathlib import Path

def fix_escape_sequences():
    """Fix escape sequence issues in the bash god server"""
    
    server_path = Path("mcp_learning_system/bash_god_mcp_server.py")
    
    # Read the file
    with open(server_path, "r") as f:
        content = f.read()
    
    # Fix escape sequences
    replacements = [
        # Fix the grep pattern with brackets
        (r'"cat /proc/{pid}/wchan && ps -eo pid,wchan,cmd \| grep -v \'\\\[\' \| head -20"',
         r'"cat /proc/{pid}/wchan && ps -eo pid,wchan,cmd | grep -v \'\\\\[\' | head -20"'),
        
        # Fix the awk pattern with dollar sign
        (r'\'ss -tan \| awk "NR>1 {state\[\\\$1\]\+\+} END {for\(s in state\) print s, state\[s\]}" \| sort -k2 -nr\'',
         r'\'ss -tan | awk "NR>1 {state[\\\\$1]++} END {for(s in state) print s, state[s]}" | sort -k2 -nr\''),
        
        # Fix the VGA pattern
        (r"'VGA\\|3D'",
         r"'VGA\\\\|3D'"),
        
        # Fix the find exec pattern
        (r'} \\;',
         r'} \\\\;'),
    ]
    
    for old, new in replacements:
        content = re.sub(old, new, content)
    
    # Also fix any indentation issues
    # Find lines that might have indentation problems around line 4218
    lines = content.split('\n')
    
    # Fix any lines that have incorrect indentation
    fixed_lines = []
    in_command_block = False
    proper_indent = "        "  # 8 spaces for command definitions
    
    for i, line in enumerate(lines):
        # Check if we're in a command definition block
        if "system_admin_commands = [" in line:
            in_command_block = True
        elif in_command_block and line.strip() == "]":
            in_command_block = False
        
        # Fix indentation for lines that seem misaligned
        if in_command_block and line.strip() and not line.startswith(proper_indent):
            # Count leading spaces
            spaces = len(line) - len(line.lstrip())
            if spaces % 4 != 0:  # Not properly indented
                # Round to nearest multiple of 4
                new_spaces = round(spaces / 4) * 4
                line = " " * new_spaces + line.lstrip()
        
        fixed_lines.append(line)
    
    content = '\n'.join(fixed_lines)
    
    # Write the fixed content
    with open(server_path, "w") as f:
        f.write(content)
    
    print("✓ Fixed escape sequences and indentation")
    
    # Verify syntax
    try:
        compile(content, server_path, 'exec')
        print("✓ Python syntax is now valid")
        return True
    except SyntaxError as e:
        print(f"❌ Still has syntax error: {e}")
        print(f"   Line {e.lineno}: {lines[e.lineno-1] if e.lineno <= len(lines) else 'N/A'}")
        return False

if __name__ == "__main__":
    print("FIXING BASH GOD SYNTAX ISSUES")
    print("=" * 60)
    
    if fix_escape_sequences():
        print("\n✅ All syntax issues fixed!")
    else:
        print("\n⚠️  Some issues remain")