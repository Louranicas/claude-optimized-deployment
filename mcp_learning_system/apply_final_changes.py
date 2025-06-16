#!/usr/bin/env python3
"""Apply final changes to bash_god_mcp_server.py"""
import re

# Read the commands to add
with open("commands_to_add.py", "r") as f:
    commands_content = f.read()

# Extract security commands section
security_start = commands_content.find("# Security Commands")
security_end = commands_content.find("# Development Commands")
security_commands = commands_content[security_start:security_end].strip()

# Read current file
with open("bash_god_mcp_server.py", "r") as f:
    content = f.read()

# Find where to insert security commands (after sec_ids_suricata)
pattern = r'(\s+"id": "sec_ids_suricata"[^}]+\})'
match = re.search(pattern, content, re.DOTALL)
if match:
    # Extract just the command definitions from security_commands
    cmd_lines = []
    for line in security_commands.split("\n")[1:]:  # Skip header
        if line.strip():
            cmd_lines.append(line)
    
    insertion_point = match.end()
    new_content = content[:insertion_point] + "".join(cmd_lines) + content[insertion_point:]
    
    # Write updated file
    with open("bash_god_mcp_server.py", "w") as f:
        f.write(new_content)
    
    print("Successfully added security commands!")
else:
    print("Could not find insertion point for security commands")

# TODO: Add development and devops commands similarly
