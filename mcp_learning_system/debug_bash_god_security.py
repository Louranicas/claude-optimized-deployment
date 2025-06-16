#!/usr/bin/env python3
"""Debug BASH GOD security validation"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from bash_god_mcp_server import BashGodCommandValidator

validator = BashGodCommandValidator()

dangerous_cmds = [
    "rm -rf /",
    ":(){ :|:& };:",
    "echo test; cat /etc/passwd",
    "sudo su -"
]

print("Testing dangerous commands:")
for cmd in dangerous_cmds:
    result = validator.validate_command_safety(cmd)
    print(f"\nCommand: {cmd}")
    print(f"Safety Level: {result['safety_level']}")
    print(f"Allow Execution: {result['allow_execution']}")
    print(f"Warnings: {result.get('warnings', [])}")