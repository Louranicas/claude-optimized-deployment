#!/usr/bin/env python3
"""
Fix all remaining import issues in __init__.py files.
"""

import os
from pathlib import Path

# Define the root directory
ROOT_DIR = Path(__file__).parent.parent

# Files and their fixes
INIT_FILE_FIXES = {
    'src/circle_of_experts/drive/__init__.py': {
        'from .manager import': 'from src.circle_of_experts.drive.manager import'
    },
    'src/circle_of_experts/utils/__init__.py': {
        'from .retry import': 'from src.circle_of_experts.utils.retry import',
        'from .rust_integration import': 'from src.circle_of_experts.utils.rust_integration import',
        'from .validation import': 'from src.circle_of_experts.utils.validation import'
    },
    'src/core/__init__.py': {
        'from .parallel_executor import': 'from src.core.parallel_executor import'
    },
    'src/platform/__init__.py': {
        'from .wsl_integration import': 'from src.platform.wsl_integration import'
    },
    'src/mcp/base/__init__.py': {},
    'src/mcp/devops/__init__.py': {},
    'src/mcp/communication/__init__.py': {
        'from .slack_server import': 'from src.mcp.communication.slack_server import'
    },
    'src/mcp/infrastructure/__init__.py': {
        'from .commander_server import': 'from src.mcp.infrastructure.commander_server import'
    },
    'src/mcp/monitoring/__init__.py': {
        'from .prometheus_server import': 'from src.mcp.monitoring.prometheus_server import'
    },
    'src/mcp/security/__init__.py': {
        'from .scanner_server import': 'from src.mcp.security.scanner_server import',
        'from .auth_middleware import': 'from src.mcp.security.auth_middleware import'
    },
    'src/mcp/storage/__init__.py': {
        'from .s3_server import': 'from src.mcp.storage.s3_server import',
        'from .cloud_storage_server import': 'from src.mcp.storage.cloud_storage_server import'
    }
}

def fix_init_file(filepath: Path, replacements: dict) -> bool:
    """Fix imports in an __init__.py file."""
    if not filepath.exists():
        # Create empty __init__.py if it doesn't exist
        filepath.write_text('"""Package initialization."""\n')
        return True
        
    try:
        content = filepath.read_text(encoding='utf-8')
        original_content = content
        
        for old, new in replacements.items():
            content = content.replace(old, new)
        
        if content != original_content:
            filepath.write_text(content, encoding='utf-8')
            return True
        return False
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return False

def main():
    """Fix all __init__.py imports."""
    print("🔧 Fixing __init__.py imports...")
    
    fixed_count = 0
    for relative_path, replacements in INIT_FILE_FIXES.items():
        filepath = ROOT_DIR / relative_path
        if fix_init_file(filepath, replacements):
            print(f"✅ Fixed imports in: {relative_path}")
            fixed_count += 1
    
    print(f"\n✨ Fixed imports in {fixed_count} files")

if __name__ == "__main__":
    main()