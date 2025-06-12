#!/usr/bin/env python3
"""
Simple CORS Security Validation

Basic validation that CORS fixes have been applied correctly.
"""

import re
import sys
from pathlib import Path
from typing import List, Tuple


def check_file_for_wildcards(file_path: Path) -> List[Tuple[int, str]]:
    """Check a file for CORS wildcard patterns."""
    if not file_path.exists():
        return []
    
    wildcard_patterns = [
        r'allow_origins.*\[.*"\*".*\]',
        r'Access-Control-Allow-Origin.*"\*"',
        r'allowed_origins.*=.*\[.*"\*".*\]'
    ]
    
    issues = []
    
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        for line_num, line in enumerate(lines, 1):
            for pattern in wildcard_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append((line_num, line.strip()))
    
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    
    return issues


def check_for_secure_cors_import(file_path: Path) -> bool:
    """Check if file imports secure CORS configuration."""
    if not file_path.exists():
        return False
    
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Look for imports of our secure CORS config
        import_patterns = [
            r'from.*cors_config.*import',
            r'import.*cors_config',
            r'get_fastapi_cors_config',
            r'get_cors_config'
        ]
        
        for pattern in import_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
    
    except Exception:
        return False


def main():
    """Main validation function."""
    print("🔒 Simple CORS Security Validation")
    print("=" * 40)
    
    project_root = Path(__file__).parent
    
    # Files to check for CORS issues
    files_to_check = [
        "test_api_functionality.py",
        "src/auth/middleware.py"
    ]
    
    total_issues = 0
    
    # Check each file
    for file_name in files_to_check:
        file_path = project_root / file_name
        print(f"\n📄 Checking {file_name}...")
        
        # Check for wildcard patterns
        wildcards = check_file_for_wildcards(file_path)
        if wildcards:
            print(f"  ❌ Found {len(wildcards)} wildcard CORS patterns:")
            for line_num, line in wildcards:
                print(f"    Line {line_num}: {line}")
            total_issues += len(wildcards)
        else:
            print(f"  ✅ No wildcard CORS patterns found")
        
        # Check for secure imports
        has_secure_import = check_for_secure_cors_import(file_path)
        if has_secure_import:
            print(f"  ✅ Uses secure CORS configuration")
        else:
            print(f"  ⚠️  No secure CORS imports detected")
    
    # Check if secure CORS config exists
    cors_config_path = project_root / "src" / "core" / "cors_config.py"
    if cors_config_path.exists():
        print(f"\n✅ Secure CORS configuration module exists: {cors_config_path}")
    else:
        print(f"\n❌ Secure CORS configuration module missing!")
        total_issues += 1
    
    # Summary
    print(f"\n📊 Summary:")
    print(f"Files checked: {len(files_to_check)}")
    print(f"Issues found: {total_issues}")
    
    if total_issues == 0:
        print(f"\n🎉 CORS security validation PASSED!")
        print(f"✅ No wildcard CORS patterns found")
        print(f"✅ Secure CORS configuration is in place")
        return 0
    else:
        print(f"\n❌ CORS security validation FAILED!")
        print(f"⚠️  {total_issues} security issues found")
        return 1


if __name__ == "__main__":
    sys.exit(main())