#!/usr/bin/env python3
"""
Test script to verify security updates for vulnerable dependencies.
This script checks if the minimum secure versions are met.
"""

import sys
import subprocess
import json
from typing import Dict, List, Tuple

# Mapping of packages to their minimum secure versions based on CVE fixes
SECURE_VERSIONS = {
    "cryptography": "41.0.6",  # Fix for multiple CVEs
    "aiohttp": "3.9.0",        # General security requirement
    "twisted": "24.7.0",       # Fix for CVE-2024-41810, CVE-2024-41671, CVE-2022-39348
    "certifi": "2023.7.22",    # Fix for CVE-2023-37920, CVE-2022-23491
    "idna": "3.7",             # Fix for CVE-2024-3651
    "configobj": "5.0.9",      # Fix for CVE-2023-26112
    "pyjwt": "2.4.0",          # Fix for CVE-2022-29217
    "pyyaml": "5.4",           # Fix for CVE-2020-14343 (we require 6.0+)
}

def get_package_version(package_name: str) -> str:
    """Get the installed version of a package."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "show", package_name],
            capture_output=True,
            text=True,
            check=True
        )
        for line in result.stdout.split('\n'):
            if line.startswith('Version:'):
                return line.split(':', 1)[1].strip()
    except subprocess.CalledProcessError:
        return None
    return None

def compare_versions(current: str, required: str) -> bool:
    """Simple version comparison. Returns True if current >= required."""
    if not current:
        return False
    
    # Simple version comparison - split by dots and compare numerically
    try:
        current_parts = [int(x) for x in current.split('.') if x.isdigit()]
        required_parts = [int(x) for x in required.split('.') if x.isdigit()]
        
        # Pad shorter version with zeros
        max_len = max(len(current_parts), len(required_parts))
        current_parts += [0] * (max_len - len(current_parts))
        required_parts += [0] * (max_len - len(required_parts))
        
        return current_parts >= required_parts
    except ValueError:
        # Fallback to string comparison if numeric fails
        return current >= required

def main():
    """Main function to check security requirements."""
    print("🔒 Security Update Verification")
    print("=" * 50)
    
    all_secure = True
    results = []
    
    for package, min_version in SECURE_VERSIONS.items():
        current_version = get_package_version(package)
        
        if current_version is None:
            status = "❌ NOT INSTALLED"
            is_secure = False
        elif compare_versions(current_version, min_version):
            status = "✅ SECURE"
            is_secure = True
        else:
            status = "⚠️  VULNERABLE"
            is_secure = False
            all_secure = False
        
        results.append({
            "package": package,
            "current": current_version,
            "required": min_version,
            "secure": is_secure,
            "status": status
        })
        
        print(f"{status} {package}: {current_version or 'N/A'} (req: >={min_version})")
    
    print("\n" + "=" * 50)
    
    if all_secure:
        print("🎉 All security requirements met!")
        return 0
    else:
        print("⚠️  Some packages need security updates!")
        print("\nTo fix vulnerable packages, run:")
        for result in results:
            if not result["secure"] and result["current"] is not None:
                print(f"pip install '{result['package']}>={result['required']}'")
        return 1

if __name__ == "__main__":
    sys.exit(main())