#!/usr/bin/env python3
"""
Check Python ML dependencies
"""
import sys
import pkgutil

def check_dependencies():
    print('Python version:', sys.version.split()[0])
    print('=' * 50)
    
    packages = ['sklearn', 'torch', 'pandas', 'transformers', 'seaborn', 'numpy', 'matplotlib']
    missing = []
    
    for pkg in packages:
        result = pkgutil.find_loader(pkg)
        status = "✅ Available" if result else "❌ Missing"
        print(f'{pkg:15}: {status}')
        if not result:
            missing.append(pkg)
    
    print('=' * 50)
    if missing:
        print(f'❌ Missing packages: {missing}')
        return False
    else:
        print('✅ All ML dependencies available')
        return True

if __name__ == "__main__":
    success = check_dependencies()
    sys.exit(0 if success else 1)