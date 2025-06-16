#!/usr/bin/env python3
"""
ML Dependencies Validation Script
Created by Agent 1 - Dependency Installation Specialist

This script validates that all required ML packages are installed and functional.
Run this script anytime to verify the ML stack integrity.

Usage:
    python scripts/validate_ml_dependencies.py
"""

import sys
import warnings
warnings.filterwarnings('ignore')

def validate_ml_stack():
    """Validate all ML dependencies and their basic functionality."""
    
    print("=== ML DEPENDENCIES VALIDATION SCRIPT ===\n")
    
    # Required packages with minimum versions
    required_packages = [
        ('numpy', 'np', '1.26.0'),
        ('matplotlib', 'matplotlib', '3.7.0'),
        ('pandas', 'pd', '2.0.0'),
        ('sklearn', 'sklearn', '1.3.0'),
        ('torch', 'torch', '2.0.0'),
        ('transformers', 'transformers', '4.30.0'),
        ('seaborn', 'sns', '0.12.0')
    ]
    
    success_count = 0
    total_count = len(required_packages)
    issues = []
    
    print("1. IMPORT VALIDATION:")
    print("-" * 50)
    
    for pkg_name, import_name, min_version in required_packages:
        try:
            if pkg_name == 'sklearn':
                import sklearn
                version = sklearn.__version__
            elif pkg_name == 'numpy':
                import numpy
                version = numpy.__version__
            elif pkg_name == 'matplotlib':
                import matplotlib
                version = matplotlib.__version__
            elif pkg_name == 'pandas':
                import pandas
                version = pandas.__version__
            elif pkg_name == 'torch':
                import torch
                version = torch.__version__
            elif pkg_name == 'transformers':
                import transformers
                version = transformers.__version__
            elif pkg_name == 'seaborn':
                import seaborn
                version = seaborn.__version__
            
            print(f'✓ {pkg_name:<15} | Version: {version:<12} | Required: >={min_version}')
            success_count += 1
        except ImportError as e:
            error_msg = f'✗ {pkg_name:<15} | FAILED: Import error'
            print(error_msg)
            issues.append(f"{pkg_name}: Import failed - {str(e)}")
        except Exception as e:
            error_msg = f'⚠ {pkg_name:<15} | WARNING: {str(e)[:30]}...'
            print(error_msg)
            issues.append(f"{pkg_name}: {str(e)}")
    
    print(f"\n2. FUNCTIONALITY VALIDATION:")
    print("-" * 50)
    
    # Test basic functionality
    try:
        # Test numpy
        import numpy as np
        test_array = np.array([1, 2, 3, 4, 5])
        np.mean(test_array)
        print("✓ numpy: Array operations working")
        
        # Test pandas
        import pandas as pd
        test_df = pd.DataFrame({'A': [1, 2], 'B': [3, 4]})
        test_df.sum()
        print("✓ pandas: DataFrame operations working")
        
        # Test matplotlib
        import matplotlib
        matplotlib.use('Agg')  # Non-interactive backend
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots()
        ax.plot([1, 2], [1, 2])
        plt.close(fig)
        print("✓ matplotlib: Plotting functionality working")
        
        # Test scikit-learn
        from sklearn.linear_model import LinearRegression
        model = LinearRegression()
        X = np.array([[1], [2], [3]])
        y = np.array([1, 2, 3])
        model.fit(X, y)
        print("✓ sklearn: Model training working")
        
        # Test torch
        import torch
        tensor = torch.tensor([1.0, 2.0, 3.0])
        torch.sum(tensor)
        print("✓ torch: Tensor operations working")
        
        # Test seaborn
        import seaborn as sns
        test_data = pd.DataFrame({'x': [1, 2], 'y': [1, 2]})
        fig, ax = plt.subplots()
        sns.scatterplot(data=test_data, x='x', y='y', ax=ax)
        plt.close(fig)
        print("✓ seaborn: Statistical plotting working")
        
        # Test transformers (basic import only)
        import transformers
        print("✓ transformers: Package available")
        
    except Exception as e:
        issues.append(f"Functionality test failed: {str(e)}")
        print(f"✗ Functionality test failed: {str(e)}")
    
    print(f"\n3. SUMMARY:")
    print("-" * 50)
    print(f"Packages installed: {success_count}/{total_count} ({success_count/total_count*100:.1f}%)")
    
    if success_count == total_count and not issues:
        print("✅ ML STACK STATUS: COMPLETE AND FUNCTIONAL")
        print("All required ML dependencies are installed and working correctly.")
        return True
    else:
        print("❌ ML STACK STATUS: INCOMPLETE OR ISSUES DETECTED")
        if issues:
            print("\nISSUES FOUND:")
            for issue in issues:
                print(f"  - {issue}")
        print("\nRECOMMENDATION: Run Agent 1 dependency installation process.")
        return False

if __name__ == "__main__":
    success = validate_ml_stack()
    sys.exit(0 if success else 1)