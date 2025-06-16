#!/usr/bin/env python3
"""
Core validation script for the script integration without optional dependencies.

This script validates that the core utility modules work correctly without
requiring all optional dependencies like asyncpg.
"""

import sys
import traceback
import importlib
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))


def test_core_module_imports():
    """Test that core utility modules can be imported successfully."""
    print("🔍 Testing Core Module Imports...")
    
    modules_to_test = [
        'src.utils.imports',
        'src.utils.git', 
        'src.utils.security',
        'src.utils.monitoring',
        'src.utils'
    ]
    
    success_count = 0
    total_count = len(modules_to_test)
    
    for module_name in modules_to_test:
        try:
            module = importlib.import_module(module_name)
            
            # Check that expected classes are available
            if module_name == 'src.utils.imports':
                assert hasattr(module, 'ImportManager')
                
            elif module_name == 'src.utils.git':
                assert hasattr(module, 'GitManager')
                
            elif module_name == 'src.utils.security':
                assert hasattr(module, 'SecurityValidator')
                
            elif module_name == 'src.utils.monitoring':
                assert hasattr(module, 'MemoryAnalyzer')
                
            elif module_name == 'src.utils':
                # Test main module imports
                assert hasattr(module, 'ImportManager')
                assert hasattr(module, 'GitManager')
                assert hasattr(module, 'SecurityValidator')
                assert hasattr(module, 'MemoryAnalyzer')
                
            success_count += 1
            print(f"✅ {module_name}: Import successful")
            
        except Exception as e:
            print(f"❌ {module_name}: {str(e)}")
            
    print(f"\n📊 Core Module Imports: {success_count}/{total_count} passed")
    return success_count == total_count


def test_core_utility_instantiation():
    """Test that core utility classes can be instantiated."""
    print("\n🔍 Testing Core Utility Instantiation...")
    
    try:
        from src.utils import ImportManager, GitManager, SecurityValidator, MemoryAnalyzer
        
        utilities_to_test = [
            ('ImportManager', lambda: ImportManager()),
            ('GitManager', lambda: GitManager()),
            ('SecurityValidator', lambda: SecurityValidator()),
            ('MemoryAnalyzer', lambda: MemoryAnalyzer())
        ]
        
        success_count = 0
        
        for utility_name, factory in utilities_to_test:
            try:
                instance = factory()
                assert instance is not None
                success_count += 1
                print(f"✅ {utility_name}: Instantiation successful")
                
            except Exception as e:
                print(f"❌ {utility_name}: {str(e)}")
                
        print(f"\n📊 Core Utility Instantiation: {success_count}/{len(utilities_to_test)} passed")
        return success_count == len(utilities_to_test)
        
    except ImportError as e:
        print(f"❌ Import error: {str(e)}")
        return False


def test_core_cli_interfaces():
    """Test that CLI interfaces are accessible."""
    print("\n🔍 Testing Core CLI Interfaces...")
    
    cli_modules = [
        'src.utils.imports',
        'src.utils.git',
        'src.utils.security',
        'src.utils.monitoring'
    ]
    
    success_count = 0
    
    for module_name in cli_modules:
        try:
            module = importlib.import_module(module_name)
            
            # Check that main function exists
            assert hasattr(module, 'main'), f"No main() function in {module_name}"
            assert callable(module.main), f"main() is not callable in {module_name}"
            
            success_count += 1
            print(f"✅ {module_name}: CLI interface available")
            
        except Exception as e:
            print(f"❌ {module_name}: {str(e)}")
            
    print(f"\n📊 Core CLI Interfaces: {success_count}/{len(cli_modules)} passed")
    return success_count == len(cli_modules)


def test_core_functionality():
    """Test basic functionality of core modules."""
    print("\n🔍 Testing Core Module Functionality...")
    
    try:
        from src.utils import ImportManager, GitManager, SecurityValidator, MemoryAnalyzer
        
        success_count = 0
        total_tests = 4
        
        # Test ImportManager
        try:
            import_manager = ImportManager()
            test_file = project_root / 'src' / '__init__.py'
            if test_file.exists():
                issues = import_manager.analyze_file(test_file)
                assert isinstance(issues, list)
            success_count += 1
            print("✅ ImportManager: File analysis working")
        except Exception as e:
            print(f"❌ ImportManager: {str(e)}")
            
        # Test GitManager  
        try:
            git_manager = GitManager()
            status = git_manager.get_status()
            assert hasattr(status, 'branch')
            assert hasattr(status, 'is_clean')
            success_count += 1
            print("✅ GitManager: Status retrieval working")
        except Exception as e:
            print(f"❌ GitManager: {str(e)}")
            
        # Test SecurityValidator
        try:
            security_validator = SecurityValidator()
            assert hasattr(security_validator, 'run_static_analysis')
            assert callable(security_validator.run_static_analysis)
            success_count += 1
            print("✅ SecurityValidator: Methods available")
        except Exception as e:
            print(f"❌ SecurityValidator: {str(e)}")
            
        # Test MemoryAnalyzer
        try:
            memory_analyzer = MemoryAnalyzer()
            snapshot = memory_analyzer.capture_snapshot()
            assert hasattr(snapshot, 'timestamp')
            assert hasattr(snapshot, 'process_memory_mb')
            success_count += 1
            print("✅ MemoryAnalyzer: Snapshot capture working")
        except Exception as e:
            print(f"❌ MemoryAnalyzer: {str(e)}")
            
        print(f"\n📊 Core Functionality: {success_count}/{total_tests} passed")
        return success_count == total_tests
        
    except ImportError as e:
        print(f"❌ Import error: {str(e)}")
        return False


def test_modular_architecture():
    """Test that the modular architecture is properly implemented."""
    print("\n🔍 Testing Modular Architecture...")
    
    try:
        # Test that modules can be imported independently
        from src.utils.imports import ImportManager
        from src.utils.git import GitManager
        from src.utils.security import SecurityValidator
        from src.utils.monitoring import MemoryAnalyzer
        
        # Test that they work independently
        im = ImportManager()
        gm = GitManager()
        sv = SecurityValidator()
        ma = MemoryAnalyzer()
        
        # Test that they have expected interfaces
        assert hasattr(im, 'analyze_project')
        assert hasattr(gm, 'get_status')
        assert hasattr(sv, 'run_full_audit')
        assert hasattr(ma, 'capture_snapshot')
        
        print("✅ Modular architecture: All modules independent and functional")
        return True
        
    except Exception as e:
        print(f"❌ Modular architecture: {str(e)}")
        return False


def main():
    """Main validation function."""
    print("🔍 Validating Core Script Integration")
    print("=" * 60)
    
    tests = [
        test_core_module_imports,
        test_core_utility_instantiation,
        test_core_cli_interfaces,
        test_core_functionality,
        test_modular_architecture
    ]
    
    passed_tests = 0
    total_tests = len(tests)
    
    for test_func in tests:
        try:
            if test_func():
                passed_tests += 1
        except Exception as e:
            print(f"💥 {test_func.__name__}: CRASHED - {str(e)}")
            traceback.print_exc()
            
    print("\n" + "=" * 60)
    print("📊 CORE VALIDATION SUMMARY")
    print("=" * 60)
    
    if passed_tests == total_tests:
        print(f"✅ SUCCESS: {passed_tests}/{total_tests} tests passed")
        print("\n🎉 Core script integration validation completed successfully!")
        print("All core utility modules are operational and ready for use.")
        print("\n📋 Available Utilities:")
        print("- ImportManager: Python import analysis and fixing")
        print("- GitManager: Git operations and multi-remote management")  
        print("- SecurityValidator: Security auditing and vulnerability scanning")
        print("- MemoryAnalyzer: Memory usage analysis and leak detection")
        print("\n🚀 Usage Examples:")
        print("# Programmatic usage")
        print("from src.utils import ImportManager, GitManager")
        print("manager = ImportManager()")
        print("result = manager.analyze_project()")
        print("")
        print("# CLI usage")
        print("python -m src.utils.imports analyze .")
        print("python -m src.utils.git status")
        print("python -m src.utils.security scan static")
        print("python -m src.utils.monitoring analyze")
        
        return 0
    else:
        print(f"❌ FAILURE: {total_tests - passed_tests}/{total_tests} tests failed")
        print("\n⚠️ Some issues detected during core validation.")
        print("Please review the failures above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())