#!/usr/bin/env python3
"""
Simple test to verify path validation uses os.path.realpath and startswith
"""

import os
import sys
import tempfile
from pathlib import Path

# Add src directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import directly from the module file
import importlib.util
spec = importlib.util.spec_from_file_location("path_validation", "src/core/path_validation.py")
path_validation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(path_validation)

spec2 = importlib.util.spec_from_file_location("exceptions", "src/core/exceptions.py")
exceptions = importlib.util.module_from_spec(spec2)
spec2.loader.exec_module(exceptions)

validate_file_path = path_validation.validate_file_path
ValidationError = exceptions.ValidationError

def test_realpath_and_startswith():
    """Test that validate_file_path uses os.path.realpath and startswith"""
    
    with tempfile.TemporaryDirectory() as tmpdir:
        print(f"Testing with base directory: {tmpdir}")
        
        # Create a test file
        test_file = Path(tmpdir) / "test.txt"
        test_file.write_text("test content")
        
        # Test 1: File within base directory
        try:
            result = validate_file_path(str(test_file), tmpdir, allow_absolute=True)
            print(f"✅ File within base directory validated: {result}")
        except ValidationError as e:
            print(f"❌ Failed to validate file within base: {e}")
        
        # Test 2: File outside base directory
        try:
            result = validate_file_path("/etc/passwd", tmpdir, allow_absolute=True)
            print(f"❌ File outside base should have failed!")
        except ValidationError as e:
            print(f"✅ Correctly rejected file outside base: {e}")
        
        # Test 3: Directory traversal attempt
        try:
            traversal_path = str(Path(tmpdir) / ".." / ".." / "etc" / "passwd")
            result = validate_file_path(traversal_path, tmpdir, allow_absolute=True)
            print(f"❌ Directory traversal should have failed!")
        except ValidationError as e:
            print(f"✅ Correctly rejected directory traversal: {e}")
        
        # Verify the implementation uses os.path.realpath
        import inspect
        source = inspect.getsource(validate_file_path)
        if "os.path.realpath" in source:
            print("✅ Function uses os.path.realpath")
        else:
            print("❌ Function does not use os.path.realpath")
        
        if "startswith" in source:
            print("✅ Function uses startswith for base directory check")
        else:
            print("❌ Function does not use startswith")

if __name__ == "__main__":
    test_realpath_and_startswith()