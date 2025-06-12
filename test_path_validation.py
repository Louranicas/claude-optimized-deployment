"""
Test script to verify path validation functionality.
"""

import asyncio
import os
import tempfile
from pathlib import Path

from src.core.path_validation import validate_file_path, is_safe_path, sanitize_filename
from src.core.exceptions import ValidationError


def test_path_validation():
    """Test the path validation functions."""
    print("Testing Path Validation...")
    
    # Test cases for validate_file_path
    test_cases = [
        # (path, base_dir, allow_absolute, should_fail, description)
        ("normal_file.txt", None, False, False, "Normal relative file"),
        ("/etc/passwd", None, False, True, "Absolute path when not allowed"),
        ("/etc/passwd", None, True, False, "Absolute path when allowed"),
        ("../../../etc/passwd", None, False, True, "Directory traversal with ../"),
        ("..\\..\\..\\windows\\system32", None, False, True, "Windows directory traversal"),
        ("file\x00name.txt", None, False, True, "Null byte in filename"),
        ("%2e%2e/etc/passwd", None, False, True, "URL encoded directory traversal"),
        ("con.txt", None, False, True, "Windows reserved name"),
        (".hidden_file", None, False, False, "Hidden file (should log warning)"),
    ]
    
    for path, base_dir, allow_absolute, should_fail, description in test_cases:
        try:
            result = validate_file_path(path, base_dir, allow_absolute)
            if should_fail:
                print(f"❌ FAIL: {description} - Expected failure but succeeded: {path}")
            else:
                print(f"✅ PASS: {description} - Validated to: {result}")
        except ValidationError as e:
            if should_fail:
                print(f"✅ PASS: {description} - Correctly rejected: {path}")
            else:
                print(f"❌ FAIL: {description} - Unexpected rejection: {e}")
    
    # Test with base directory restriction
    with tempfile.TemporaryDirectory() as tmpdir:
        print(f"\nTesting with base directory: {tmpdir}")
        
        # Create a test file
        test_file = Path(tmpdir) / "test.txt"
        test_file.write_text("test content")
        
        base_test_cases = [
            (str(test_file), tmpdir, True, False, "File within base directory"),
            ("/etc/passwd", tmpdir, True, True, "File outside base directory"),
            (str(Path(tmpdir) / ".." / "outside.txt"), tmpdir, True, True, "Traversal outside base"),
        ]
        
        for path, base_dir, allow_absolute, should_fail, description in base_test_cases:
            try:
                result = validate_file_path(path, base_dir, allow_absolute)
                if should_fail:
                    print(f"❌ FAIL: {description} - Expected failure but succeeded: {path}")
                else:
                    print(f"✅ PASS: {description} - Validated to: {result}")
            except ValidationError as e:
                if should_fail:
                    print(f"✅ PASS: {description} - Correctly rejected: {path}")
                else:
                    print(f"❌ FAIL: {description} - Unexpected rejection: {e}")
    
    # Test is_safe_path
    print("\nTesting is_safe_path...")
    safe_test_cases = [
        ("normal.txt", None, True, "Normal file"),
        ("../etc/passwd", None, False, "Directory traversal"),
        ("con", None, False, "Reserved name"),
    ]
    
    for path, base_dir, expected_safe, description in safe_test_cases:
        result = is_safe_path(path, base_dir)
        if result == expected_safe:
            print(f"✅ PASS: {description} - is_safe={result}")
        else:
            print(f"❌ FAIL: {description} - Expected is_safe={expected_safe}, got {result}")
    
    # Test sanitize_filename
    print("\nTesting sanitize_filename...")
    sanitize_test_cases = [
        ("normal.txt", "normal.txt", "Normal filename"),
        ("../../../etc/passwd", "passwd", "Path traversal"),
        ("file:with*special?chars.txt", "file_with_special_chars.txt", "Special characters"),
        ("con.txt", "con.txt", "Reserved name (sanitize doesn't check reserved)"),
        ("..", "unnamed_file", "Just dots"),
        ("", "unnamed_file", "Empty string"),
        ("a" * 300 + ".txt", "a" * 251 + ".txt", "Very long filename"),
        ("file\x00name.txt", "file_name.txt", "Null byte"),
    ]
    
    for input_name, expected, description in sanitize_test_cases:
        result = sanitize_filename(input_name)
        if result == expected:
            print(f"✅ PASS: {description} - '{input_name}' -> '{result}'")
        else:
            print(f"❌ FAIL: {description} - Expected '{expected}', got '{result}'")


async def test_infrastructure_server():
    """Test the DesktopCommanderMCPServer with path validation."""
    print("\n\nTesting Infrastructure Server Path Validation...")
    
    from src.mcp.infrastructure_servers import DesktopCommanderMCPServer
    
    server = DesktopCommanderMCPServer()
    
    # Test read_file with various paths
    with tempfile.TemporaryDirectory() as tmpdir:
        server.working_directory = Path(tmpdir)
        
        # Create a safe test file
        safe_file = Path(tmpdir) / "safe.txt"
        safe_file.write_text("Safe content")
        
        # Test cases
        test_cases = [
            (str(safe_file), False, "Safe file in working directory"),
            ("../../../etc/passwd", True, "Directory traversal attempt"),
            (str(Path(tmpdir) / ".." / "outside.txt"), True, "Path outside working directory"),
        ]
        
        for file_path, should_fail, description in test_cases:
            try:
                result = await server._read_file(file_path)
                if should_fail:
                    print(f"❌ FAIL: {description} - Expected failure but succeeded")
                else:
                    print(f"✅ PASS: {description} - Successfully read file")
            except Exception as e:
                if should_fail:
                    print(f"✅ PASS: {description} - Correctly rejected: {type(e).__name__}")
                else:
                    print(f"❌ FAIL: {description} - Unexpected error: {e}")


async def test_cloud_storage():
    """Test the CloudStorageMCP with path validation."""
    print("\n\nTesting Cloud Storage Path Validation...")
    
    from src.mcp.storage.cloud_storage_server import CloudStorageMCP
    
    storage = CloudStorageMCP()
    
    # Test storage_upload with various paths
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a safe test file
        safe_file = Path(tmpdir) / "upload.txt"
        safe_file.write_text("Upload content")
        
        # Test cases
        test_cases = [
            (str(safe_file), "safe-name.txt", False, "Safe file and remote path"),
            ("../../../etc/passwd", "passwd", True, "Directory traversal in local path"),
            (str(safe_file), "../../../etc/passwd", False, "Directory traversal in remote path (should be sanitized)"),
        ]
        
        for local_path, remote_path, should_fail, description in test_cases:
            try:
                # Mock the actual upload since we don't have real cloud credentials
                result = await storage._storage_upload(
                    provider="s3",
                    container="test-bucket",
                    file_path=local_path,
                    remote_path=remote_path
                )
                if should_fail:
                    print(f"❌ FAIL: {description} - Expected failure but succeeded")
                else:
                    print(f"✅ PASS: {description} - Validation passed")
            except Exception as e:
                if should_fail:
                    print(f"✅ PASS: {description} - Correctly rejected: {type(e).__name__}")
                else:
                    print(f"❌ FAIL: {description} - Unexpected error: {e}")


def main():
    """Run all tests."""
    print("=" * 60)
    print("Path Validation Security Tests")
    print("=" * 60)
    
    # Run synchronous tests
    test_path_validation()
    
    # Run async tests
    asyncio.run(test_infrastructure_server())
    asyncio.run(test_cloud_storage())
    
    print("\n" + "=" * 60)
    print("Tests completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()