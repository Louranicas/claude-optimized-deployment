"""
Comprehensive test suite for path_validation module.

Tests cover:
- Path validation edge cases
- Directory traversal protection
- URL encoding attacks
- Windows reserved names
- Symlink handling
- Base directory restrictions
- Error conditions and security scenarios
"""

import os
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, mock_open

from src.core.path_validation import (
    validate_file_path,
    is_safe_path,
    sanitize_filename,
    ValidationError
)


class TestValidateFilePath:
    """Test the validate_file_path function with comprehensive edge cases."""
    
    def test_valid_relative_path(self):
        """Test valid relative path validation."""
        result = validate_file_path("test.txt")
        assert isinstance(result, Path)
        assert result.is_absolute()
    
    def test_valid_absolute_path_when_allowed(self):
        """Test valid absolute path when explicitly allowed."""
        test_path = "/tmp/test.txt"
        result = validate_file_path(test_path, allow_absolute=True)
        assert isinstance(result, Path)
        assert result.is_absolute()
    
    def test_reject_absolute_path_when_not_allowed(self):
        """Test rejection of absolute paths when not allowed."""
        test_path = "/tmp/test.txt"
        with pytest.raises(ValidationError, match="absolute paths are not allowed"):
            validate_file_path(test_path, allow_absolute=False)
    
    def test_null_byte_injection(self):
        """Test protection against null byte injection."""
        with pytest.raises(ValidationError, match="contains null bytes"):
            validate_file_path("test.txt\x00")
    
    def test_directory_traversal_attacks(self):
        """Test protection against various directory traversal patterns."""
        dangerous_patterns = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32",
            "test/../../../etc/passwd",
            "test/..%2f..%2f..%2fetc%2fpasswd",
            "test%2e%2e%2f%2e%2e%2fpasswd",
            "test%252e%252e%252fpasswd",
            "..%2ftest",
            "..%5ctest"
        ]
        
        for pattern in dangerous_patterns:
            with pytest.raises(ValidationError, match="directory traversal pattern"):
                validate_file_path(pattern, allow_absolute=True)
    
    def test_windows_reserved_names(self):
        """Test protection against Windows reserved file names."""
        reserved_names = [
            "con", "CON", "Con.txt",
            "prn", "PRN", "prn.log",
            "aux", "AUX", "aux.dat",
            "nul", "NUL", "nul.txt",
            "com1", "COM1", "com1.txt",
            "com9", "COM9", "com9.log",
            "lpt1", "LPT1", "lpt1.txt",
            "lpt9", "LPT9", "lpt9.log"
        ]
        
        for name in reserved_names:
            with pytest.raises(ValidationError, match="reserved system name"):
                validate_file_path(name)
    
    def test_base_directory_restriction(self):
        """Test base directory restriction functionality."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Valid path within base directory
            safe_path = os.path.join(temp_dir, "test.txt")
            result = validate_file_path(safe_path, base_directory=temp_dir, allow_absolute=True)
            assert str(result).startswith(str(Path(temp_dir).resolve()))
            
            # Invalid path outside base directory
            with pytest.raises(ValidationError, match="must be within base directory"):
                validate_file_path("/tmp/outside.txt", base_directory=temp_dir, allow_absolute=True)
    
    def test_nonexistent_base_directory(self):
        """Test error handling for nonexistent base directory."""
        with pytest.raises(ValidationError, match="Base directory does not exist"):
            validate_file_path("test.txt", base_directory="/nonexistent/path")
    
    @patch('os.path.realpath')
    def test_path_resolution_error(self, mock_realpath):
        """Test handling of path resolution errors."""
        mock_realpath.side_effect = OSError("Resolution failed")
        
        with pytest.raises(ValidationError, match="cannot resolve path"):
            validate_file_path("test.txt")
    
    def test_symlink_handling(self):
        """Test symlink handling with allow_symlinks parameter."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a test file and symlink
            test_file = os.path.join(temp_dir, "test.txt")
            with open(test_file, 'w') as f:
                f.write("test")
            
            symlink_path = os.path.join(temp_dir, "test_link.txt")
            try:
                os.symlink(test_file, symlink_path)
                
                # Should reject symlink when not allowed
                with pytest.raises(ValidationError, match="symbolic links are not allowed"):
                    validate_file_path(symlink_path, allow_symlinks=False, allow_absolute=True)
                
                # Should accept symlink when allowed
                result = validate_file_path(symlink_path, allow_symlinks=True, allow_absolute=True)
                assert isinstance(result, Path)
                
            except OSError:
                # Skip test on systems that don't support symlinks
                pytest.skip("System doesn't support symlinks")
    
    def test_hidden_file_warning(self, caplog):
        """Test that hidden files generate warnings but are allowed."""
        result = validate_file_path(".hidden")
        assert isinstance(result, Path)
        assert "hidden file requested" in caplog.text
    
    def test_edge_case_filenames(self):
        """Test edge case filenames that should be valid."""
        valid_names = [
            "normal_file.txt",
            "file-with-dashes.log",
            "file_with_underscores.dat",
            "file123.ext",
            "UPPERCASE.TXT",
            "mixed_CASE_file.pdf"
        ]
        
        for name in valid_names:
            result = validate_file_path(name)
            assert isinstance(result, Path)
    
    def test_empty_path(self):
        """Test handling of empty paths."""
        with pytest.raises(ValidationError):
            validate_file_path("")
    
    def test_path_object_input(self):
        """Test that Path objects are handled correctly."""
        path_obj = Path("test.txt")
        result = validate_file_path(path_obj)
        assert isinstance(result, Path)


class TestIsSafePath:
    """Test the is_safe_path convenience function."""
    
    def test_safe_path_returns_true(self):
        """Test that safe paths return True."""
        assert is_safe_path("safe_file.txt") is True
    
    def test_unsafe_path_returns_false(self):
        """Test that unsafe paths return False."""
        assert is_safe_path("../../../etc/passwd") is False
        assert is_safe_path("con.txt") is False
        assert is_safe_path("test\x00.txt") is False
    
    def test_with_base_directory(self):
        """Test is_safe_path with base directory parameter."""
        with tempfile.TemporaryDirectory() as temp_dir:
            assert is_safe_path("test.txt", base_directory=temp_dir) is True
            assert is_safe_path("/tmp/outside.txt", base_directory=temp_dir) is False


class TestSanitizeFilename:
    """Test the sanitize_filename function."""
    
    def test_remove_dangerous_characters(self):
        """Test removal of dangerous characters."""
        dangerous_chars = {
            "file/name.txt": "file_name.txt",
            "file\\name.txt": "file_name.txt",
            "file:name.txt": "file_name.txt",
            "file*name.txt": "file_name.txt",
            "file?name.txt": "file_name.txt",
            'file"name.txt': "file_name.txt",
            "file<name.txt": "file_name.txt",
            "file>name.txt": "file_name.txt",
            "file|name.txt": "file_name.txt",
            "file\x00name.txt": "file_name.txt",
            "file\nname.txt": "file_name.txt",
            "file\rname.txt": "file_name.txt",
            "file\tname.txt": "file_name.txt"
        }
        
        for dangerous, expected in dangerous_chars.items():
            result = sanitize_filename(dangerous)
            assert result == expected
    
    def test_remove_path_components(self):
        """Test that path components are removed."""
        assert sanitize_filename("/path/to/file.txt") == "file.txt"
        assert sanitize_filename("C:\\path\\to\\file.txt") == "file.txt"
        assert sanitize_filename("../../../file.txt") == "file.txt"
    
    def test_trim_dots_and_spaces(self):
        """Test trimming of leading/trailing dots and spaces."""
        test_cases = {
            "   file.txt   ": "file.txt",
            "...file.txt...": "file.txt",
            " . file.txt . ": "file.txt",
            "  ..  file.txt  ..  ": "file.txt"
        }
        
        for input_name, expected in test_cases.items():
            result = sanitize_filename(input_name)
            assert result == expected
    
    def test_handle_empty_or_dots_only(self):
        """Test handling of empty filenames or dots-only names."""
        test_cases = ["", ".", "..", "   ", "...", " . . "]
        
        for empty_name in test_cases:
            result = sanitize_filename(empty_name)
            assert result == "unnamed_file"
    
    def test_length_limitation(self):
        """Test filename length limitation."""
        # Test normal length preservation
        normal_name = "a" * 100 + ".txt"
        assert sanitize_filename(normal_name) == normal_name
        
        # Test length truncation
        long_name = "a" * 300 + ".txt"
        result = sanitize_filename(long_name)
        assert len(result) <= 255
        assert result.endswith(".txt")  # Extension should be preserved
        
        # Test very long extension handling
        very_long_ext = "a" * 250 + "." + "b" * 20
        result = sanitize_filename(very_long_ext)
        assert len(result) <= 255
    
    def test_preserve_valid_extensions(self):
        """Test that valid extensions are preserved during truncation."""
        long_name = "a" * 300 + ".pdf"
        result = sanitize_filename(long_name)
        assert result.endswith(".pdf")
        assert len(result) <= 255
    
    def test_unicode_handling(self):
        """Test handling of Unicode characters."""
        unicode_names = [
            "файл.txt",  # Cyrillic
            "文件.txt",   # Chinese
            "ファイル.txt", # Japanese
            "café.txt",   # Accented characters
            "🎉test.txt"  # Emoji
        ]
        
        for unicode_name in unicode_names:
            result = sanitize_filename(unicode_name)
            # Should not crash and should return a string
            assert isinstance(result, str)
            assert len(result) > 0
    
    def test_already_safe_filename(self):
        """Test that already safe filenames are preserved."""
        safe_names = [
            "document.pdf",
            "image_001.jpg",
            "data-file.csv",
            "README.md",
            "file123.txt"
        ]
        
        for safe_name in safe_names:
            result = sanitize_filename(safe_name)
            assert result == safe_name


class TestErrorHandling:
    """Test error handling and edge cases."""
    
    def test_validation_error_properties(self):
        """Test ValidationError properties."""
        try:
            validate_file_path("con.txt")
        except ValidationError as e:
            assert hasattr(e, 'field')
            assert hasattr(e, 'value')
            assert e.field == "file_path"
            assert e.value == "con.txt"
    
    def test_complex_attack_vectors(self):
        """Test complex attack vectors combining multiple techniques."""
        complex_attacks = [
            # URL encoding + directory traversal
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            # Double encoding
            "%252e%252e%252f%252e%252e%252fpasswd",
            # Mixed case with traversal
            "..%2F..%2Fetc%2Fpasswd",
            # Null byte + traversal
            "../../../etc/passwd\x00.txt",
            # Windows path with forward slashes
            "..\\..\\..\\windows\\system32\\config\\sam",
        ]
        
        for attack in complex_attacks:
            with pytest.raises(ValidationError):
                validate_file_path(attack, allow_absolute=True)
    
    def test_performance_with_long_paths(self):
        """Test performance with very long paths."""
        # Create a very long but safe path
        long_safe_path = "a" * 1000 + ".txt"
        result = sanitize_filename(long_safe_path)
        assert len(result) <= 255
        
        # Very long unsafe path should still be caught
        long_unsafe_path = "../" * 500 + "etc/passwd"
        with pytest.raises(ValidationError):
            validate_file_path(long_unsafe_path)


class TestIntegrationScenarios:
    """Test realistic integration scenarios."""
    
    def test_file_upload_scenario(self):
        """Test typical file upload validation scenario."""
        with tempfile.TemporaryDirectory() as upload_dir:
            # Simulate various file upload attempts
            test_uploads = [
                ("document.pdf", True),
                ("../../../etc/passwd", False),
                ("normal file.txt", True),  # Space in name
                ("con.txt", False),  # Reserved name
                ("file\x00.txt", False),  # Null byte
                (".hidden_file", True),  # Hidden file (allowed but warned)
            ]
            
            for filename, should_pass in test_uploads:
                if should_pass:
                    try:
                        result = validate_file_path(
                            filename,
                            base_directory=upload_dir,
                            allow_absolute=False,
                            allow_symlinks=False
                        )
                        assert isinstance(result, Path)
                    except ValidationError:
                        pytest.fail(f"Expected {filename} to pass validation")
                else:
                    with pytest.raises(ValidationError):
                        validate_file_path(
                            filename,
                            base_directory=upload_dir,
                            allow_absolute=False,
                            allow_symlinks=False
                        )
    
    def test_log_file_scenario(self):
        """Test log file path validation scenario."""
        with tempfile.TemporaryDirectory() as log_dir:
            # Valid log file paths
            valid_logs = [
                "application.log",
                "error-2023.log",
                "debug_trace.txt",
                "access.log.1"
            ]
            
            for log_file in valid_logs:
                result = validate_file_path(
                    log_file,
                    base_directory=log_dir,
                    allow_absolute=False
                )
                assert isinstance(result, Path)
    
    def test_config_file_scenario(self):
        """Test configuration file validation."""
        # Test sanitization of config filenames from user input
        user_inputs = [
            ("my-config.json", "my-config.json"),
            ("config file.yaml", "config file.yaml"),
            ("../../../etc/passwd.conf", "passwd.conf"),
            ("config|dangerous.ini", "config_dangerous.ini"),
            ("", "unnamed_file")
        ]
        
        for user_input, expected_safe in user_inputs:
            safe_filename = sanitize_filename(user_input)
            # The result should be safe and reasonable
            assert safe_filename == expected_safe or safe_filename == "unnamed_file"
            # And should pass basic validation
            assert is_safe_path(safe_filename)


if __name__ == "__main__":
    pytest.main([__file__])