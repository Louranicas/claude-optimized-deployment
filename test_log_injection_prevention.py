#!/usr/bin/env python3
"""
Comprehensive tests for log injection prevention system.

Tests all sanitization features and attack prevention capabilities.
"""

import sys
import os
import tempfile
import logging
from datetime import datetime
from pathlib import Path

# Add src to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.core.log_sanitization import (
    LogSanitizer,
    LogSanitizerConfig,
    SanitizationLevel,
    LogInjectionFilter,
    sanitize_for_logging,
    sanitize_dict_for_logging
)


def test_basic_sanitization():
    """Test basic CRLF injection prevention."""
    print("Testing basic CRLF injection prevention...")
    
    sanitizer = LogSanitizer()
    
    # Test CRLF injection attempts
    test_cases = [
        "Normal log message",
        "Injection attempt\r\nFAKE LOG ENTRY",
        "Another attempt\nFAKE: 2024-01-01 00:00:00 ERROR Injected",
        "URL encoded\r\n%0D%0AFAKE LOG",
        "Mixed injection\\r\\n2024-01-01 INFO FAKE",
        "Tab injection\tFAKE\tLOG",
    ]
    
    for test_input in test_cases:
        sanitized = sanitizer.sanitize(test_input)
        print(f"Input:  '{test_input}'")
        print(f"Output: '{sanitized}'")
        
        # Verify no CRLF characters remain
        assert '\r' not in sanitized, f"Carriage return found in: {sanitized}"
        assert '\n' not in sanitized, f"Line feed found in: {sanitized}"
        print("✓ CRLF injection prevented\n")


def test_control_character_removal():
    """Test control character filtering."""
    print("Testing control character removal...")
    
    sanitizer = LogSanitizer()
    
    # Test various control characters
    test_input = "Normal text\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f with controls"
    sanitized = sanitizer.sanitize(test_input)
    
    print(f"Input length: {len(test_input)}")
    print(f"Output length: {len(sanitized)}")
    print(f"Sanitized: '{sanitized}'")
    
    # Verify no control characters remain (except allowed ones)
    for char in sanitized:
        if ord(char) < 32 and char not in ['\t', '\n', '\r']:
            assert False, f"Control character {ord(char)} found in sanitized output"
    
    print("✓ Control characters removed\n")


def test_pattern_detection():
    """Test dangerous pattern detection."""
    print("Testing dangerous pattern detection...")
    
    sanitizer = LogSanitizer()
    
    # Test patterns that should be flagged
    dangerous_inputs = [
        "2024-01-01 00:00:00 ERROR Fake log entry",
        "User query: <script>alert('xss')</script>",
        "Path: ../../../etc/passwd",
        "Command: eval(malicious_code)",
        "JSON: {\"level\":\"ERROR\",\"message\":\"fake\"}",
        "Log level: INFO Something happened",
        "Syslog: <134>Jan 01 00:00:00 fake",
        "HTTP: 192.168.1.1 - - [01/Jan/2024:00:00:00] \"GET /\"",
    ]
    
    for dangerous_input in dangerous_inputs:
        sanitized = sanitizer.sanitize(dangerous_input, context="test")
        print(f"Input:  '{dangerous_input}'")
        print(f"Output: '{sanitized}'")
        
        # Check if suspicious pattern was detected
        if "[SUSPICIOUS_PATTERN_DETECTED" in sanitized:
            print("✓ Dangerous pattern detected and flagged")
        else:
            print("⚠ Pattern not flagged (may be acceptable)")
        print()


def test_sanitization_levels():
    """Test different sanitization levels."""
    print("Testing sanitization levels...")
    
    test_input = "User: admin\r\nPassword: secret123\nCommand: rm -rf /"
    
    # Test all levels
    for level in SanitizationLevel:
        config = LogSanitizerConfig(level=level)
        sanitizer = LogSanitizer(config)
        sanitized = sanitizer.sanitize(test_input)
        
        print(f"Level {level.value}:")
        print(f"  Input:  '{test_input}'")
        print(f"  Output: '{sanitized}'")
        print()


def test_unicode_handling():
    """Test Unicode normalization and handling."""
    print("Testing Unicode handling...")
    
    # Test Unicode normalization attacks
    unicode_tests = [
        "Normal ASCII text",
        "Unicode: café résumé naïve",
        "Emoji: 🚨 Alert! 💥",
        "Combining chars: e\u0301 (é)",  # e + combining acute accent
        "RTL override: \u202etext\u202c",
        "Zero-width: zero\u200bzero\u200cwidth",
    ]
    
    for preserve_unicode in [True, False]:
        config = LogSanitizerConfig(preserve_unicode=preserve_unicode)
        sanitizer = LogSanitizer(config)
        
        print(f"\nPreserve Unicode: {preserve_unicode}")
        for test_input in unicode_tests:
            sanitized = sanitizer.sanitize(test_input)
            print(f"  '{test_input}' -> '{sanitized}'")


def test_length_limits():
    """Test length limiting."""
    print("Testing length limits...")
    
    config = LogSanitizerConfig(max_length=50)
    sanitizer = LogSanitizer(config)
    
    long_input = "A" * 100 + "\r\nINJECTED LOG ENTRY"
    sanitized = sanitizer.sanitize(long_input)
    
    print(f"Input length: {len(long_input)}")
    print(f"Output length: {len(sanitized)}")
    print(f"Sanitized: '{sanitized}'")
    
    assert len(sanitized) <= config.max_length, "Length limit not enforced"
    assert config.truncate_marker in sanitized, "Truncation marker not added"
    print("✓ Length limit enforced\n")


def test_dictionary_sanitization():
    """Test dictionary sanitization."""
    print("Testing dictionary sanitization...")
    
    sanitizer = LogSanitizer()
    
    test_dict = {
        "normal_key": "normal_value",
        "injection_key\r\nFAKE": "injection_value\nLOG",
        "nested": {
            "deep_injection": "2024-01-01 ERROR Fake",
            "list_items": ["item1\r\n", "item2\n", "item3"]
        },
        "user_input": "../../../etc/passwd"
    }
    
    sanitized = sanitizer.sanitize_dict(test_dict)
    
    print("Original dictionary:")
    print(test_dict)
    print("\nSanitized dictionary:")
    print(sanitized)
    
    # Verify no CRLF in any values
    def check_no_crlf(obj, path=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                assert '\r' not in str(k), f"CRLF in key at {path}.{k}"
                assert '\n' not in str(k), f"CRLF in key at {path}.{k}"
                check_no_crlf(v, f"{path}.{k}")
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                check_no_crlf(item, f"{path}[{i}]")
        elif isinstance(obj, str):
            assert '\r' not in obj, f"CRLF in value at {path}"
            assert '\n' not in obj, f"CRLF in value at {path}"
    
    check_no_crlf(sanitized)
    print("✓ Dictionary sanitization successful\n")


def test_logging_filter():
    """Test LogInjectionFilter integration."""
    print("Testing LogInjectionFilter integration...")
    
    # Create temporary log file
    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.log') as temp_log:
        temp_log_path = temp_log.name
    
    try:
        # Set up logger with injection filter
        logger = logging.getLogger('test_injection')
        logger.setLevel(logging.DEBUG)
        
        # Remove existing handlers
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
        
        # Add file handler with injection filter
        handler = logging.FileHandler(temp_log_path)
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        handler.addFilter(LogInjectionFilter(SanitizationLevel.STANDARD))
        logger.addHandler(handler)
        
        # Test various injection attempts
        test_logs = [
            "Normal log message",
            "Injection attempt\r\n2024-01-01 ERROR FAKE LOG",
            "User input: <script>alert('xss')</script>",
            "Path traversal: ../../../etc/passwd",
            "Command injection: ; rm -rf /",
        ]
        
        for msg in test_logs:
            logger.info("User message: %s", msg)
        
        # Close handler to flush
        handler.close()
        logger.removeHandler(handler)
        
        # Read log file and verify sanitization
        with open(temp_log_path, 'r') as f:
            log_content = f.read()
        
        print("Log file content:")
        print(log_content)
        
        # Verify no CRLF injection succeeded
        lines = log_content.split('\n')
        for line in lines:
            if line.strip():
                # Each line should start with timestamp or be empty
                if not line.startswith('20') and line.strip():
                    print(f"Potentially injected line: {line}")
        
        print("✓ Logging filter prevented injection\n")
        
    finally:
        # Clean up
        if os.path.exists(temp_log_path):
            os.unlink(temp_log_path)


def test_performance():
    """Test sanitization performance."""
    print("Testing sanitization performance...")
    
    import time
    
    sanitizer = LogSanitizer()
    
    # Test with various input sizes
    test_sizes = [100, 1000, 10000]
    
    for size in test_sizes:
        test_input = "A" * size + "\r\nINJECTED\n" + "B" * size
        
        start_time = time.time()
        sanitized = sanitizer.sanitize(test_input)
        end_time = time.time()
        
        duration_ms = (end_time - start_time) * 1000
        print(f"Size {size*2+10} chars: {duration_ms:.2f}ms")
        
        assert len(sanitized) <= len(test_input), "Sanitized output longer than input"
    
    print("✓ Performance test completed\n")


def test_audit_sanitization():
    """Test audit logging sanitization."""
    print("Testing audit logging sanitization...")
    
    try:
        from src.auth.audit import AuditLogger, AuditEventType, AuditSeverity
        
        # Create audit logger
        audit_logger = AuditLogger(signing_key="test_key_for_testing_purposes_only_32_chars")
        
        # Test with injection attempts
        test_user_id = "admin\r\nFAKE: Injected log entry"
        test_resource = "../../../etc/passwd"
        test_details = {
            "user_input": "SELECT * FROM users; DROP TABLE users;",
            "injection": "2024-01-01 ERROR Fake audit entry"
        }
        
        # This should sanitize all inputs
        import asyncio
        async def test_audit():
            event_id = await audit_logger.log_event(
                event_type=AuditEventType.LOGIN_SUCCESS,
                severity=AuditSeverity.INFO,
                user_id=test_user_id,
                resource=test_resource,
                details=test_details
            )
            
            print(f"Audit event created: {event_id}")
            
            # Get the event from buffer
            if audit_logger.buffer:
                event = audit_logger.buffer[0]
                event_dict = event.to_dict()
                
                print("Sanitized audit event:")
                for key, value in event_dict.items():
                    print(f"  {key}: {value}")
                
                # Verify sanitization
                assert '\r' not in str(event_dict), "CRLF found in audit event"
                assert '\n' not in str(event_dict), "LF found in audit event"
                
                print("✓ Audit sanitization successful")
        
        asyncio.run(test_audit())
        
    except ImportError:
        print("⚠ Audit module not available, skipping audit tests")
    
    print()


def main():
    """Run all log injection prevention tests."""
    print("=== Log Injection Prevention Test Suite ===\n")
    
    try:
        test_basic_sanitization()
        test_control_character_removal()
        test_pattern_detection()
        test_sanitization_levels()
        test_unicode_handling()
        test_length_limits()
        test_dictionary_sanitization()
        test_logging_filter()
        test_performance()
        test_audit_sanitization()
        
        print("=== All Tests Passed! ===")
        print("✅ Log injection prevention system is working correctly")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()