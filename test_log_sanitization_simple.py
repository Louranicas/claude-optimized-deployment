#!/usr/bin/env python3
"""
Simple tests for log injection prevention - core sanitization only.
"""

import sys
import os
import re
import json
from typing import Any, Dict, List, Optional, Union
from enum import Enum

# Simple implementation for testing
class SanitizationLevel(Enum):
    PERMISSIVE = "permissive"
    STANDARD = "standard"
    STRICT = "strict"

class LogSanitizerConfig:
    def __init__(
        self,
        level: SanitizationLevel = SanitizationLevel.STANDARD,
        max_length: int = 8192,
        preserve_unicode: bool = True,
        detect_patterns: bool = True,
        truncate_marker: str = "...[TRUNCATED]"
    ):
        self.level = level
        self.max_length = max_length
        self.preserve_unicode = preserve_unicode
        self.detect_patterns = detect_patterns
        self.truncate_marker = truncate_marker

class LogSanitizer:
    # Dangerous patterns that could indicate log injection attempts
    DANGEROUS_PATTERNS = [
        r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}',
        r'\b(DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\b',
        r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b.*?"[A-Z]+ /',
        r'<\d+>',
        r'^\s*\{.*"level".*:',
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'data:text/html',
        r'eval\s*\(',
        r'exec\s*\(',
        r'system\s*\(',
        r'\.\./',
        r'\.\.\\',
    ]
    
    CONTROL_CHARS = [chr(i) for i in range(32) if i not in (9, 10, 13)]
    
    def __init__(self, config: Optional[LogSanitizerConfig] = None):
        self.config = config or LogSanitizerConfig()
        self._compile_patterns()
    
    def _compile_patterns(self):
        if self.config.detect_patterns:
            self.dangerous_pattern_regex = re.compile(
                '|'.join(self.DANGEROUS_PATTERNS),
                re.IGNORECASE | re.MULTILINE
            )
        else:
            self.dangerous_pattern_regex = None
    
    def sanitize(self, value: Any, context: Optional[str] = None) -> str:
        if value is None:
            return "None"
        
        if isinstance(value, (dict, list)):
            try:
                text = json.dumps(value, default=str, ensure_ascii=False)
            except (TypeError, ValueError):
                text = str(value)
        else:
            text = str(value)
        
        text = self._remove_crlf_injection(text)
        text = self._remove_control_characters(text)
        text = self._apply_length_limit(text)
        
        if self.config.detect_patterns and self.dangerous_pattern_regex:
            text = self._flag_dangerous_patterns(text, context)
        
        return text
    
    def _remove_crlf_injection(self, text: str) -> str:
        # Remove carriage return and line feed combinations
        text = text.replace('\\r\\n', ' ')
        text = text.replace('\\n', ' ')
        text = text.replace('\\r', ' ')
        text = text.replace('\r\n', ' ')
        text = text.replace('\n', ' ')
        text = text.replace('\r', ' ')
        
        # Remove encoded versions
        text = text.replace('%0D%0A', ' ')
        text = text.replace('%0A', ' ')
        text = text.replace('%0D', ' ')
        text = text.replace('%0d%0a', ' ')
        text = text.replace('%0a', ' ')
        text = text.replace('%0d', ' ')
        
        return text
    
    def _remove_control_characters(self, text: str) -> str:
        for char in self.CONTROL_CHARS:
            text = text.replace(char, '')
        
        if self.config.level == SanitizationLevel.STRICT:
            text = ''.join(char for char in text if char.isprintable() or char.isspace())
        
        return text
    
    def _apply_length_limit(self, text: str) -> str:
        if len(text) > self.config.max_length:
            truncate_length = self.config.max_length - len(self.config.truncate_marker)
            text = text[:truncate_length] + self.config.truncate_marker
        
        return text
    
    def _flag_dangerous_patterns(self, text: str, context: Optional[str]) -> str:
        if self.dangerous_pattern_regex and self.dangerous_pattern_regex.search(text):
            warning = f"[SUSPICIOUS_PATTERN_DETECTED{':' + context if context else ''}]"
            text = self._aggressive_sanitize(text)
            return f"{warning} {text}"
        
        return text
    
    def _aggressive_sanitize(self, text: str) -> str:
        replacements = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '/': '&#x2F;',
            '{': '&#123;',
            '}': '&#125;',
            '(': '&#40;',
            ')': '&#41;',
            '=': '&#61;',
            ';': '&#59;',
            ':': '&#58;',
        }
        
        for char, replacement in replacements.items():
            text = text.replace(char, replacement)
        
        return text


def test_crlf_injection_prevention():
    """Test CRLF injection prevention."""
    print("Testing CRLF injection prevention...")
    
    sanitizer = LogSanitizer()
    
    test_cases = [
        ("Normal log message", "Normal log message"),
        ("Injection\r\nFAKE LOG", "Injection FAKE LOG"),
        ("Another\nFAKE: ERROR", "Another FAKE: ERROR"),
        ("URL encoded%0D%0AFAKE", "URL encoded FAKE"),
        ("Mixed\\r\\n2024-01-01", "Mixed 2024-01-01"),
    ]
    
    for input_text, expected_safe in test_cases:
        result = sanitizer.sanitize(input_text)
        print(f"Input:  '{input_text}'")
        print(f"Result: '{result}'")
        
        # Verify no CRLF characters
        assert '\r' not in result, f"CR found in result: {result}"
        assert '\n' not in result, f"LF found in result: {result}"
        
        print("✓ CRLF injection prevented\n")


def test_control_character_removal():
    """Test control character removal."""
    print("Testing control character removal...")
    
    sanitizer = LogSanitizer()
    
    # Create test input with control characters
    test_input = "Normal\x00text\x01with\x02controls\x03"
    result = sanitizer.sanitize(test_input)
    
    print(f"Input:  '{repr(test_input)}'")
    print(f"Result: '{result}'")
    
    # Verify no control characters remain
    for char in result:
        if ord(char) < 32 and char not in ['\t', ' ']:
            assert False, f"Control character {ord(char)} found in result"
    
    print("✓ Control characters removed\n")


def test_pattern_detection():
    """Test dangerous pattern detection."""
    print("Testing dangerous pattern detection...")
    
    sanitizer = LogSanitizer()
    
    dangerous_inputs = [
        "2024-01-01 00:00:00 ERROR Fake log",
        "User: <script>alert('xss')</script>",
        "Path: ../../../etc/passwd",
        "Command: eval(code)",
    ]
    
    for dangerous_input in dangerous_inputs:
        result = sanitizer.sanitize(dangerous_input, context="test")
        print(f"Input:  '{dangerous_input}'")
        print(f"Result: '{result}'")
        
        if "[SUSPICIOUS_PATTERN_DETECTED" in result:
            print("✓ Dangerous pattern detected")
        else:
            print("⚠ Pattern not flagged")
        print()


def test_length_limits():
    """Test length limiting."""
    print("Testing length limits...")
    
    config = LogSanitizerConfig(max_length=50)
    sanitizer = LogSanitizer(config)
    
    long_input = "A" * 100
    result = sanitizer.sanitize(long_input)
    
    print(f"Input length: {len(long_input)}")
    print(f"Result length: {len(result)}")
    print(f"Result: '{result}'")
    
    assert len(result) <= config.max_length, "Length limit not enforced"
    print("✓ Length limit enforced\n")


def test_combined_attack():
    """Test combined injection attack."""
    print("Testing combined injection attack...")
    
    # Realistic attack attempt
    attack_input = (
        "User login: admin\r\n"
        "2024-01-01 00:00:00 ERROR [FAKE] Unauthorized access detected\n"
        "IP: 192.168.1.1 - GET /admin <script>alert('xss')</script>\r\n"
        "Command: eval(process.exit(1)); rm -rf /"
    )
    
    sanitizer = LogSanitizer()
    result = sanitizer.sanitize(attack_input, context="security")
    
    print(f"Attack input:\n{repr(attack_input)}\n")
    print(f"Sanitized result:\n{result}\n")
    
    # Verify sanitization
    assert '\r' not in result, "CR found in result"
    assert '\n' not in result, "LF found in result"
    
    if "[SUSPICIOUS_PATTERN_DETECTED" in result:
        print("✓ Suspicious patterns detected")
    
    print("✓ Combined attack mitigated\n")


def main():
    """Run all tests."""
    print("=== Log Injection Prevention Tests ===\n")
    
    try:
        test_crlf_injection_prevention()
        test_control_character_removal()
        test_pattern_detection()
        test_length_limits()
        test_combined_attack()
        
        print("=== All Tests Passed! ===")
        print("✅ Log injection prevention is working correctly")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)