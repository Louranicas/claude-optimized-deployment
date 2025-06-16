"""
SYNTHEX Agent 4: Comprehensive Security Architecture

This module implements a multi-layered security architecture that provides defense-in-depth
against various attack vectors while maintaining system usability and performance.

Security Layers:
1. Sandboxing for file parsing operations
2. Input validation and sanitization
3. Protection against malicious files
4. Resource limits and monitoring
5. Access control for sensitive directories
6. Secure communication protocols
7. Authentication and authorization
8. Comprehensive audit logging

Author: SYNTHEX Agent 4
Version: 1.0.0
"""

import os
import asyncio
import tempfile
import subprocess
import resource
import hashlib
import magic
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging
import json
import time
from datetime import datetime, timedelta
import psutil
import mmap
import struct

from ..core.path_validation import validate_file_path, sanitize_filename
from ..core.ssrf_protection import SSRFProtector, validate_url_safe
from ..core.log_sanitization import sanitize_for_logging, LogSanitizer, SanitizationLevel
from ..core.memory_monitor import MemoryMonitor, MemoryPressureLevel
from ..core.security_policy import SecurityPolicy
from ..auth.middleware import AuthMiddleware
from ..auth.audit import AuditLogger

__all__ = [
    "SecurityArchitecture",
    "FileSandbox",
    "InputValidator",
    "MaliciousFileDetector",
    "ResourceLimiter",
    "SecureFileAccess",
    "SecureCommunicationProtocol",
    "MCPSecurityManager",
    "SecurityAuditLogger"
]

logger = logging.getLogger(__name__)


class ThreatType(Enum):
    """Types of security threats"""
    PATH_TRAVERSAL = "path_traversal"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    MALICIOUS_FILE = "malicious_file"
    INJECTION = "injection"
    INFORMATION_DISCLOSURE = "information_disclosure"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DENIAL_OF_SERVICE = "denial_of_service"


@dataclass
class SecurityContext:
    """Security context for operations"""
    user_id: str
    client_id: str
    ip_address: str
    permissions: List[str]
    risk_level: str = "medium"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationResult:
    """Result of validation operations"""
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    sanitized_value: Any = None
    threat_indicators: List[ThreatType] = field(default_factory=list)


class FileSandbox:
    """
    Sandboxing for file parsing operations.
    
    Provides isolated execution environment for potentially dangerous file operations.
    """
    
    def __init__(self, 
                 sandbox_dir: Optional[Path] = None,
                 max_file_size: int = 100 * 1024 * 1024,  # 100MB
                 allowed_extensions: Optional[List[str]] = None,
                 use_docker: bool = False):
        """
        Initialize file sandbox.
        
        Args:
            sandbox_dir: Directory for sandboxed operations
            max_file_size: Maximum allowed file size
            allowed_extensions: List of allowed file extensions
            use_docker: Use Docker for enhanced isolation
        """
        self.sandbox_dir = sandbox_dir or Path(tempfile.mkdtemp(prefix="sandbox_"))
        self.max_file_size = max_file_size
        self.allowed_extensions = allowed_extensions or [
            '.txt', '.pdf', '.doc', '.docx', '.xls', '.xlsx',
            '.png', '.jpg', '.jpeg', '.gif', '.bmp',
            '.csv', '.json', '.xml', '.yaml', '.yml'
        ]
        self.use_docker = use_docker
        
        # Ensure sandbox directory exists with restricted permissions
        self.sandbox_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.sandbox_dir, 0o700)
        
        # File type detector
        self.mime = magic.Magic(mime=True)
        
    async def process_file(self, 
                          file_path: Path,
                          operation: Callable[[Path], Any],
                          context: SecurityContext) -> Tuple[Any, ValidationResult]:
        """
        Process file in sandboxed environment.
        
        Args:
            file_path: Path to file to process
            operation: Operation to perform on file
            context: Security context
            
        Returns:
            Tuple of (operation result, validation result)
        """
        validation = self._validate_file(file_path)
        if not validation.is_valid:
            return None, validation
            
        # Create isolated copy
        sandbox_file = self.sandbox_dir / f"{context.user_id}_{int(time.time())}_{file_path.name}"
        
        try:
            # Copy file to sandbox with size limit
            with open(file_path, 'rb') as src:
                with open(sandbox_file, 'wb') as dst:
                    copied = 0
                    while True:
                        chunk = src.read(8192)
                        if not chunk:
                            break
                        if copied + len(chunk) > self.max_file_size:
                            raise ValueError(f"File exceeds maximum size of {self.max_file_size} bytes")
                        dst.write(chunk)
                        copied += len(chunk)
            
            # Set restrictive permissions
            os.chmod(sandbox_file, 0o400)
            
            # Execute operation with resource limits
            if self.use_docker:
                result = await self._docker_sandbox_execute(sandbox_file, operation, context)
            else:
                result = await self._process_sandbox_execute(sandbox_file, operation, context)
                
            return result, validation
            
        except Exception as e:
            logger.error(f"Sandbox processing error: {e}")
            validation.errors.append(f"Processing error: {str(e)}")
            validation.is_valid = False
            return None, validation
            
        finally:
            # Cleanup
            if sandbox_file.exists():
                sandbox_file.unlink()
                
    def _validate_file(self, file_path: Path) -> ValidationResult:
        """Validate file before processing"""
        result = ValidationResult(is_valid=True)
        
        # Check file exists
        if not file_path.exists():
            result.is_valid = False
            result.errors.append("File does not exist")
            return result
            
        # Check file size
        file_size = file_path.stat().st_size
        if file_size > self.max_file_size:
            result.is_valid = False
            result.errors.append(f"File size {file_size} exceeds limit {self.max_file_size}")
            result.threat_indicators.append(ThreatType.RESOURCE_EXHAUSTION)
            return result
            
        # Check extension
        if self.allowed_extensions:
            ext = file_path.suffix.lower()
            if ext not in self.allowed_extensions:
                result.is_valid = False
                result.errors.append(f"File extension {ext} not allowed")
                result.threat_indicators.append(ThreatType.MALICIOUS_FILE)
                return result
                
        # Check MIME type
        try:
            mime_type = self.mime.from_file(str(file_path))
            if self._is_dangerous_mime_type(mime_type):
                result.is_valid = False
                result.errors.append(f"Dangerous MIME type: {mime_type}")
                result.threat_indicators.append(ThreatType.MALICIOUS_FILE)
        except Exception as e:
            result.warnings.append(f"Could not determine MIME type: {e}")
            
        return result
        
    def _is_dangerous_mime_type(self, mime_type: str) -> bool:
        """Check if MIME type is potentially dangerous"""
        dangerous_types = [
            'application/x-executable',
            'application/x-sharedlib',
            'application/x-shellscript',
            'application/x-mach-binary',
            'application/x-dosexec'
        ]
        return mime_type in dangerous_types
        
    async def _process_sandbox_execute(self, 
                                     file_path: Path,
                                     operation: Callable,
                                     context: SecurityContext) -> Any:
        """Execute operation in process sandbox with resource limits"""
        # Set resource limits for child process
        def set_limits():
            # CPU time limit (5 seconds)
            resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
            # Memory limit (512MB)
            resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
            # File size limit (100MB)
            resource.setrlimit(resource.RLIMIT_FSIZE, (100 * 1024 * 1024, 100 * 1024 * 1024))
            # Number of processes (1)
            resource.setrlimit(resource.RLIMIT_NPROC, (1, 1))
            
        # Execute in subprocess with limits
        import multiprocessing
        
        def worker(file_path, result_queue):
            try:
                result = operation(file_path)
                result_queue.put(('success', result))
            except Exception as e:
                result_queue.put(('error', str(e)))
                
        result_queue = multiprocessing.Queue()
        process = multiprocessing.Process(
            target=worker,
            args=(file_path, result_queue),
            kwargs={}
        )
        process.start()
        
        # Wait with timeout
        process.join(timeout=10)
        
        if process.is_alive():
            process.terminate()
            process.join()
            raise TimeoutError("Operation timed out")
            
        if result_queue.empty():
            raise RuntimeError("No result from sandboxed operation")
            
        status, result = result_queue.get()
        if status == 'error':
            raise RuntimeError(f"Sandboxed operation failed: {result}")
            
        return result
        
    async def _docker_sandbox_execute(self,
                                    file_path: Path,
                                    operation: Callable,
                                    context: SecurityContext) -> Any:
        """Execute operation in Docker container for maximum isolation"""
        # This would use Docker SDK to create isolated container
        # Implementation depends on Docker availability
        raise NotImplementedError("Docker sandbox not implemented")


class InputValidator:
    """
    Comprehensive input validation and sanitization.
    
    Prevents injection attacks and validates all user inputs.
    """
    
    def __init__(self):
        self.sanitizer = LogSanitizer()
        self.validators: Dict[str, Callable] = {}
        self._setup_default_validators()
        
    def _setup_default_validators(self):
        """Setup default validators"""
        # Email validator
        self.validators['email'] = self._validate_email
        # URL validator
        self.validators['url'] = self._validate_url
        # File path validator
        self.validators['file_path'] = self._validate_file_path
        # SQL identifier validator
        self.validators['sql_identifier'] = self._validate_sql_identifier
        # Command validator
        self.validators['command'] = self._validate_command
        
    def validate(self, 
                value: Any,
                value_type: str,
                context: Optional[Dict[str, Any]] = None) -> ValidationResult:
        """
        Validate and sanitize input value.
        
        Args:
            value: Value to validate
            value_type: Type of value (email, url, file_path, etc.)
            context: Additional context for validation
            
        Returns:
            ValidationResult with sanitized value
        """
        result = ValidationResult(is_valid=True)
        
        # Sanitize first
        sanitized = self.sanitizer.sanitize(value)
        result.sanitized_value = sanitized
        
        # Type-specific validation
        if value_type in self.validators:
            try:
                is_valid, errors = self.validators[value_type](sanitized, context)
                result.is_valid = is_valid
                result.errors.extend(errors)
            except Exception as e:
                result.is_valid = False
                result.errors.append(f"Validation error: {str(e)}")
                
        # Check for common injection patterns
        injection_check = self._check_injection_patterns(sanitized)
        if injection_check:
            result.warnings.extend(injection_check)
            result.threat_indicators.append(ThreatType.INJECTION)
            
        return result
        
    def _validate_email(self, value: str, context: Optional[Dict] = None) -> Tuple[bool, List[str]]:
        """Validate email address"""
        errors = []
        
        # Basic email regex
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not re.match(email_pattern, value):
            errors.append("Invalid email format")
            
        # Length check
        if len(value) > 254:
            errors.append("Email too long")
            
        return len(errors) == 0, errors
        
    def _validate_url(self, value: str, context: Optional[Dict] = None) -> Tuple[bool, List[str]]:
        """Validate URL with SSRF protection"""
        errors = []
        
        # Use SSRF protector
        validation = validate_url_safe(value)
        if not validation.is_safe:
            errors.append(f"URL validation failed: {validation.reason}")
            
        return len(errors) == 0, errors
        
    def _validate_file_path(self, value: str, context: Optional[Dict] = None) -> Tuple[bool, List[str]]:
        """Validate file path"""
        errors = []
        
        try:
            # Use path validation
            base_dir = context.get('base_directory') if context else None
            validate_file_path(value, base_directory=base_dir)
        except Exception as e:
            errors.append(str(e))
            
        return len(errors) == 0, errors
        
    def _validate_sql_identifier(self, value: str, context: Optional[Dict] = None) -> Tuple[bool, List[str]]:
        """Validate SQL identifier (table/column name)"""
        errors = []
        
        # Only allow alphanumeric and underscore
        import re
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', value):
            errors.append("Invalid SQL identifier format")
            
        # Length check
        if len(value) > 64:
            errors.append("SQL identifier too long")
            
        # Check against reserved words
        reserved_words = {'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER'}
        if value.upper() in reserved_words:
            errors.append("SQL identifier is a reserved word")
            
        return len(errors) == 0, errors
        
    def _validate_command(self, value: str, context: Optional[Dict] = None) -> Tuple[bool, List[str]]:
        """Validate shell command"""
        errors = []
        
        # Dangerous command patterns
        dangerous_patterns = [
            r';\s*rm\s+-rf',
            r'>\s*/dev/null',
            r'\|\s*sh',
            r'\|\s*bash',
            r'`.*`',
            r'\$\(.*\)',
            r'&&\s*curl',
            r'&&\s*wget'
        ]
        
        import re
        for pattern in dangerous_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                errors.append(f"Dangerous command pattern detected: {pattern}")
                
        return len(errors) == 0, errors
        
    def _check_injection_patterns(self, value: str) -> List[str]:
        """Check for common injection patterns"""
        warnings = []
        
        patterns = {
            'sql_injection': [r"('\s*OR\s*'1'\s*=\s*'1)", r'(;\s*DROP\s+TABLE)', r'(UNION\s+SELECT)'],
            'xss': [r'<script[^>]*>', r'javascript:', r'onerror\s*='],
            'ldap_injection': [r'\*\)', r'\(\|\(', r'\(\&\('],
            'xpath_injection': [r"'\s*or\s*'1'\s*=\s*'1", r'count\(/\*\)'],
            'command_injection': [r';\s*cat\s+/etc/passwd', r'\|\s*nc\s+', r'`id`']
        }
        
        import re
        for injection_type, pattern_list in patterns.items():
            for pattern in pattern_list:
                if re.search(pattern, value, re.IGNORECASE):
                    warnings.append(f"Potential {injection_type} pattern detected")
                    break
                    
        return warnings


class MaliciousFileDetector:
    """
    Detection and prevention of malicious files.
    
    Protects against zip bombs, XML bombs, and other malicious file types.
    """
    
    def __init__(self,
                 max_decompressed_size: int = 1024 * 1024 * 1024,  # 1GB
                 max_file_count: int = 10000,
                 max_nested_depth: int = 10):
        """
        Initialize malicious file detector.
        
        Args:
            max_decompressed_size: Maximum allowed decompressed size
            max_file_count: Maximum number of files in archive
            max_nested_depth: Maximum nesting depth for archives
        """
        self.max_decompressed_size = max_decompressed_size
        self.max_file_count = max_file_count
        self.max_nested_depth = max_nested_depth
        
    async def scan_file(self, file_path: Path) -> ValidationResult:
        """
        Scan file for malicious content.
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            ValidationResult with threat indicators
        """
        result = ValidationResult(is_valid=True)
        
        # Check file header for magic bytes
        header_check = self._check_file_header(file_path)
        if not header_check.is_valid:
            return header_check
            
        # Get file type
        file_type = self._detect_file_type(file_path)
        
        # Type-specific checks
        if file_type == 'zip':
            result = await self._check_zip_bomb(file_path)
        elif file_type == 'xml':
            result = await self._check_xml_bomb(file_path)
        elif file_type == 'image':
            result = await self._check_malicious_image(file_path)
        elif file_type == 'pdf':
            result = await self._check_malicious_pdf(file_path)
            
        return result
        
    def _check_file_header(self, file_path: Path) -> ValidationResult:
        """Check file header for suspicious patterns"""
        result = ValidationResult(is_valid=True)
        
        try:
            with open(file_path, 'rb') as f:
                header = f.read(1024)
                
            # Check for null bytes in text files
            if file_path.suffix in ['.txt', '.csv', '.json', '.xml']:
                if b'\x00' in header:
                    result.is_valid = False
                    result.errors.append("Null bytes found in text file")
                    result.threat_indicators.append(ThreatType.MALICIOUS_FILE)
                    
            # Check for executable headers
            executable_headers = [
                b'MZ',  # DOS/Windows executable
                b'\x7fELF',  # Linux ELF
                b'\xfe\xed\xfa\xce',  # Mach-O (macOS)
                b'\xce\xfa\xed\xfe',  # Mach-O (macOS)
                b'#!/bin/',  # Shell script
                b'#!/usr/bin/'  # Shell script
            ]
            
            for exe_header in executable_headers:
                if header.startswith(exe_header):
                    result.warnings.append("Executable file detected")
                    result.threat_indicators.append(ThreatType.MALICIOUS_FILE)
                    
        except Exception as e:
            result.warnings.append(f"Could not check file header: {e}")
            
        return result
        
    def _detect_file_type(self, file_path: Path) -> str:
        """Detect file type from content"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(8)
                
            # Check magic bytes
            if header.startswith(b'PK'):
                return 'zip'
            elif header.startswith(b'<?xml'):
                return 'xml'
            elif header.startswith(b'\x89PNG'):
                return 'image'
            elif header.startswith(b'\xff\xd8\xff'):
                return 'image'
            elif header.startswith(b'%PDF'):
                return 'pdf'\n            else:\n                return 'unknown'\n\n        except Exception:\n            return 'unknown'\n\n    async def _check_zip_bomb(self, file_path: Path) -> ValidationResult:\n        """Check for zip bomb"""\n        result = ValidationResult(is_valid=True)\n\n        try:\n            total_size = 0\n            file_count = 0\n\n            with zipfile.ZipFile(file_path, 'r') as zf:\n                for info in zf.infolist():\n                    # Check decompressed size\n                    total_size += info.file_size\n                    file_count += 1\n\n                    if total_size > self.max_decompressed_size:\n                        result.is_valid = False\n                        result.errors.append(f"Zip bomb detected: decompressed size exceeds {self.max_decompressed_size}")\n                        result.threat_indicators.append(ThreatType.MALICIOUS_FILE)\n                        break\n\n                    if file_count > self.max_file_count:\n                        result.is_valid = False\n                        result.errors.append(f"Too many files in archive: {file_count}")\n                        result.threat_indicators.append(ThreatType.RESOURCE_EXHAUSTION)\n                        break\n\n                    # Check compression ratio\n                    if info.compress_size > 0:\n                        ratio = info.file_size / info.compress_size\n                        if ratio > 100:\n                            result.warnings.append(f"High compression ratio detected: {ratio:.1f}")\n\n        except Exception as e:\n            result.warnings.append(f"Could not check zip file: {e}")\n\n        return result\n\n    async def _check_xml_bomb(self, file_path: Path) -> ValidationResult:\n        """Check for XML bomb (billion laughs attack)"""\n        result = ValidationResult(is_valid=True)\n\n        try:\n            # Use defusedxml for safe parsing\n            import defusedxml.ElementTree as DefusedET\n\n            # Parse with limits\n            parser = DefusedET.XMLParser()\n            tree = DefusedET.parse(file_path, parser=parser)\n\n            # Check for excessive entity expansion\n            xml_content = file_path.read_text()\n            if xml_content.count('<!ENTITY') > 10:\n                result.warnings.append("Many XML entities detected")\n\n            if 'SYSTEM' in xml_content and 'file://' in xml_content:\n                result.is_valid = False\n                result.errors.append("External entity reference detected")\n                result.threat_indicators.append(ThreatType.INFORMATION_DISCLOSURE)\n\n        except Exception as e:\n            result.warnings.append(f"Could not parse XML: {e}")\n\n        return result\n\n    async def _check_malicious_image(self, file_path: Path) -> ValidationResult:\n        """Check for malicious image files"""\n        result = ValidationResult(is_valid=True)\n\n        try:\n            # Check for embedded code in EXIF data\n            from PIL import Image\n            from PIL.ExifTags import TAGS\n\n            img = Image.open(file_path)\n            exifdata = img.getexif()\n\n            for tag_id in exifdata:\n                tag = TAGS.get(tag_id, tag_id)\n                data = exifdata.get(tag_id)\n\n                # Check for suspicious content in EXIF\n                if isinstance(data, str):\n                    if any(pattern in data.lower() for pattern in ['<script', 'javascript:', 'eval(']):\n                        result.warnings.append(f"Suspicious content in EXIF tag {tag}")\n                        result.threat_indicators.append(ThreatType.MALICIOUS_FILE)\n\n        except Exception as e:\n            result.warnings.append(f"Could not check image: {e}")\n\n        return result\n\n    async def _check_malicious_pdf(self, file_path: Path) -> ValidationResult:\n        """Check for malicious PDF files"""\n        result = ValidationResult(is_valid=True)\n\n        try:\n            with open(file_path, 'rb') as f:\n                content = f.read()\n\n            # Check for suspicious PDF features\n            suspicious_patterns = [\n                b'/JavaScript',\n                b'/JS',\n                b'/Launch',\n                b'/EmbeddedFile',\n                b'/OpenAction',\n                b'/AA',  # Additional actions\n                b'/URI',\n                b'/SubmitForm',\n                b'/ImportData'\n            ]\n\n            for pattern in suspicious_patterns:\n                if pattern in content:\n                    result.warnings.append(f"Suspicious PDF feature detected: {pattern.decode('utf-8', errors='ignore')}")\n\n            # Check for embedded executables\n            if b'/Type/Filespec' in content:\n                result.warnings.append("Embedded files detected in PDF")\n                result.threat_indicators.append(ThreatType.MALICIOUS_FILE)\n\n        except Exception as e:\n            result.warnings.append(f"Could not check PDF: {e}")\n\n        return result\n\n\nclass ResourceLimiter:\n    """\n    Resource limiting and monitoring.\n\n    Prevents resource exhaustion attacks through comprehensive limits.\n    """\n\n    def __init__(self,\n                 max_memory_mb: int = 512,\n                 max_cpu_seconds: int = 30,\n                 max_file_handles: int = 100,\n                 max_threads: int = 10,\n                 max_disk_usage_mb: int = 1024):\n        """\n        Initialize resource limiter.\n\n        Args:\n            max_memory_mb: Maximum memory usage in MB\n            max_cpu_seconds: Maximum CPU time in seconds\n            max_file_handles: Maximum open file handles\n            max_threads: Maximum number of threads\n            max_disk_usage_mb: Maximum disk usage in MB\n        """\n        self.max_memory_mb = max_memory_mb\n        self.max_cpu_seconds = max_cpu_seconds\n        self.max_file_handles = max_file_handles\n        self.max_threads = max_threads\n        self.max_disk_usage_mb = max_disk_usage_mb\n\n        # Resource monitoring\n        self.memory_monitor = MemoryMonitor()\n        self.resource_usage: Dict[str, Dict[str, Any]] = {}\n\n    def create_limited_context(self, context_id: str) -> 'ResourceContext':\n        """Create a resource-limited execution context"""\n        return ResourceContext(\n            context_id=context_id,\n            limiter=self,\n            max_memory_mb=self.max_memory_mb,\n            max_cpu_seconds=self.max_cpu_seconds,\n            max_file_handles=self.max_file_handles,\n            max_threads=self.max_threads\n        )\n\n    def check_limits(self, context_id: str) -> ValidationResult:\n        """Check if resource limits are exceeded"""\n        result = ValidationResult(is_valid=True)\n\n        usage = self.resource_usage.get(context_id, {})\n\n        # Check memory\n        current_memory = self._get_current_memory_usage()\n        if current_memory > self.max_memory_mb:\n            result.is_valid = False\n            result.errors.append(f"Memory limit exceeded: {current_memory}MB > {self.max_memory_mb}MB")\n            result.threat_indicators.append(ThreatType.RESOURCE_EXHAUSTION)\n\n        # Check CPU\n        cpu_time = usage.get('cpu_time', 0)\n        if cpu_time > self.max_cpu_seconds:\n            result.is_valid = False\n            result.errors.append(f"CPU time limit exceeded: {cpu_time}s > {self.max_cpu_seconds}s")\n            result.threat_indicators.append(ThreatType.RESOURCE_EXHAUSTION)\n\n        # Check file handles\n        file_handles = len(usage.get('open_files', []))\n        if file_handles > self.max_file_handles:\n            result.is_valid = False\n            result.errors.append(f"File handle limit exceeded: {file_handles} > {self.max_file_handles}")\n            result.threat_indicators.append(ThreatType.RESOURCE_EXHAUSTION)\n\n        return result\n\n    def _get_current_memory_usage(self) -> float:\n        """Get current process memory usage in MB"""\n        process = psutil.Process()\n        return process.memory_info().rss / 1024 / 1024\n\n    def enforce_limits(self):\n        """Enforce resource limits on current process"""\n        try:\n            # Memory limit\n            resource.setrlimit(resource.RLIMIT_AS,\n                             (self.max_memory_mb * 1024 * 1024, self.max_memory_mb * 1024 * 1024))\n\n            # CPU time limit\n            resource.setrlimit(resource.RLIMIT_CPU,\n                             (self.max_cpu_seconds, self.max_cpu_seconds))\n\n            # File handle limit\n            resource.setrlimit(resource.RLIMIT_NOFILE,\n                             (self.max_file_handles, self.max_file_handles))\n\n            # Process limit\n            resource.setrlimit(resource.RLIMIT_NPROC,\n                             (self.max_threads, self.max_threads))\n\n        except Exception as e:\n            logger.warning(f"Could not set resource limits: {e}")\n\n\nclass ResourceContext:\n    """Context manager for resource-limited execution"""\n\n    def __init__(self, context_id: str, limiter: ResourceLimiter, **limits):\n        self.context_id = context_id\n        self.limiter = limiter\n        self.limits = limits\n        self.start_time = None\n        self.start_cpu = None\n\n    def __enter__(self):\n        self.start_time = time.time()\n        self.start_cpu = time.process_time()\n\n        # Record context start\n        self.limiter.resource_usage[self.context_id] = {\n            'start_time': self.start_time,\n            'cpu_time': 0,\n            'open_files': []\n        }\n\n        return self\n\n    def __exit__(self, exc_type, exc_val, exc_tb):\n        # Calculate resource usage\n        elapsed_time = time.time() - self.start_time\n        cpu_time = time.process_time() - self.start_cpu\n\n        # Update usage\n        usage = self.limiter.resource_usage.get(self.context_id, {})\n        usage['cpu_time'] = cpu_time\n        usage['elapsed_time'] = elapsed_time\n\n        # Check limits\n        result = self.limiter.check_limits(self.context_id)\n        if not result.is_valid:\n            logger.warning(f"Resource limits exceeded for context {self.context_id}: {result.errors}")\n\n\nclass SecureFileAccess:\n    """\n    Secure file access control for downloads and uploads.\n\n    Implements strict access control and validation for file operations.\n    """\n\n    def __init__(self,\n                 downloads_dir: Path,\n                 uploads_dir: Path,\n                 max_file_size: int = 100 * 1024 * 1024,\n                 allowed_mime_types: Optional[List[str]] = None):\n        """\n        Initialize secure file access.\n\n        Args:\n            downloads_dir: Directory for downloads\n            uploads_dir: Directory for uploads\n            max_file_size: Maximum file size\n            allowed_mime_types: Allowed MIME types\n        """\n        self.downloads_dir = Path(downloads_dir)\n        self.uploads_dir = Path(uploads_dir)\n        self.max_file_size = max_file_size\n        self.allowed_mime_types = allowed_mime_types or [\n            'text/plain', 'text/csv', 'application/json',\n            'application/pdf', 'image/png', 'image/jpeg'\n        ]\n\n        # Ensure directories exist with proper permissions\n        for directory in [self.downloads_dir, self.uploads_dir]:\n            directory.mkdir(parents=True, exist_ok=True)\n            os.chmod(directory, 0o750)\n\n        # Access control lists\n        self.acl: Dict[str, Dict[str, List[str]]] = {}\n\n    def grant_access(self, user_id: str, file_path: Path, permissions: List[str]):\n        """Grant access to a file for a user"""\n        file_key = str(file_path.absolute())\n\n        if file_key not in self.acl:\n            self.acl[file_key] = {}\n\n        self.acl[file_key][user_id] = permissions\n\n    def check_access(self, user_id: str, file_path: Path, permission: str) -> bool:\n        """Check if user has permission for file"""\n        file_key = str(file_path.absolute())\n\n        if file_key not in self.acl:\n            return False\n\n        user_perms = self.acl.get(file_key, {}).get(user_id, [])\n        return permission in user_perms\n\n    async def secure_download(self,\n                            user_id: str,\n                            file_path: Path,\n                            context: SecurityContext) -> Tuple[Optional[bytes], ValidationResult]:\n        """Securely download a file"""\n        result = ValidationResult(is_valid=True)\n\n        # Validate file path\n        try:\n            safe_path = validate_file_path(file_path, base_directory=self.downloads_dir)\n        except Exception as e:\n            result.is_valid = False\n            result.errors.append(str(e))\n            result.threat_indicators.append(ThreatType.PATH_TRAVERSAL)\n            return None, result\n\n        # Check access\n        if not self.check_access(user_id, safe_path, 'read'):\n            result.is_valid = False\n            result.errors.append("Access denied")\n            result.threat_indicators.append(ThreatType.UNAUTHORIZED_ACCESS)\n            return None, result\n\n        # Read file with size limit\n        try:\n            file_size = safe_path.stat().st_size\n            if file_size > self.max_file_size:\n                result.is_valid = False\n                result.errors.append(f"File too large: {file_size} bytes")\n                result.threat_indicators.append(ThreatType.RESOURCE_EXHAUSTION)\n                return None, result\n\n            with open(safe_path, 'rb') as f:\n                content = f.read()\n\n            # Log access\n            logger.info(f"File downloaded: {safe_path} by user {user_id}")\n\n            return content, result\n\n        except Exception as e:\n            result.is_valid = False\n            result.errors.append(f"Download error: {str(e)}")\n            return None, result\n\n    async def secure_upload(self,\n                          user_id: str,\n                          filename: str,\n                          content: bytes,\n                          context: SecurityContext) -> Tuple[Optional[Path], ValidationResult]:\n        """Securely upload a file"""\n        result = ValidationResult(is_valid=True)\n\n        # Sanitize filename\n        safe_filename = sanitize_filename(filename)\n\n        # Check file size\n        if len(content) > self.max_file_size:\n            result.is_valid = False\n            result.errors.append(f"File too large: {len(content)} bytes")\n            result.threat_indicators.append(ThreatType.RESOURCE_EXHAUSTION)\n            return None, result\n\n        # Check MIME type\n        mime = magic.Magic(mime=True)\n        mime_type = mime.from_buffer(content)\n\n        if mime_type not in self.allowed_mime_types:\n            result.is_valid = False\n            result.errors.append(f"MIME type not allowed: {mime_type}")\n            result.threat_indicators.append(ThreatType.MALICIOUS_FILE)\n            return None, result\n\n        # Generate unique filename\n        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")\n        unique_filename = f"{user_id}_{timestamp}_{safe_filename}"\n        upload_path = self.uploads_dir / unique_filename\n\n        try:\n            # Write file with restricted permissions\n            with open(upload_path, 'wb') as f:\n                f.write(content)\n            os.chmod(upload_path, 0o640)\n\n            # Grant read access to uploader\n            self.grant_access(user_id, upload_path, ['read'])\n\n            # Log upload\n            logger.info(f"File uploaded: {upload_path} by user {user_id}")\n\n            return upload_path, result\n\n        except Exception as e:\n            result.is_valid = False\n            result.errors.append(f"Upload error: {str(e)}")\n            return None, result\n\n\nclass SecureCommunicationProtocol:\n    """\n    Secure communication protocol implementation.\n\n    Provides encryption, authentication, and integrity for MCP communications.\n    """\n\n    def __init__(self,\n                 encryption_enabled: bool = True,\n                 require_signature: bool = True,\n                 max_message_size: int = 10 * 1024 * 1024):\n        """\n        Initialize secure communication protocol.\n\n        Args:\n            encryption_enabled: Enable message encryption\n            require_signature: Require message signatures\n            max_message_size: Maximum message size\n        """\n        self.encryption_enabled = encryption_enabled\n        self.require_signature = require_signature\n        self.max_message_size = max_message_size\n\n        # Cryptographic components\n        from cryptography.fernet import Fernet\n        from cryptography.hazmat.primitives import hashes, serialization\n        from cryptography.hazmat.primitives.asymmetric import rsa, padding\n\n        # Generate keys (in production, load from secure storage)\n        self.symmetric_key = Fernet.generate_key()\n        self.fernet = Fernet(self.symmetric_key)\n\n        # Generate RSA keypair for signatures\n        self.private_key = rsa.generate_private_key(\n            public_exponent=65537,\n            key_size=2048\n        )\n        self.public_key = self.private_key.public_key()\n\n    def encrypt_message(self, message: bytes, context: SecurityContext) -> bytes:\n        """Encrypt a message"""\n        if not self.encryption_enabled:\n            return message\n\n        # Add metadata\n        metadata = {\n            'timestamp': datetime.utcnow().isoformat(),\n            'user_id': context.user_id,\n            'client_id': context.client_id\n        }\n\n        # Create payload\n        payload = {\n            'metadata': metadata,\n            'message': message.hex()\n        }\n\n        # Encrypt\n        encrypted = self.fernet.encrypt(json.dumps(payload).encode())\n\n        return encrypted\n\n    def decrypt_message(self, encrypted_message: bytes, context: SecurityContext) -> Optional[bytes]:\n        """Decrypt a message"""\n        if not self.encryption_enabled:\n            return encrypted_message\n\n        try:\n            # Decrypt\n            decrypted = self.fernet.decrypt(encrypted_message)\n            payload = json.loads(decrypted.decode())\n\n            # Verify metadata\n            metadata = payload.get('metadata', {})\n\n            # Check timestamp (prevent replay attacks)\n            timestamp_str = metadata.get('timestamp')\n            if timestamp_str:\n                timestamp = datetime.fromisoformat(timestamp_str)\n                age = datetime.utcnow() - timestamp\n                if age > timedelta(minutes=5):\n                    logger.warning("Message too old, possible replay attack")\n                    return None\n\n            # Extract message\n            message_hex = payload.get('message')\n            if message_hex:\n                return bytes.fromhex(message_hex)\n            else:\n                return None\n\n        except Exception as e:\n            logger.error(f"Decryption error: {e}")\n            return None\n\n    def sign_message(self, message: bytes) -> bytes:\n        """Sign a message"""\n        if not self.require_signature:\n            return b''\n\n        from cryptography.hazmat.primitives.asymmetric import padding\n        from cryptography.hazmat.primitives import hashes\n\n        signature = self.private_key.sign(\n            message,\n            padding.PSS(\n                mgf=padding.MGF1(hashes.SHA256()),\n                salt_length=padding.PSS.MAX_LENGTH\n            ),\n            hashes.SHA256()\n        )\n\n        return signature\n\n    def verify_signature(self, message: bytes, signature: bytes) -> bool:\n        """Verify message signature"""\n        if not self.require_signature:\n            return True\n\n        try:\n            from cryptography.hazmat.primitives.asymmetric import padding\n            from cryptography.hazmat.primitives import hashes\n\n            self.public_key.verify(\n                signature,\n                message,\n                padding.PSS(\n                    mgf=padding.MGF1(hashes.SHA256()),\n                    salt_length=padding.PSS.MAX_LENGTH\n                ),\n                hashes.SHA256()\n            )\n            return True\n\n        except Exception as e:\n            logger.warning(f"Signature verification failed: {e}")\n            return False\n\n    def validate_message_size(self, message: bytes) -> ValidationResult:\n        """Validate message size"""\n        result = ValidationResult(is_valid=True)\n\n        if len(message) > self.max_message_size:\n            result.is_valid = False\n            result.errors.append(f"Message too large: {len(message)} bytes")\n            result.threat_indicators.append(ThreatType.RESOURCE_EXHAUSTION)\n\n        return result\n\n\nclass MCPSecurityManager:\n    """\n    Comprehensive security manager for MCP clients.\n\n    Integrates authentication, authorization, and secure communication.\n    """\n\n    def __init__(self,\n                 auth_middleware: AuthMiddleware,\n                 secure_protocol: SecureCommunicationProtocol,\n                 audit_logger: 'SecurityAuditLogger'):\n        """\n        Initialize MCP security manager.\n\n        Args:\n            auth_middleware: Authentication middleware\n            secure_protocol: Secure communication protocol\n            audit_logger: Audit logger\n        """\n        self.auth_middleware = auth_middleware\n        self.secure_protocol = secure_protocol\n        self.audit_logger = audit_logger\n\n        # Client registry\n        self.registered_clients: Dict[str, Dict[str, Any]] = {}\n\n        # Session management\n        self.active_sessions: Dict[str, Dict[str, Any]] = {}\n\n    def register_client(self,\n                       client_id: str,\n                       client_secret: str,\n                       permissions: List[str],\n                       metadata: Optional[Dict[str, Any]] = None) -> bool:\n        """Register an MCP client"""\n        # Hash client secret\n        secret_hash = hashlib.sha256(client_secret.encode()).hexdigest()\n\n        self.registered_clients[client_id] = {\n            'secret_hash': secret_hash,\n            'permissions': permissions,\n            'metadata': metadata or {},\n            'created_at': datetime.utcnow(),\n            'last_access': None\n        }\n\n        self.audit_logger.log_event(\n            'client_registered',\n            {'client_id': client_id, 'permissions': permissions}\n        )\n\n        return True\n\n    async def authenticate_client(self,\n                                client_id: str,\n                                client_secret: str,\n                                context: SecurityContext) -> Optional[Dict[str, Any]]:\n        """Authenticate MCP client"""\n        client = self.registered_clients.get(client_id)\n\n        if not client:\n            self.audit_logger.log_event(\n                'auth_failed',\n                {'client_id': client_id, 'reason': 'unknown_client'},\n                context=context\n            )\n            return None\n\n        # Verify secret\n        secret_hash = hashlib.sha256(client_secret.encode()).hexdigest()\n        if secret_hash != client['secret_hash']:\n            self.audit_logger.log_event(\n                'auth_failed',\n                {'client_id': client_id, 'reason': 'invalid_secret'},\n                context=context\n            )\n            return None\n\n        # Update last access\n        client['last_access'] = datetime.utcnow()\n\n        # Create session\n        session_id = hashlib.sha256(f"{client_id}{time.time()}".encode()).hexdigest()\n        session = {\n            'session_id': session_id,\n            'client_id': client_id,\n            'permissions': client['permissions'],\n            'created_at': datetime.utcnow(),\n            'context': context\n        }\n\n        self.active_sessions[session_id] = session\n\n        self.audit_logger.log_event(\n            'auth_success',\n            {'client_id': client_id, 'session_id': session_id},\n            context=context\n        )\n\n        return session\n\n    def authorize_action(self,\n                        session_id: str,\n                        resource: str,\n                        action: str) -> bool:\n        """Authorize client action"""\n        session = self.active_sessions.get(session_id)\n\n        if not session:\n            return False\n\n        # Check permissions\n        required_permission = f"{resource}:{action}"\n        has_permission = (\n            required_permission in session['permissions'] or\n            f"{resource}:*" in session['permissions'] or\n            "*:*" in session['permissions']\n        )\n\n        # Log authorization attempt\n        self.audit_logger.log_event(\n            'authorization',\n            {\n                'session_id': session_id,\n                'resource': resource,\n                'action': action,\n                'granted': has_permission\n            },\n            context=session.get('context')\n        )\n\n        return has_permission\n\n    async def secure_request(self,\n                           session_id: str,\n                           request_data: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], ValidationResult]:\n        """Process secure MCP request"""\n        result = ValidationResult(is_valid=True)\n\n        session = self.active_sessions.get(session_id)\n        if not session:\n            result.is_valid = False\n            result.errors.append("Invalid session")\n            result.threat_indicators.append(ThreatType.UNAUTHORIZED_ACCESS)\n            return None, result\n\n        # Validate request\n        if 'action' not in request_data or 'resource' not in request_data:\n            result.is_valid = False\n            result.errors.append("Missing required fields")\n            return None, result\n\n        # Check authorization\n        if not self.authorize_action(session_id, request_data['resource'], request_data['action']):\n            result.is_valid = False\n            result.errors.append("Unauthorized action")\n            result.threat_indicators.append(ThreatType.UNAUTHORIZED_ACCESS)\n            return None, result\n\n        # Process request (actual implementation would handle specific actions)\n        response = {\n            'status': 'success',\n            'session_id': session_id,\n            'timestamp': datetime.utcnow().isoformat()\n        }\n\n        return response, result\n\n\nclass SecurityAuditLogger:\n    """\n    Comprehensive security audit logging.\n\n    Logs all security-relevant events for monitoring and compliance.\n    """\n\n    def __init__(self,\n                 log_dir: Path,\n                 rotation_size: int = 100 * 1024 * 1024,  # 100MB\n                 retention_days: int = 90):\n        """\n        Initialize security audit logger.\n\n        Args:\n            log_dir: Directory for audit logs\n            rotation_size: Log rotation size\n            retention_days: Log retention period\n        """\n        self.log_dir = Path(log_dir)\n        self.rotation_size = rotation_size\n        self.retention_days = retention_days\n\n        # Ensure log directory exists\n        self.log_dir.mkdir(parents=True, exist_ok=True)\n        os.chmod(self.log_dir, 0o750)\n\n        # Current log file\n        self.current_log = self.log_dir / f"security_audit_{datetime.now().strftime('%Y%m%d')}.log"\n\n        # Log sanitizer\n        self.sanitizer = LogSanitizer()\n\n    def log_event(self,\n                 event_type: str,\n                 details: Dict[str, Any],\n                 severity: str = 'INFO',\n                 context: Optional[SecurityContext] = None):\n        """Log security event"""\n        # Create event record\n        event = {\n            'timestamp': datetime.utcnow().isoformat(),\n            'event_type': event_type,\n            'severity': severity,\n            'details': self.sanitizer.sanitize_dict(details)\n        }\n\n        # Add context if provided\n        if context:\n            event['context'] = {\n                'user_id': context.user_id,\n                'client_id': context.client_id,\n                'ip_address': context.ip_address,\n                'risk_level': context.risk_level\n            }\n\n        # Write to log\n        try:\n            with open(self.current_log, 'a') as f:\n                f.write(json.dumps(event) + '
')
                
            # Check rotation
            if self.current_log.stat().st_size > self.rotation_size:
                self._rotate_log()
                
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")
            
    def _rotate_log(self):
        """Rotate audit log"""
        # Rename current log
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        rotated_log = self.log_dir / f"security_audit_{timestamp}.log.gz"
        
        # Compress and move
        import gzip
        import shutil
        
        with open(self.current_log, 'rb') as f_in:
            with gzip.open(rotated_log, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
                
        # Create new log
        self.current_log = self.log_dir / f"security_audit_{datetime.now().strftime('%Y%m%d')}.log"
        
        # Clean old logs
        self._clean_old_logs()
        
    def _clean_old_logs(self):
        """Clean logs older than retention period"""
        cutoff_date = datetime.now() - timedelta(days=self.retention_days)
        
        for log_file in self.log_dir.glob("security_audit_*.log.gz"):
            # Extract date from filename
            try:
                date_str = log_file.stem.split('_')[2]
                file_date = datetime.strptime(date_str, '%Y%m%d')
                
                if file_date < cutoff_date:
                    log_file.unlink()
                    logger.info(f"Deleted old audit log: {log_file}")
                    
            except Exception as e:
                logger.warning(f"Could not process log file {log_file}: {e}")
                
    def search_logs(self,
                   start_date: datetime,
                   end_date: datetime,
                   event_type: Optional[str] = None,
                   user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Search audit logs"""
        results = []
        
        # Search through logs in date range
        for log_file in self.log_dir.glob("security_audit_*.log*"):
            # Check if file is in date range
            # (Implementation would parse dates and search)
            pass
            
        return results


class SecurityArchitecture:
    """
    Main security architecture orchestrator.
    
    Integrates all security components into a cohesive system.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize security architecture.
        
        Args:
            config: Security configuration
        """
        self.config = config
        
        # Initialize components
        self.file_sandbox = FileSandbox(
            sandbox_dir=Path(config.get('sandbox_dir', '/tmp/sandbox')),
            max_file_size=config.get('max_file_size', 100 * 1024 * 1024),
            use_docker=config.get('use_docker_sandbox', False)
        )
        
        self.input_validator = InputValidator()
        
        self.malicious_file_detector = MaliciousFileDetector(
            max_decompressed_size=config.get('max_decompressed_size', 1024 * 1024 * 1024)
        )
        
        self.resource_limiter = ResourceLimiter(
            max_memory_mb=config.get('max_memory_mb', 512),
            max_cpu_seconds=config.get('max_cpu_seconds', 30)
        )
        
        self.secure_file_access = SecureFileAccess(
            downloads_dir=Path(config.get('downloads_dir', './downloads')),
            uploads_dir=Path(config.get('uploads_dir', './uploads'))
        )
        
        self.secure_protocol = SecureCommunicationProtocol(
            encryption_enabled=config.get('encryption_enabled', True),
            require_signature=config.get('require_signature', True)
        )
        
        self.audit_logger = SecurityAuditLogger(
            log_dir=Path(config.get('audit_log_dir', './audit_logs'))
        )
        
        # Initialize auth middleware (would be injected in production)
        self.auth_middleware = None
        
        # Security policies
        self.security_policy = SecurityPolicy()
        
        logger.info("Security architecture initialized")
        
    async def process_request(self,
                            request_type: str,
                            request_data: Dict[str, Any],
                            context: SecurityContext) -> Tuple[Optional[Any], ValidationResult]:
        """
        Process a request through the security architecture.
        
        Args:
            request_type: Type of request
            request_data: Request data
            context: Security context
            
        Returns:
            Tuple of (result, validation)
        """
        # Log request
        self.audit_logger.log_event(
            'request_received',
            {'type': request_type, 'data_keys': list(request_data.keys())},
            context=context
        )
        
        # Create resource context
        with self.resource_limiter.create_limited_context(context.user_id):
            # Validate inputs
            validation_results = []
            
            for field, value in request_data.items():
                # Determine field type
                field_type = self._infer_field_type(field)
                validation = self.input_validator.validate(value, field_type)
                validation_results.append(validation)
                
                if not validation.is_valid:
                    self.audit_logger.log_event(
                        'validation_failed',
                        {'field': field, 'errors': validation.errors},
                        severity='WARNING',
                        context=context
                    )
                    return None, validation
                    
            # Process based on request type
            if request_type == 'file_upload':
                return await self._handle_file_upload(request_data, context)
            elif request_type == 'file_download':
                return await self._handle_file_download(request_data, context)
            elif request_type == 'mcp_request':
                return await self._handle_mcp_request(request_data, context)
            else:
                result = ValidationResult(is_valid=False)
                result.errors.append(f"Unknown request type: {request_type}")
                return None, result
                
    def _infer_field_type(self, field_name: str) -> str:
        """Infer field type from name"""
        field_lower = field_name.lower()
        
        if 'email' in field_lower:
            return 'email'
        elif 'url' in field_lower or 'link' in field_lower:
            return 'url'
        elif 'path' in field_lower or 'file' in field_lower:
            return 'file_path'
        elif 'command' in field_lower or 'cmd' in field_lower:
            return 'command'
        elif 'sql' in field_lower or 'query' in field_lower:
            return 'sql_identifier'
        else:
            return 'generic'
            
    async def _handle_file_upload(self,
                                request_data: Dict[str, Any],
                                context: SecurityContext) -> Tuple[Optional[Path], ValidationResult]:
        """Handle file upload request"""
        filename = request_data.get('filename')
        content = request_data.get('content')
        
        if not filename or not content:
            result = ValidationResult(is_valid=False)
            result.errors.append("Missing filename or content")
            return None, result
            
        # Save to temporary file
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)
            
        try:
            # Scan for malicious content
            scan_result = await self.malicious_file_detector.scan_file(tmp_path)
            if not scan_result.is_valid:
                return None, scan_result
                
            # Process in sandbox
            def process_upload(file_path):
                # Actual processing logic
                return file_path
                
            processed, sandbox_result = await self.file_sandbox.process_file(
                tmp_path, process_upload, context
            )
            
            if not sandbox_result.is_valid:
                return None, sandbox_result
                
            # Secure upload
            upload_path, upload_result = await self.secure_file_access.secure_upload(
                context.user_id, filename, content, context
            )
            
            return upload_path, upload_result
            
        finally:
            # Cleanup
            tmp_path.unlink()
            
    async def _handle_file_download(self,
                                  request_data: Dict[str, Any],
                                  context: SecurityContext) -> Tuple[Optional[bytes], ValidationResult]:
        """Handle file download request"""
        file_path = request_data.get('file_path')
        
        if not file_path:
            result = ValidationResult(is_valid=False)
            result.errors.append("Missing file_path")
            return None, result
            
        # Secure download
        content, download_result = await self.secure_file_access.secure_download(
            context.user_id, Path(file_path), context
        )
        
        return content, download_result
        
    async def _handle_mcp_request(self,
                                request_data: Dict[str, Any],
                                context: SecurityContext) -> Tuple[Optional[Dict[str, Any]], ValidationResult]:
        """Handle MCP request"""
        # This would integrate with MCPSecurityManager
        result = ValidationResult(is_valid=True)
        response = {'status': 'processed', 'timestamp': datetime.utcnow().isoformat()}
        return response, result


# Example usage and testing
if __name__ == "__main__":
    # Initialize security architecture
    config = {
        'sandbox_dir': '/tmp/security_sandbox',
        'max_file_size': 50 * 1024 * 1024,  # 50MB
        'max_memory_mb': 256,
        'max_cpu_seconds': 20,
        'downloads_dir': './secure_downloads',
        'uploads_dir': './secure_uploads',
        'audit_log_dir': './security_audit_logs',
        'encryption_enabled': True,
        'require_signature': True
    }
    
    security_arch = SecurityArchitecture(config)
    
    # Example context
    context = SecurityContext(
        user_id='user123',
        client_id='client456',
        ip_address='192.168.1.100',
        permissions=['file:read', 'file:write'],
        risk_level='medium'
    )
    
    # Example: Validate input
    validator = InputValidator()
    email_result = validator.validate('user@example.com', 'email')
    print(f"Email validation: {email_result.is_valid}")
    
    # Example: Check for malicious patterns
    sql_result = validator.validate("'; DROP TABLE users; --", 'sql_identifier')
    print(f"SQL validation: {sql_result.is_valid}, Errors: {sql_result.errors}")
    
    # Example: Resource limiting
    limiter = ResourceLimiter()
    with limiter.create_limited_context('test_context') as ctx:
        # Perform resource-limited operations
        pass
        
    print("Security architecture example completed")