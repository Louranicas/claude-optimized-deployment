#!/usr/bin/env python3
"""Fix remaining issues in the codebase"""

import subprocess
import sys

# Install remaining dependencies
dependencies = [
    "PyJWT",  # JWT should be installed as PyJWT
    "PyYAML",  # YAML should be installed as PyYAML
    "opentelemetry-instrumentation-requests",
    "opentelemetry-instrumentation-aiohttp-client",
    "opentelemetry-instrumentation-fastapi",
    "opentelemetry-instrumentation-sqlalchemy",
    "redis",  # Required for redis instrumentation
    "psycopg2-binary",  # Required for postgres
]

print("Installing remaining dependencies...")
for dep in dependencies:
    print(f"Installing {dep}...")
    subprocess.run([sys.executable, "-m", "pip", "install", dep], check=True)

# Add missing exception classes
exceptions_to_add = """

class ConflictError(BaseDeploymentError):
    \"\"\"Resource conflict error.\"\"\"
    
    def __init__(self, message: str, resource_type: str, conflict_reason: str, **kwargs):
        context = kwargs.get('context', {})
        context['resource_type'] = resource_type
        context['conflict_reason'] = conflict_reason
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        self.error_code = ErrorCode.VALIDATION_GENERAL


class DatabaseError(BaseDeploymentError):
    \"\"\"General database error.\"\"\"
    
    def __init__(self, message: str, operation: str, **kwargs):
        context = kwargs.get('context', {})
        context['operation'] = operation
        kwargs['context'] = context
        super().__init__(message, **kwargs)
        self.error_code = ErrorCode.DATABASE_GENERAL
"""

# Read exceptions file
with open('src/core/exceptions.py', 'r') as f:
    content = f.read()

# Add DATABASE_GENERAL error code if not present
if "DATABASE_GENERAL" not in content:
    content = content.replace(
        "    DATABASE_CONNECTION = \"5005\"",
        "    DATABASE_CONNECTION = \"5005\"\n    DATABASE_GENERAL = \"5006\""
    )

# Add missing exception classes
if "class ConflictError" not in content:
    # Find a good place to insert (after NotFoundError)
    insertion_point = content.find("class TimeoutError(NetworkError):")
    if insertion_point > 0:
        content = content[:insertion_point] + exceptions_to_add + "\n\n" + content[insertion_point:]

# Write back
with open('src/core/exceptions.py', 'w') as f:
    f.write(content)

print("Fixes applied successfully!")