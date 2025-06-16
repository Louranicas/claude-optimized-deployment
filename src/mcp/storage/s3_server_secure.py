"""
Secure AWS S3 Storage MCP Server with proper input validation.

Fixed version that prevents command injection vulnerabilities.
"""

from __future__ import annotations
import os
import asyncio
import json
import shlex
from typing import Dict, Any, List, Optional
from pathlib import Path
import logging

from src.mcp.protocols import MCPTool, MCPToolParameter, MCPServerInfo, MCPCapabilities, MCPError
from src.mcp.servers import MCPServer
from src.core.security_validators import SecurityValidators, validate_safe_path
from src.core.command_sanitizer import CommandSanitizer
from src.core.secure_command_executor import SecureCommandExecutor

from src.core.error_handler import (
    handle_errors,
    async_handle_errors,
    log_error,
    ServiceUnavailableError,
    ExternalServiceError,
    ConfigurationError,
    ValidationError,
    SecurityError
)

__all__ = [
    "SecureS3StorageMCPServer"
]

logger = logging.getLogger(__name__)


class SecureS3StorageMCPServer(MCPServer):
    """
    Secure AWS S3 Storage MCP Server with comprehensive input validation.
    
    Prevents command injection and other security vulnerabilities.
    """
    
    # File upload constraints
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
    ALLOWED_CONTENT_TYPES = {
        'text/plain', 'text/html', 'text/css', 'text/javascript',
        'application/json', 'application/pdf', 'application/zip',
        'image/jpeg', 'image/png', 'image/gif', 'image/webp',
        'video/mp4', 'audio/mpeg'
    }
    
    def __init__(self, aws_access_key: Optional[str] = None, aws_secret_key: Optional[str] = None, region: Optional[str] = None):
        """Initialize Secure S3 Storage MCP Server."""
        self.aws_access_key = aws_access_key or os.getenv("AWS_ACCESS_KEY_ID")
        self.aws_secret_key = aws_secret_key or os.getenv("AWS_SECRET_ACCESS_KEY")
        self.region = region or os.getenv("AWS_DEFAULT_REGION", "us-east-1")
        
        # Initialize secure command executor
        self.command_executor = SecureCommandExecutor(
            working_directory=Path.cwd(),
            enable_sandbox=True,
            max_output_size=10 * 1024 * 1024  # 10MB
        )
        
        # Add AWS CLI to whitelist
        self._setup_aws_commands()
    
    def _setup_aws_commands(self):
        """Configure AWS CLI commands in secure executor."""
        from src.core.secure_command_executor import CommandCategory
        
        self.command_executor.add_to_whitelist(
            'aws',
            CommandCategory.INFRASTRUCTURE,
            allowed_args=['s3', 's3api', 'sts'],
            dangerous_args=['--no-verify-ssl', '--endpoint-url'],
            max_args=20
        )
    
    def get_server_info(self) -> MCPServerInfo:
        """Get Secure S3 Storage server information."""
        return MCPServerInfo(
            name="secure-s3-storage",
            version="2.0.0",
            description="Secure AWS S3 storage integration with input validation",
            capabilities=MCPCapabilities(
                tools=True,
                resources=False,
                prompts=False,
                experimental={
                    "file_storage": True,
                    "backup_automation": True,
                    "content_delivery": True,
                    "asset_management": True,
                    "security_validation": True
                }
            )
        )
    
    def get_tools(self) -> List[MCPTool]:
        """Get available S3 Storage tools."""
        return [
            MCPTool(
                name="s3_list_buckets",
                description="List all S3 buckets",
                parameters=[]
            ),
            MCPTool(
                name="s3_list_objects",
                description="List objects in S3 bucket",
                parameters=[
                    MCPToolParameter(
                        name="bucket_name",
                        type="string",
                        description="S3 bucket name",
                        required=True
                    ),
                    MCPToolParameter(
                        name="prefix",
                        type="string",
                        description="Object key prefix filter",
                        required=False
                    ),
                    MCPToolParameter(
                        name="max_keys",
                        type="integer",
                        description="Maximum number of objects to list",
                        required=False,
                        default=100
                    )
                ]
            ),
            MCPTool(
                name="s3_upload_file",
                description="Upload file to S3 bucket",
                parameters=[
                    MCPToolParameter(
                        name="bucket_name",
                        type="string",
                        description="S3 bucket name",
                        required=True
                    ),
                    MCPToolParameter(
                        name="file_path",
                        type="string",
                        description="Local file path to upload",
                        required=True
                    ),
                    MCPToolParameter(
                        name="s3_key",
                        type="string",
                        description="S3 object key",
                        required=True
                    ),
                    MCPToolParameter(
                        name="content_type",
                        type="string",
                        description="File content type",
                        required=False
                    )
                ]
            ),
            MCPTool(
                name="s3_download_file",
                description="Download file from S3 bucket",
                parameters=[
                    MCPToolParameter(
                        name="bucket_name",
                        type="string",
                        description="S3 bucket name",
                        required=True
                    ),
                    MCPToolParameter(
                        name="s3_key",
                        type="string",
                        description="S3 object key",
                        required=True
                    ),
                    MCPToolParameter(
                        name="local_path",
                        type="string",
                        description="Local path to save file",
                        required=True
                    )
                ]
            ),
            MCPTool(
                name="s3_delete_object",
                description="Delete object from S3 bucket",
                parameters=[
                    MCPToolParameter(
                        name="bucket_name",
                        type="string",
                        description="S3 bucket name",
                        required=True
                    ),
                    MCPToolParameter(
                        name="s3_key",
                        type="string",
                        description="S3 object key to delete",
                        required=True
                    )
                ]
            ),
            MCPTool(
                name="s3_create_presigned_url",
                description="Create presigned URL for S3 object",
                parameters=[
                    MCPToolParameter(
                        name="bucket_name",
                        type="string",
                        description="S3 bucket name",
                        required=True
                    ),
                    MCPToolParameter(
                        name="s3_key",
                        type="string",
                        description="S3 object key",
                        required=True
                    ),
                    MCPToolParameter(
                        name="expiration",
                        type="integer",
                        description="URL expiration time in seconds",
                        required=False,
                        default=3600
                    ),
                    MCPToolParameter(
                        name="method",
                        type="string",
                        description="HTTP method for presigned URL",
                        required=False,
                        enum=["GET", "PUT"],
                        default="GET"
                    )
                ]
            )
        ]
    
    def _validate_bucket_name(self, bucket_name: str) -> str:
        """Validate S3 bucket name according to AWS rules."""
        # S3 bucket naming rules
        if not bucket_name:
            raise ValidationError("Bucket name cannot be empty")
        
        if len(bucket_name) < 3 or len(bucket_name) > 63:
            raise ValidationError("Bucket name must be 3-63 characters")
        
        # Must start and end with lowercase letter or number
        if not re.match(r'^[a-z0-9]', bucket_name) or not re.match(r'[a-z0-9]$', bucket_name):
            raise ValidationError("Bucket name must start and end with lowercase letter or number")
        
        # Can contain lowercase letters, numbers, hyphens, and dots
        if not re.match(r'^[a-z0-9.-]+$', bucket_name):
            raise ValidationError("Bucket name can only contain lowercase letters, numbers, dots, and hyphens")
        
        # Cannot be formatted as IP address
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', bucket_name):
            raise ValidationError("Bucket name cannot be formatted as IP address")
        
        # Cannot contain consecutive dots or hyphens
        if '..' in bucket_name or '--' in bucket_name or '.-' in bucket_name or '-.' in bucket_name:
            raise ValidationError("Bucket name cannot contain consecutive special characters")
        
        return bucket_name
    
    def _validate_s3_key(self, s3_key: str) -> str:
        """Validate S3 object key."""
        if not s3_key:
            raise ValidationError("S3 key cannot be empty")
        
        # Remove leading slashes
        s3_key = s3_key.lstrip('/')
        
        # Check length (S3 limit is 1024)
        if len(s3_key) > 1024:
            raise ValidationError("S3 key too long (max 1024 characters)")
        
        # Prevent directory traversal
        if '..' in s3_key:
            raise SecurityError("Directory traversal not allowed in S3 key")
        
        # Warn about special characters (but don't reject)
        if any(char in s3_key for char in ['\\', '<', '>', '{', '}', '^', '`', '[', ']', '#', '%', '|']):
            logger.warning(f"S3 key contains special characters: {s3_key}")
        
        return s3_key
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Execute an S3 Storage tool with security validation."""
        try:
            if tool_name == "s3_list_buckets":
                return await self._s3_list_buckets()
            elif tool_name == "s3_list_objects":
                return await self._s3_list_objects(**arguments)
            elif tool_name == "s3_upload_file":
                return await self._s3_upload_file(**arguments)
            elif tool_name == "s3_download_file":
                return await self._s3_download_file(**arguments)
            elif tool_name == "s3_delete_object":
                return await self._s3_delete_object(**arguments)
            elif tool_name == "s3_create_presigned_url":
                return await self._s3_create_presigned_url(**arguments)
            else:
                raise MCPError(-32601, f"Unknown tool: {tool_name}")
        except (ValidationError, SecurityError) as e:
            logger.error(f"Security validation failed for {tool_name}: {e}")
            raise MCPError(-32602, str(e))
        except Exception as e:
            logger.error(f"Error calling S3 Storage tool {tool_name}: {e}")
            raise
    
    async def _check_aws_cli(self) -> bool:
        """Check if AWS CLI is available and configured."""
        try:
            result = await self.command_executor.execute_async(
                command="aws",
                args=["sts", "get-caller-identity"],
                timeout=10.0
            )
            return result.success
        except Exception:
            return False
    
    async def _s3_list_buckets(self) -> Dict[str, Any]:
        """List S3 buckets using secure command execution."""
        if not await self._check_aws_cli():
            raise MCPError(-32000, "AWS CLI not available or not configured")
        
        try:
            result = await self.command_executor.execute_async(
                command="aws",
                args=["s3api", "list-buckets", "--output", "json"],
                timeout=30.0
            )
            
            if not result.success:
                raise MCPError(-32000, f"AWS CLI error: {result.stderr}")
            
            data = json.loads(result.stdout)
            
            buckets = []
            for bucket in data.get("Buckets", []):
                buckets.append({
                    "name": bucket.get("Name"),
                    "creation_date": bucket.get("CreationDate")
                })
            
            return {
                "buckets": buckets,
                "total": len(buckets)
            }
            
        except json.JSONDecodeError as e:
            raise MCPError(-32000, f"Failed to parse AWS response: {e}")
        except Exception as e:
            raise MCPError(-32000, f"S3 list buckets failed: {str(e)}")
    
    async def _s3_list_objects(
        self,
        bucket_name: str,
        prefix: Optional[str] = None,
        max_keys: int = 100
    ) -> Dict[str, Any]:
        """List objects in S3 bucket with input validation."""
        # Validate inputs
        bucket_name = self._validate_bucket_name(bucket_name)
        
        # Validate max_keys
        max_keys = int(max_keys)
        if max_keys < 1 or max_keys > 1000:
            raise ValidationError("max_keys must be between 1 and 1000")
        
        # Build command arguments
        args = [
            "s3api", "list-objects-v2",
            "--bucket", bucket_name,
            "--max-items", str(max_keys),
            "--output", "json"
        ]
        
        if prefix:
            # Validate prefix
            prefix = self._validate_s3_key(prefix)
            args.extend(["--prefix", prefix])
        
        try:
            result = await self.command_executor.execute_async(
                command="aws",
                args=args,
                timeout=30.0
            )
            
            if not result.success:
                raise MCPError(-32000, f"AWS CLI error: {result.stderr}")
            
            data = json.loads(result.stdout)
            
            objects = []
            for obj in data.get("Contents", []):
                objects.append({
                    "key": obj.get("Key"),
                    "size": obj.get("Size"),
                    "last_modified": obj.get("LastModified"),
                    "etag": obj.get("ETag")
                })
            
            return {
                "bucket_name": bucket_name,
                "prefix": prefix,
                "objects": objects,
                "total": len(objects)
            }
            
        except json.JSONDecodeError as e:
            raise MCPError(-32000, f"Failed to parse AWS response: {e}")
        except Exception as e:
            raise MCPError(-32000, f"S3 list objects failed: {str(e)}")
    
    async def _s3_upload_file(
        self,
        bucket_name: str,
        file_path: str,
        s3_key: str,
        content_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """Upload file to S3 with comprehensive validation."""
        # Validate inputs
        bucket_name = self._validate_bucket_name(bucket_name)
        s3_key = self._validate_s3_key(s3_key)
        
        # Validate file path
        file_path = validate_safe_path(file_path)
        path = Path(file_path)
        
        if not path.exists():
            raise ValidationError(f"File not found: {file_path}")
        
        if not path.is_file():
            raise ValidationError(f"Not a file: {file_path}")
        
        # Check file size
        file_size = path.stat().st_size
        if file_size > self.MAX_FILE_SIZE:
            raise ValidationError(f"File too large: {file_size} bytes (max: {self.MAX_FILE_SIZE})")
        
        # Validate content type if provided
        if content_type:
            if content_type not in self.ALLOWED_CONTENT_TYPES:
                raise ValidationError(f"Content type not allowed: {content_type}")
        
        # Build S3 URL safely
        s3_url = f"s3://{bucket_name}/{s3_key}"
        
        # Build command arguments
        args = ["s3", "cp", file_path, s3_url]
        
        if content_type:
            args.extend(["--content-type", content_type])
        
        try:
            result = await self.command_executor.execute_async(
                command="aws",
                args=args,
                timeout=300.0  # 5 minutes for large files
            )
            
            if not result.success:
                raise MCPError(-32000, f"S3 upload failed: {result.stderr}")
            
            return {
                "bucket_name": bucket_name,
                "file_path": file_path,
                "s3_key": s3_key,
                "size": file_size,
                "success": True,
                "message": result.stdout
            }
            
        except Exception as e:
            raise MCPError(-32000, f"S3 upload failed: {str(e)}")
    
    async def _s3_download_file(
        self,
        bucket_name: str,
        s3_key: str,
        local_path: str
    ) -> Dict[str, Any]:
        """Download file from S3 with security validation."""
        # Validate inputs
        bucket_name = self._validate_bucket_name(bucket_name)
        s3_key = self._validate_s3_key(s3_key)
        
        # Validate and prepare local path
        local_path = validate_safe_path(local_path, base_dir=os.getcwd())
        path = Path(local_path)
        
        # Create parent directory if needed
        path.parent.mkdir(parents=True, exist_ok=True)
        
        # Build S3 URL safely
        s3_url = f"s3://{bucket_name}/{s3_key}"
        
        # Build command arguments
        args = ["s3", "cp", s3_url, local_path]
        
        try:
            result = await self.command_executor.execute_async(
                command="aws",
                args=args,
                timeout=300.0  # 5 minutes for large files
            )
            
            if not result.success:
                raise MCPError(-32000, f"S3 download failed: {result.stderr}")
            
            # Verify file was created
            if not path.exists():
                raise MCPError(-32000, "Download succeeded but file not found")
            
            return {
                "bucket_name": bucket_name,
                "s3_key": s3_key,
                "local_path": str(path.absolute()),
                "size": path.stat().st_size,
                "success": True,
                "message": result.stdout
            }
            
        except Exception as e:
            raise MCPError(-32000, f"S3 download failed: {str(e)}")
    
    async def _s3_delete_object(self, bucket_name: str, s3_key: str) -> Dict[str, Any]:
        """Delete object from S3 with validation."""
        # Validate inputs
        bucket_name = self._validate_bucket_name(bucket_name)
        s3_key = self._validate_s3_key(s3_key)
        
        # Build S3 URL safely
        s3_url = f"s3://{bucket_name}/{s3_key}"
        
        # Build command arguments
        args = ["s3", "rm", s3_url]
        
        try:
            result = await self.command_executor.execute_async(
                command="aws",
                args=args,
                timeout=30.0
            )
            
            if not result.success:
                raise MCPError(-32000, f"S3 delete failed: {result.stderr}")
            
            return {
                "bucket_name": bucket_name,
                "s3_key": s3_key,
                "success": True,
                "message": result.stdout
            }
            
        except Exception as e:
            raise MCPError(-32000, f"S3 delete failed: {str(e)}")
    
    async def _s3_create_presigned_url(
        self,
        bucket_name: str,
        s3_key: str,
        expiration: int = 3600,
        method: str = "GET"
    ) -> Dict[str, Any]:
        """Create presigned URL with validation."""
        # Validate inputs
        bucket_name = self._validate_bucket_name(bucket_name)
        s3_key = self._validate_s3_key(s3_key)
        
        # Validate expiration
        if expiration < 1 or expiration > 604800:  # Max 7 days
            raise ValidationError("Expiration must be between 1 and 604800 seconds")
        
        # Validate method
        if method not in ["GET", "PUT"]:
            raise ValidationError("Method must be GET or PUT")
        
        # Build S3 URL safely
        s3_url = f"s3://{bucket_name}/{s3_key}"
        
        # Build command arguments
        args = ["s3", "presign", s3_url, "--expires-in", str(expiration)]
        
        try:
            result = await self.command_executor.execute_async(
                command="aws",
                args=args,
                timeout=10.0
            )
            
            if not result.success:
                raise MCPError(-32000, f"S3 presign failed: {result.stderr}")
            
            # Extract URL from output
            presigned_url = result.stdout.strip()
            
            # Validate the URL format
            try:
                SecurityValidators.validate_url(presigned_url, allowed_schemes=['https'])
            except Exception as e:
                raise MCPError(-32000, f"Invalid presigned URL generated: {e}")
            
            return {
                "bucket_name": bucket_name,
                "s3_key": s3_key,
                "method": method,
                "expiration": expiration,
                "presigned_url": presigned_url,
                "success": True
            }
            
        except Exception as e:
            raise MCPError(-32000, f"S3 presign failed: {str(e)}")