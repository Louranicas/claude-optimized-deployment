"""
AWS S3 Storage MCP Server for CODE project file and asset management.

Provides S3 integration for backup, storage, and content delivery automation.
"""

from __future__ import annotations
import os
import asyncio
import json
from typing import Dict, Any, List, Optional
from pathlib import Path
import logging

from src.mcp.protocols import MCPTool, MCPToolParameter, MCPServerInfo, MCPCapabilities, MCPError
from src.mcp.servers import MCPServer

from src.core.error_handler import (
    handle_errors,\n    async_handle_errors,\n    log_error,\n    ServiceUnavailableError,\n    ExternalServiceError,\n    ConfigurationError
)

__all__ = [
    "S3StorageMCPServer"
]


logger = logging.getLogger(__name__)


class S3StorageMCPServer(MCPServer):
    """
    AWS S3 Storage MCP Server for CODE project file and asset management.
    
    Provides S3 integration for backup, storage, and content delivery automation.
    """
    
    def __init__(self, aws_access_key: Optional[str] = None, aws_secret_key: Optional[str] = None, region: Optional[str] = None):
        """Initialize S3 Storage MCP Server."""
        self.aws_access_key = aws_access_key or os.getenv("AWS_ACCESS_KEY_ID")
        self.aws_secret_key = aws_secret_key or os.getenv("AWS_SECRET_ACCESS_KEY")
        self.region = region or os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    
    def get_server_info(self) -> MCPServerInfo:
        """Get S3 Storage server information."""
        return MCPServerInfo(
            name="s3-storage",
            version="1.0.0",
            description="AWS S3 storage integration for CODE project file and asset management",
            capabilities=MCPCapabilities(
                tools=True,
                resources=False,
                prompts=False,
                experimental={
                    "file_storage": True,
                    "backup_automation": True,
                    "content_delivery": True,
                    "asset_management": True
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
                        enum=["GET", "PUT", "POST"],
                        default="GET"
                    )
                ]
            )
        ]
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Execute an S3 Storage tool."""
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
        except Exception as e:
            logger.error(f"Error calling S3 Storage tool {tool_name}: {e}")
            raise
    
    async def _check_aws_cli(self) -> bool:
        """Check if AWS CLI is available and configured."""
        try:
            process = await asyncio.create_subprocess_shell(
                "aws sts get-caller-identity",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            return process.returncode == 0
        except Exception:
            return False
    
    async def _s3_list_buckets(self) -> Dict[str, Any]:
        """List S3 buckets using AWS CLI."""
        if not await self._check_aws_cli():
            raise MCPError(-32000, "AWS CLI not available or not configured")
        
        cmd = "aws s3api list-buckets --output json"
        
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise MCPError(-32000, f"AWS CLI error: {stderr.decode('utf-8')}")
            
            data = json.loads(stdout.decode('utf-8'))
            
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
            
        except Exception as e:
            raise MCPError(-32000, f"S3 list buckets failed: {str(e)}")
    
    async def _s3_list_objects(
        self,
        bucket_name: str,
        prefix: Optional[str] = None,
        max_keys: int = 100
    ) -> Dict[str, Any]:
        """List objects in S3 bucket."""
        cmd = f"aws s3api list-objects-v2 --bucket {bucket_name} --max-items {max_keys} --output json"
        
        if prefix:
            cmd += f" --prefix {prefix}"
        
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise MCPError(-32000, f"AWS CLI error: {stderr.decode('utf-8')}")
            
            data = json.loads(stdout.decode('utf-8'))
            
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
            
        except Exception as e:
            raise MCPError(-32000, f"S3 list objects failed: {str(e)}")
    
    async def _s3_upload_file(
        self,
        bucket_name: str,
        file_path: str,
        s3_key: str,
        content_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """Upload file to S3."""
        if not Path(file_path).exists():
            raise MCPError(-32000, f"File not found: {file_path}")
        
        cmd = f"aws s3 cp {file_path} s3://{bucket_name}/{s3_key}"
        
        if content_type:
            cmd += f" --content-type {content_type}"
        
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            result = {
                "bucket_name": bucket_name,
                "file_path": file_path,
                "s3_key": s3_key,
                "success": process.returncode == 0,
                "stdout": stdout.decode('utf-8'),
                "stderr": stderr.decode('utf-8')
            }
            
            if process.returncode != 0:
                raise MCPError(-32000, f"S3 upload failed: {stderr.decode('utf-8')}")
            
            return result
            
        except Exception as e:
            raise MCPError(-32000, f"S3 upload failed: {str(e)}")
    
    async def _s3_download_file(
        self,
        bucket_name: str,
        s3_key: str,
        local_path: str
    ) -> Dict[str, Any]:
        """Download file from S3."""
        # Create parent directory if needed
        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        
        cmd = f"aws s3 cp s3://{bucket_name}/{s3_key} {local_path}"
        
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            result = {
                "bucket_name": bucket_name,
                "s3_key": s3_key,
                "local_path": local_path,
                "success": process.returncode == 0,
                "stdout": stdout.decode('utf-8'),
                "stderr": stderr.decode('utf-8')
            }
            
            if process.returncode != 0:
                raise MCPError(-32000, f"S3 download failed: {stderr.decode('utf-8')}")
            
            return result
            
        except Exception as e:
            raise MCPError(-32000, f"S3 download failed: {str(e)}")
    
    async def _s3_delete_object(self, bucket_name: str, s3_key: str) -> Dict[str, Any]:
        """Delete object from S3."""
        cmd = f"aws s3 rm s3://{bucket_name}/{s3_key}"
        
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            result = {
                "bucket_name": bucket_name,
                "s3_key": s3_key,
                "success": process.returncode == 0,
                "stdout": stdout.decode('utf-8'),
                "stderr": stderr.decode('utf-8')
            }
            
            if process.returncode != 0:
                raise MCPError(-32000, f"S3 delete failed: {stderr.decode('utf-8')}")
            
            return result
            
        except Exception as e:
            raise MCPError(-32000, f"S3 delete failed: {str(e)}")
    
    async def _s3_create_presigned_url(
        self,
        bucket_name: str,
        s3_key: str,
        expiration: int = 3600,
        method: str = "GET"
    ) -> Dict[str, Any]:
        """Create presigned URL for S3 object."""
        cmd = f"aws s3 presign s3://{bucket_name}/{s3_key} --expires-in {expiration}"
        
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise MCPError(-32000, f"S3 presign failed: {stderr.decode('utf-8')}")
            
            return {
                "bucket_name": bucket_name,
                "s3_key": s3_key,
                "method": method,
                "expiration": expiration,
                "presigned_url": stdout.decode('utf-8').strip(),
                "success": True
            }
            
        except Exception as e:
            raise MCPError(-32000, f"S3 presign failed: {str(e)}")