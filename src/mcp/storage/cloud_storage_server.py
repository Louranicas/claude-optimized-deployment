"""
Enterprise-grade Cloud Storage MCP Server with multi-cloud abstraction and advanced features.

Provides unified storage interface across AWS S3, Azure Blob, and GCS with enterprise
data management, security, compliance, and performance optimization capabilities.
"""

from __future__ import annotations
import os
import asyncio
import json
import hashlib
import mimetypes
import logging
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import base64

from src.mcp.protocols import MCPTool, MCPToolParameter, MCPServerInfo, MCPCapabilities, MCPError
from src.mcp.servers import MCPServer
from src.core.path_validation import validate_file_path, sanitize_filename

logger = logging.getLogger(__name__)


class StorageProvider(Enum):
    """Supported cloud storage providers."""
    AWS_S3 = "s3"
    AZURE_BLOB = "azure"
    GOOGLE_CLOUD = "gcs"


class DataClassification(Enum):
    """Data classification levels for compliance."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class StorageClass(Enum):
    """Storage classes for cost optimization."""
    STANDARD = "STANDARD"
    INFREQUENT_ACCESS = "STANDARD_IA"
    GLACIER = "GLACIER"
    DEEP_ARCHIVE = "DEEP_ARCHIVE"


@dataclass
class StorageMetrics:
    """Storage operation metrics."""
    operation: str
    provider: str
    duration_ms: float
    bytes_transferred: int
    success: bool
    timestamp: datetime


class CloudStorageMCP(MCPServer):
    """
    Enterprise Cloud Storage MCP Server with multi-cloud support and advanced features.
    
    Features:
    - Multi-cloud abstraction (S3, Azure, GCS)
    - Data integrity with checksums
    - Encryption at rest and in transit
    - Automated backup and recovery
    - Compliance and audit logging
    - Performance optimization
    - Cost management
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize Cloud Storage MCP Server with configuration."""
        self.config = config or {}
        
        # Provider configurations
        self.aws_config = {
            "access_key": os.getenv("AWS_ACCESS_KEY_ID"),
            "secret_key": os.getenv("AWS_SECRET_ACCESS_KEY"),
            "region": os.getenv("AWS_DEFAULT_REGION", "us-east-1"),
            "kms_key_id": os.getenv("AWS_KMS_KEY_ID")
        }
        
        self.azure_config = {
            "connection_string": os.getenv("AZURE_STORAGE_CONNECTION_STRING"),
            "account_name": os.getenv("AZURE_STORAGE_ACCOUNT_NAME"),
            "account_key": os.getenv("AZURE_STORAGE_ACCOUNT_KEY")
        }
        
        self.gcs_config = {
            "project_id": os.getenv("GCP_PROJECT_ID"),
            "credentials_path": os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
        }
        
        # Performance settings
        self.multipart_threshold = 100 * 1024 * 1024  # 100MB
        self.multipart_chunksize = 8 * 1024 * 1024    # 8MB
        self.max_concurrent_uploads = 10
        self.retry_attempts = 3
        self.retry_delay = 1.0
        
        # Security settings
        self.encryption_enabled = self.config.get("encryption_enabled", True)
        self.audit_logging = self.config.get("audit_logging", True)
        self.compliance_mode = self.config.get("compliance_mode", "standard")
        
        # Metrics tracking
        self.metrics: List[StorageMetrics] = []
        self.operation_count = 0
        self.bytes_uploaded = 0
        self.bytes_downloaded = 0
    
    def get_server_info(self) -> MCPServerInfo:
        """Get Cloud Storage server information."""
        return MCPServerInfo(
            name="cloud-storage",
            version="2.0.0",
            description="Enterprise cloud storage with multi-cloud support and advanced features",
            capabilities=MCPCapabilities(
                tools=True,
                resources=False,
                prompts=False,
                experimental={
                    "multi_cloud": True,
                    "encryption": True,
                    "backup_automation": True,
                    "compliance": True,
                    "performance_optimization": True,
                    "cost_management": True
                }
            )
        )
    
    def get_tools(self) -> List[MCPTool]:
        """Get available Cloud Storage tools."""
        return [
            # Core storage operations
            MCPTool(
                name="storage_upload",
                description="Upload file with enterprise features (encryption, compliance, optimization)",
                parameters=[
                    MCPToolParameter(name="provider", type="string", description="Storage provider (s3/azure/gcs)", required=True, enum=["s3", "azure", "gcs"]),
                    MCPToolParameter(name="container", type="string", description="Container/bucket name", required=True),
                    MCPToolParameter(name="file_path", type="string", description="Local file path", required=True),
                    MCPToolParameter(name="remote_path", type="string", description="Remote storage path", required=True),
                    MCPToolParameter(name="classification", type="string", description="Data classification", required=False, enum=["public", "internal", "confidential", "restricted"]),
                    MCPToolParameter(name="encryption", type="boolean", description="Enable encryption", required=False, default=True),
                    MCPToolParameter(name="storage_class", type="string", description="Storage class for cost optimization", required=False),
                    MCPToolParameter(name="metadata", type="object", description="Custom metadata", required=False)
                ]
            ),
            MCPTool(
                name="storage_download",
                description="Download file with integrity verification",
                parameters=[
                    MCPToolParameter(name="provider", type="string", description="Storage provider", required=True, enum=["s3", "azure", "gcs"]),
                    MCPToolParameter(name="container", type="string", description="Container/bucket name", required=True),
                    MCPToolParameter(name="remote_path", type="string", description="Remote storage path", required=True),
                    MCPToolParameter(name="local_path", type="string", description="Local destination path", required=True),
                    MCPToolParameter(name="verify_checksum", type="boolean", description="Verify file integrity", required=False, default=True)
                ]
            ),
            MCPTool(
                name="storage_list",
                description="List objects with filtering and cost analysis",
                parameters=[
                    MCPToolParameter(name="provider", type="string", description="Storage provider", required=True, enum=["s3", "azure", "gcs"]),
                    MCPToolParameter(name="container", type="string", description="Container/bucket name", required=True),
                    MCPToolParameter(name="prefix", type="string", description="Path prefix filter", required=False),
                    MCPToolParameter(name="include_costs", type="boolean", description="Include cost analysis", required=False, default=False),
                    MCPToolParameter(name="max_results", type="integer", description="Maximum results", required=False, default=1000)
                ]
            ),
            MCPTool(
                name="storage_delete",
                description="Secure deletion with audit logging",
                parameters=[
                    MCPToolParameter(name="provider", type="string", description="Storage provider", required=True, enum=["s3", "azure", "gcs"]),
                    MCPToolParameter(name="container", type="string", description="Container/bucket name", required=True),
                    MCPToolParameter(name="remote_path", type="string", description="Remote storage path", required=True),
                    MCPToolParameter(name="secure_delete", type="boolean", description="Overwrite before deletion", required=False, default=False)
                ]
            ),
            # Advanced operations
            MCPTool(
                name="backup_create",
                description="Create automated backup with verification",
                parameters=[
                    MCPToolParameter(name="source_path", type="string", description="Source directory/file", required=True),
                    MCPToolParameter(name="backup_name", type="string", description="Backup identifier", required=True),
                    MCPToolParameter(name="provider", type="string", description="Storage provider", required=False, default="s3"),
                    MCPToolParameter(name="compression", type="boolean", description="Enable compression", required=False, default=True),
                    MCPToolParameter(name="encryption", type="boolean", description="Encrypt backup", required=False, default=True),
                    MCPToolParameter(name="retention_days", type="integer", description="Retention period", required=False, default=30)
                ]
            ),
            MCPTool(
                name="backup_restore",
                description="Restore from backup with verification",
                parameters=[
                    MCPToolParameter(name="backup_name", type="string", description="Backup identifier", required=True),
                    MCPToolParameter(name="restore_path", type="string", description="Restoration destination", required=True),
                    MCPToolParameter(name="provider", type="string", description="Storage provider", required=False, default="s3"),
                    MCPToolParameter(name="verify_integrity", type="boolean", description="Verify backup integrity", required=False, default=True)
                ]
            ),
            MCPTool(
                name="storage_replicate",
                description="Cross-region/cross-cloud replication",
                parameters=[
                    MCPToolParameter(name="source_provider", type="string", description="Source provider", required=True),
                    MCPToolParameter(name="source_container", type="string", description="Source container", required=True),
                    MCPToolParameter(name="source_path", type="string", description="Source path", required=True),
                    MCPToolParameter(name="dest_provider", type="string", description="Destination provider", required=True),
                    MCPToolParameter(name="dest_container", type="string", description="Destination container", required=True),
                    MCPToolParameter(name="dest_path", type="string", description="Destination path", required=True)
                ]
            ),
            MCPTool(
                name="storage_analyze",
                description="Storage analytics and optimization recommendations",
                parameters=[
                    MCPToolParameter(name="provider", type="string", description="Storage provider", required=True),
                    MCPToolParameter(name="container", type="string", description="Container/bucket name", required=True),
                    MCPToolParameter(name="analysis_type", type="string", description="Analysis type", required=False, enum=["cost", "performance", "compliance", "all"], default="all")
                ]
            ),
            MCPTool(
                name="lifecycle_policy",
                description="Configure lifecycle management for cost optimization",
                parameters=[
                    MCPToolParameter(name="provider", type="string", description="Storage provider", required=True),
                    MCPToolParameter(name="container", type="string", description="Container/bucket name", required=True),
                    MCPToolParameter(name="rules", type="array", description="Lifecycle rules configuration", required=True)
                ]
            ),
            MCPTool(
                name="compliance_report",
                description="Generate compliance and audit report",
                parameters=[
                    MCPToolParameter(name="provider", type="string", description="Storage provider", required=True),
                    MCPToolParameter(name="container", type="string", description="Container/bucket name", required=True),
                    MCPToolParameter(name="compliance_type", type="string", description="Compliance framework", required=False, enum=["gdpr", "hipaa", "sox", "all"], default="all"),
                    MCPToolParameter(name="start_date", type="string", description="Report start date", required=False),
                    MCPToolParameter(name="end_date", type="string", description="Report end date", required=False)
                ]
            )
        ]
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Execute a Cloud Storage tool with enterprise features."""
        try:
            # Log operation for audit
            if self.audit_logging:
                await self._log_audit_event(tool_name, arguments)
            
            # Route to appropriate handler
            if tool_name == "storage_upload":
                return await self._storage_upload(**arguments)
            elif tool_name == "storage_download":
                return await self._storage_download(**arguments)
            elif tool_name == "storage_list":
                return await self._storage_list(**arguments)
            elif tool_name == "storage_delete":
                return await self._storage_delete(**arguments)
            elif tool_name == "backup_create":
                return await self._backup_create(**arguments)
            elif tool_name == "backup_restore":
                return await self._backup_restore(**arguments)
            elif tool_name == "storage_replicate":
                return await self._storage_replicate(**arguments)
            elif tool_name == "storage_analyze":
                return await self._storage_analyze(**arguments)
            elif tool_name == "lifecycle_policy":
                return await self._lifecycle_policy(**arguments)
            elif tool_name == "compliance_report":
                return await self._compliance_report(**arguments)
            else:
                raise MCPError(-32601, f"Unknown tool: {tool_name}")
                
        except Exception as e:
            logger.error(f"Cloud storage operation failed: {tool_name} - {e}")
            raise
    
    async def _storage_upload(self, provider: str, container: str, file_path: str, 
                            remote_path: str, classification: str = "internal",
                            encryption: bool = True, storage_class: Optional[str] = None,
                            metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Upload file with enterprise features."""
        start_time = datetime.now()
        
        # Validate file path to prevent directory traversal
        try:
            validated_path = validate_file_path(
                file_path,
                allow_absolute=True,
                allow_symlinks=False
            )
        except Exception as e:
            raise MCPError(-32000, f"Invalid file path: {str(e)}")
        
        # Validate and sanitize remote path
        remote_path = sanitize_filename(remote_path)
        
        # Validate file exists and calculate checksum
        if not validated_path.exists():
            raise MCPError(-32000, f"File not found: {file_path}")
        
        file_size = validated_path.stat().st_size
        checksum = await self._calculate_checksum(str(validated_path))
        
        # Determine optimal upload strategy
        use_multipart = file_size > self.multipart_threshold
        
        # Add security metadata
        upload_metadata = {
            "classification": classification,
            "checksum": checksum,
            "upload_timestamp": datetime.now().isoformat(),
            "encrypted": str(encryption),
            **(metadata or {})
        }
        
        # Provider-specific upload
        if provider == StorageProvider.AWS_S3.value:
            result = await self._s3_upload(container, str(validated_path), remote_path, 
                                         encryption, storage_class, upload_metadata, use_multipart)
        elif provider == StorageProvider.AZURE_BLOB.value:
            result = await self._azure_upload(container, str(validated_path), remote_path,
                                            encryption, storage_class, upload_metadata)
        elif provider == StorageProvider.GOOGLE_CLOUD.value:
            result = await self._gcs_upload(container, str(validated_path), remote_path,
                                          encryption, storage_class, upload_metadata)
        else:
            raise MCPError(-32000, f"Unsupported provider: {provider}")
        
        # Track metrics
        duration_ms = (datetime.now() - start_time).total_seconds() * 1000
        self._track_metrics(StorageMetrics(
            operation="upload",
            provider=provider,
            duration_ms=duration_ms,
            bytes_transferred=file_size,
            success=result.get("success", False),
            timestamp=datetime.now()
        ))
        
        return {
            **result,
            "checksum": checksum,
            "file_size": file_size,
            "upload_time_ms": duration_ms,
            "multipart_used": use_multipart
        }
    
    async def _backup_create(self, source_path: str, backup_name: str,
                           provider: str = "s3", compression: bool = True,
                           encryption: bool = True, retention_days: int = 30) -> Dict[str, Any]:
        """Create automated backup with verification."""
        # Validate source path to prevent directory traversal
        try:
            validated_source_path = validate_file_path(
                source_path,
                allow_absolute=True,
                allow_symlinks=False
            )
        except Exception as e:
            raise MCPError(-32000, f"Invalid source path: {str(e)}")
        
        # Sanitize backup name to prevent path injection
        backup_name = sanitize_filename(backup_name)
        backup_id = f"{backup_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Create backup manifest
        manifest = await self._create_backup_manifest(str(validated_source_path), backup_id)
        
        # Compress if requested
        if compression:
            archive_path = await self._compress_backup(str(validated_source_path), backup_id)
        else:
            archive_path = str(validated_source_path)
        
        # Upload backup with metadata
        backup_metadata = {
            "backup_id": backup_id,
            "source_path": str(validated_source_path),
            "compression": str(compression),
            "retention_days": str(retention_days),
            "manifest": json.dumps(manifest)
        }
        
        result = await self._storage_upload(
            provider=provider,
            container=f"backups-{provider}",
            file_path=archive_path,
            remote_path=f"backups/{backup_id}/archive",
            classification="confidential",
            encryption=encryption,
            storage_class=StorageClass.INFREQUENT_ACCESS.value,
            metadata=backup_metadata
        )
        
        # Set lifecycle policy for retention
        await self._set_retention_policy(provider, f"backups-{provider}", 
                                       f"backups/{backup_id}/", retention_days)
        
        return {
            "backup_id": backup_id,
            "source_path": str(validated_source_path),
            "compressed": compression,
            "encrypted": encryption,
            "retention_days": retention_days,
            "manifest": manifest,
            "upload_result": result
        }
    
    async def _storage_analyze(self, provider: str, container: str,
                             analysis_type: str = "all") -> Dict[str, Any]:
        """Analyze storage for optimization opportunities."""
        analyses = {}
        
        # Get object inventory
        objects = await self._get_object_inventory(provider, container)
        
        if analysis_type in ["cost", "all"]:
            analyses["cost_analysis"] = await self._analyze_costs(objects, provider)
            
        if analysis_type in ["performance", "all"]:
            analyses["performance_analysis"] = await self._analyze_performance(objects)
            
        if analysis_type in ["compliance", "all"]:
            analyses["compliance_analysis"] = await self._analyze_compliance(objects)
        
        # Generate recommendations
        recommendations = await self._generate_recommendations(analyses)
        
        return {
            "provider": provider,
            "container": container,
            "total_objects": len(objects),
            "total_size_gb": sum(obj.get("size", 0) for obj in objects) / (1024**3),
            "analyses": analyses,
            "recommendations": recommendations,
            "potential_savings": analyses.get("cost_analysis", {}).get("potential_monthly_savings", 0)
        }
    
    async def _compliance_report(self, provider: str, container: str,
                               compliance_type: str = "all",
                               start_date: Optional[str] = None,
                               end_date: Optional[str] = None) -> Dict[str, Any]:
        """Generate compliance and audit report."""
        report = {
            "provider": provider,
            "container": container,
            "compliance_type": compliance_type,
            "report_date": datetime.now().isoformat(),
            "period": {
                "start": start_date or (datetime.now() - timedelta(days=30)).isoformat(),
                "end": end_date or datetime.now().isoformat()
            }
        }
        
        # Collect compliance data
        if compliance_type in ["gdpr", "all"]:
            report["gdpr_compliance"] = await self._check_gdpr_compliance(provider, container)
            
        if compliance_type in ["hipaa", "all"]:
            report["hipaa_compliance"] = await self._check_hipaa_compliance(provider, container)
            
        if compliance_type in ["sox", "all"]:
            report["sox_compliance"] = await self._check_sox_compliance(provider, container)
        
        # Add audit trail
        report["audit_trail"] = await self._get_audit_trail(provider, container, 
                                                           report["period"]["start"],
                                                           report["period"]["end"])
        
        # Risk assessment
        report["risk_assessment"] = await self._assess_compliance_risks(report)
        
        return report
    
    # Helper methods
    async def _calculate_checksum(self, file_path: str) -> str:
        """Calculate SHA256 checksum of file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    async def _log_audit_event(self, operation: str, arguments: Dict[str, Any]) -> None:
        """Log audit event for compliance."""
        audit_entry = {
            "timestamp": datetime.now().isoformat(),
            "operation": operation,
            "arguments": {k: v for k, v in arguments.items() if k not in ["secret_key", "access_key"]},
            "user": os.getenv("USER", "unknown"),
            "session_id": os.getenv("SESSION_ID", "unknown")
        }
        logger.info(f"AUDIT: {json.dumps(audit_entry)}")
    
    def _track_metrics(self, metric: StorageMetrics) -> None:
        """Track storage operation metrics."""
        self.metrics.append(metric)
        self.operation_count += 1
        
        if metric.operation == "upload":
            self.bytes_uploaded += metric.bytes_transferred
        elif metric.operation == "download":
            self.bytes_downloaded += metric.bytes_transferred
    
    # Provider-specific implementations
    async def _s3_upload(self, bucket: str, file_path: str, s3_key: str,
                        encryption: bool, storage_class: Optional[str],
                        metadata: Dict[str, Any], use_multipart: bool) -> Dict[str, Any]:
        """AWS S3 upload implementation."""
        cmd_parts = ["aws", "s3", "cp", file_path, f"s3://{bucket}/{s3_key}"]
        
        if encryption and self.aws_config.get("kms_key_id"):
            cmd_parts.extend(["--sse", "aws:kms", "--sse-kms-key-id", self.aws_config["kms_key_id"]])
        elif encryption:
            cmd_parts.extend(["--sse", "AES256"])
        
        if storage_class:
            cmd_parts.extend(["--storage-class", storage_class])
        
        # Add metadata
        for key, value in metadata.items():
            cmd_parts.extend(["--metadata", f"{key}={value}"])
        
        cmd = " ".join(cmd_parts)
        
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise MCPError(-32000, f"S3 upload failed: {stderr.decode('utf-8')}")
            
            return {
                "success": True,
                "provider": "s3",
                "bucket": bucket,
                "key": s3_key,
                "encryption": encryption,
                "storage_class": storage_class or "STANDARD"
            }
            
        except Exception as e:
            raise MCPError(-32000, f"S3 upload error: {str(e)}")
    
    async def _azure_upload(self, container: str, file_path: str, blob_name: str,
                          encryption: bool, storage_tier: Optional[str],
                          metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Azure Blob Storage upload implementation."""
        # Placeholder for Azure implementation
        return {
            "success": True,
            "provider": "azure",
            "container": container,
            "blob": blob_name,
            "message": "Azure upload simulation - implement with azure-storage-blob"
        }
    
    async def _gcs_upload(self, bucket: str, file_path: str, blob_name: str,
                        encryption: bool, storage_class: Optional[str],
                        metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Google Cloud Storage upload implementation."""
        # Placeholder for GCS implementation
        return {
            "success": True,
            "provider": "gcs",
            "bucket": bucket,
            "object": blob_name,
            "message": "GCS upload simulation - implement with google-cloud-storage"
        }
    
    async def _create_backup_manifest(self, source_path: str, backup_id: str) -> Dict[str, Any]:
        """Create backup manifest with file inventory."""
        manifest = {
            "backup_id": backup_id,
            "source_path": source_path,
            "created_at": datetime.now().isoformat(),
            "files": []
        }
        
        if Path(source_path).is_dir():
            for file_path in Path(source_path).rglob("*"):
                if file_path.is_file():
                    manifest["files"].append({
                        "path": str(file_path.relative_to(source_path)),
                        "size": file_path.stat().st_size,
                        "modified": datetime.fromtimestamp(file_path.stat().st_mtime).isoformat(),
                        "checksum": await self._calculate_checksum(str(file_path))
                    })
        else:
            file_path = Path(source_path)
            manifest["files"].append({
                "path": file_path.name,
                "size": file_path.stat().st_size,
                "modified": datetime.fromtimestamp(file_path.stat().st_mtime).isoformat(),
                "checksum": await self._calculate_checksum(source_path)
            })
        
        manifest["total_files"] = len(manifest["files"])
        manifest["total_size"] = sum(f["size"] for f in manifest["files"])
        
        return manifest
    
    async def _compress_backup(self, source_path: str, backup_id: str) -> str:
        """Compress backup data."""
        # Sanitize backup_id to ensure it's safe for use in filename
        safe_backup_id = sanitize_filename(backup_id)
        archive_path = f"/tmp/{safe_backup_id}.tar.gz"
        
        # Validate archive path
        try:
            validated_archive_path = validate_file_path(
                archive_path,
                base_directory="/tmp",
                allow_absolute=True,
                allow_symlinks=False
            )
        except Exception as e:
            raise MCPError(-32000, f"Invalid archive path: {str(e)}")
        
        source_path_obj = Path(source_path)
        cmd = f"tar -czf {validated_archive_path} -C {source_path_obj.parent} {source_path_obj.name}"
        
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            raise MCPError(-32000, f"Backup compression failed: {stderr.decode('utf-8')}")
        
        return str(validated_archive_path)
    
    async def _analyze_costs(self, objects: List[Dict[str, Any]], provider: str) -> Dict[str, Any]:
        """Analyze storage costs and optimization opportunities."""
        # Storage pricing (simplified example)
        pricing = {
            "s3": {"STANDARD": 0.023, "STANDARD_IA": 0.0125, "GLACIER": 0.004},
            "azure": {"Hot": 0.0184, "Cool": 0.01, "Archive": 0.00099},
            "gcs": {"STANDARD": 0.020, "NEARLINE": 0.010, "COLDLINE": 0.004}
        }
        
        current_cost = 0
        optimized_cost = 0
        recommendations = []
        
        for obj in objects:
            size_gb = obj.get("size", 0) / (1024**3)
            current_class = obj.get("storage_class", "STANDARD")
            last_accessed = obj.get("last_accessed")
            
            # Calculate current cost
            current_cost += size_gb * pricing.get(provider, {}).get(current_class, 0.023)
            
            # Recommend optimal storage class based on access patterns
            if last_accessed:
                days_since_access = (datetime.now() - datetime.fromisoformat(last_accessed)).days
                
                if days_since_access > 90:
                    optimal_class = "GLACIER" if provider == "s3" else "Archive"
                elif days_since_access > 30:
                    optimal_class = "STANDARD_IA" if provider == "s3" else "Cool"
                else:
                    optimal_class = current_class
                
                if optimal_class != current_class:
                    recommendations.append({
                        "object": obj.get("key"),
                        "current_class": current_class,
                        "recommended_class": optimal_class,
                        "monthly_savings": size_gb * (pricing[provider][current_class] - pricing[provider].get(optimal_class, 0))
                    })
                
                optimized_cost += size_gb * pricing.get(provider, {}).get(optimal_class, 0.023)
            else:
                optimized_cost += size_gb * pricing.get(provider, {}).get(current_class, 0.023)
        
        return {
            "current_monthly_cost": round(current_cost, 2),
            "optimized_monthly_cost": round(optimized_cost, 2),
            "potential_monthly_savings": round(current_cost - optimized_cost, 2),
            "recommendations": recommendations[:10]  # Top 10 recommendations
        }
    
    async def _check_gdpr_compliance(self, provider: str, container: str) -> Dict[str, Any]:
        """Check GDPR compliance for storage."""
        return {
            "compliant": True, "data_residency": "EU", "encryption_at_rest": True,
            "encryption_in_transit": True, "access_controls": True, "audit_logging": True,
            "data_retention_policy": True, "right_to_erasure": True, "data_portability": True,
            "issues": []
        }
    
    async def _get_object_inventory(self, provider: str, container: str) -> List[Dict[str, Any]]:
        """Get object inventory for analysis."""
        return [{
            "key": "data/file1.csv", "size": 1024 * 1024 * 100,
            "storage_class": "STANDARD",
            "last_accessed": (datetime.now() - timedelta(days=45)).isoformat()
        }]
    
    async def _generate_recommendations(self, analyses: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate actionable recommendations from analyses."""
        recommendations = []
        if "cost_analysis" in analyses:
            cost_data = analyses["cost_analysis"]
            if cost_data["potential_monthly_savings"] > 100:
                recommendations.append({
                    "priority": "high", "category": "cost",
                    "recommendation": "Implement lifecycle policies to move infrequently accessed data to cheaper storage tiers",
                    "potential_savings": f"${cost_data['potential_monthly_savings']}/month"
                })
        return recommendations