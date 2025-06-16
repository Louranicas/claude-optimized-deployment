"""
Chapter Extraction API Implementation
SYNTHEX Agent 7 - Comprehensive API Design for Chapter Extraction

This module provides multiple API interfaces for chapter extraction:
1. MCP tool definitions for chapter extraction
2. RESTful API endpoints for direct access
3. WebSocket API for real-time updates
4. GraphQL schema for flexible queries
5. Event-driven APIs for file monitoring
6. Batch processing APIs
7. Search and filter capabilities
8. Export formats (JSON, Markdown, HTML)
"""

import asyncio
import hashlib
import json
import logging
import mimetypes
import os
import re
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, AsyncIterator
from uuid import uuid4

import aiofiles
from fastapi import (
    APIRouter, Depends, FastAPI, File, HTTPException, 
    Query, UploadFile, WebSocket, WebSocketDisconnect, status, BackgroundTasks
)
from fastapi.responses import FileResponse, StreamingResponse
from graphene import (
    ObjectType, String, Int, List as GrapheneList, Boolean, 
    Field, Schema, Mutation, InputObjectType, Enum as GrapheneEnum
)
from pydantic import BaseModel, Field as PydanticField, validator
from starlette.websockets import WebSocketState

from src.api.base import BaseAPIClient
from src.auth.middleware import require_auth
from src.core.exceptions import ValidationError
from src.core.cache_config import CacheConfig
from src.core.rate_limiter import RateLimiter
from src.monitoring.metrics import track_api_request

logger = logging.getLogger(__name__)

# ===== ENUMS AND CONSTANTS =====

class ExportFormat(str, Enum):
    """Supported export formats."""
    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"
    PDF = "pdf"\n    DOCX = "docx"\n\nclass ChapterType(str, Enum):\n    """Types of chapters that can be extracted."""\n    STANDARD = "standard"\n    NUMBERED = "numbered"\n    NAMED = "named"\n    HIERARCHICAL = "hierarchical"\n    CUSTOM = "custom"\n\nclass ProcessingStatus(str, Enum):\n    """Status of chapter extraction processing."""\n    PENDING = "pending"\n    PROCESSING = "processing"\n    COMPLETED = "completed"\n    FAILED = "failed"\n    CANCELLED = "cancelled"\n\n# ===== PYDANTIC MODELS =====\n\nclass ChapterMetadata(BaseModel):\n    """Metadata for an extracted chapter."""\n    id: str = PydanticField(default_factory=lambda: str(uuid4()))\n    title: str\n    number: Optional[int] = None\n    level: int = 1\n    start_line: int\n    end_line: int\n    word_count: int\n    character_count: int\n    has_subsections: bool = False\n    tags: List[str] = []\n    extracted_at: datetime = PydanticField(default_factory=datetime.utcnow)\n\nclass Chapter(BaseModel):\n    """Represents an extracted chapter."""\n    metadata: ChapterMetadata\n    content: str\n    subsections: List['Chapter'] = []\n    parent_id: Optional[str] = None\n\nclass ExtractionConfig(BaseModel):\n    """Configuration for chapter extraction."""\n    chapter_pattern: str = r"^(Chapter|CHAPTER)\s+(\d+)"\n    section_pattern: Optional[str] = r"^(Section|SECTION)\s+(\d+\.?\d*)"\n    min_chapter_length: int = 100\n    max_chapter_length: Optional[int] = None\n    include_metadata: bool = True\n    preserve_formatting: bool = True\n    extract_subsections: bool = True\n    custom_patterns: List[str] = []\n\n    @validator('chapter_pattern', 'section_pattern', 'custom_patterns')\n    def validate_regex(cls, v):\n        if v:\n            try:\n                if isinstance(v, list):\n                    for pattern in v:\n                        re.compile(pattern)\n                else:\n                    re.compile(v)\n            except re.error as e:\n                raise ValidationError(f"Invalid regex pattern: {e}")\n        return v\n\nclass ExtractionRequest(BaseModel):\n    """Request model for chapter extraction."""\n    content: Optional[str] = None\n    file_path: Optional[str] = None\n    url: Optional[str] = None\n    config: ExtractionConfig = ExtractionConfig()\n    output_format: ExportFormat = ExportFormat.JSON\n    async_processing: bool = False\n\nclass ExtractionResponse(BaseModel):\n    """Response model for chapter extraction."""\n    job_id: str\n    status: ProcessingStatus\n    chapters: Optional[List[Chapter]] = None\n    total_chapters: int = 0\n    processing_time: Optional[float] = None\n    error: Optional[str] = None\n    export_url: Optional[str] = None\n\nclass BatchExtractionRequest(BaseModel):\n    """Request for batch chapter extraction."""\n    files: List[str]\n    config: ExtractionConfig = ExtractionConfig()\n    output_format: ExportFormat = ExportFormat.JSON\n    parallel_processing: bool = True\n    max_concurrent: int = 5\n\nclass SearchQuery(BaseModel):\n    """Search query for chapters."""\n    query: str\n    filters: Dict[str, Any] = {}\n    limit: int = 10\n    offset: int = 0\n    sort_by: str = "relevance"\n    include_content: bool = False\n\n# ===== MCP TOOL DEFINITIONS =====\n\nclass ChapterExtractionTool:\n    """MCP tool for chapter extraction."""\n\n    name = "extract_chapters"\n    description = "Extract chapters from documents with configurable patterns"\n\n    parameters = {\n        "type": "object",\n        "properties": {\n            "source": {\n                "type": "string",\n                "description": "File path, URL, or direct content"\n            },\n            "config": {\n                "type": "object",\n                "properties": {\n                    "chapter_pattern": {"type": "string"},\n                    "min_length": {"type": "integer"},\n                    "include_metadata": {"type": "boolean"}\n                }\n            },\n            "format": {\n                "type": "string",\n                "enum": ["json", "markdown", "html"]\n            }\n        },\n        "required": ["source"]\n    }\n\n    async def execute(self, source: str, config: dict = None, format: str = "json"):\n        """Execute chapter extraction."""\n        extractor = ChapterExtractor()\n        result = await extractor.extract(source, ExtractionConfig(**(config or {})))\n        return await extractor.export(result, ExportFormat(format))\n\nclass ChapterSearchTool:\n    """MCP tool for searching within extracted chapters."""\n\n    name = "search_chapters"\n    description = "Search through extracted chapters with advanced filtering"\n\n    parameters = {\n        "type": "object",\n        "properties": {\n            "query": {"type": "string"},\n            "filters": {"type": "object"},\n            "limit": {"type": "integer", "default": 10}\n        },\n        "required": ["query"]\n    }\n\n    async def execute(self, query: str, filters: dict = None, limit: int = 10):\n        """Execute chapter search."""\n        searcher = ChapterSearcher()\n        return await searcher.search(\n            SearchQuery(query=query, filters=filters or {}, limit=limit)\n        )\n\n# ===== CORE EXTRACTION ENGINE =====\n\nclass ChapterExtractor:\n    """Core chapter extraction engine."""\n\n    def __init__(self):\n        self.cache = CacheConfig.get_cache("chapter_extraction")\n        self.patterns_cache = {}\n\n    async def extract(\n        self,\n        source: Union[str, Path, UploadFile],\n        config: ExtractionConfig\n    ) -> List[Chapter]:\n        """Extract chapters from various sources."""\n        content = await self._load_content(source)\n        cache_key = self._generate_cache_key(content, config)\n\n        # Check cache\n        cached = await self.cache.get(cache_key)\n        if cached:\n            logger.info(f"Cache hit for extraction: {cache_key}")\n            return cached\n\n        # Perform extraction\n        chapters = await self._extract_chapters(content, config)\n\n        # Cache results\n        await self.cache.set(cache_key, chapters, ttl=3600)\n\n        return chapters\n\n    async def _load_content(self, source: Union[str, Path, UploadFile]) -> str:\n        """Load content from various sources."""\n        if isinstance(source, UploadFile):\n            content = await source.read()\n            return content.decode('utf-8', errors='ignore')\n        elif isinstance(source, Path) or (isinstance(source, str) and os.path.exists(source)):\n            async with aiofiles.open(source, 'r', encoding='utf-8') as f:\n                return await f.read()\n        elif isinstance(source, str) and source.startswith(('http://', 'https://')):\n            # Fetch from URL\n            import aiohttp\n            async with aiohttp.ClientSession() as session:\n                async with session.get(source) as response:\n                    return await response.text()\n        else:\n            # Assume direct content\n            return source\n\n    async def _extract_chapters(\n        self,\n        content: str,\n        config: ExtractionConfig\n    ) -> List[Chapter]:\n        """Extract chapters based on configuration."""\n        lines = content.split('\n')\n        chapters = []\n        current_chapter = None\n        current_content = []\n\n        # Compile patterns\n        chapter_pattern = re.compile(config.chapter_pattern, re.MULTILINE)\n        section_pattern = None\n        if config.section_pattern:\n            section_pattern = re.compile(config.section_pattern, re.MULTILINE)\n\n        for i, line in enumerate(lines):\n            # Check for chapter match\n            chapter_match = chapter_pattern.match(line)\n\n            if chapter_match:\n                # Save previous chapter\n                if current_chapter:\n                    current_chapter.content = '\n'.join(current_content)\n                    current_chapter.metadata.end_line = i - 1\n                    current_chapter.metadata.word_count = len(current_chapter.content.split())\n                    current_chapter.metadata.character_count = len(current_chapter.content)\n                    chapters.append(current_chapter)\n\n                # Start new chapter\n                current_chapter = Chapter(\n                    metadata=ChapterMetadata(\n                        title=line.strip(),\n                        number=self._extract_chapter_number(chapter_match),\n                        start_line=i,\n                        end_line=i,  # Will be updated\n                        word_count=0,  # Will be updated\n                        character_count=0  # Will be updated\n                    ),\n                    content=""\n                )\n                current_content = []\n            else:\n                # Add to current chapter content\n                if current_chapter:\n                    current_content.append(line)\n\n                    # Check for subsections if enabled\n                    if config.extract_subsections and section_pattern:\n                        section_match = section_pattern.match(line)\n                        if section_match:\n                            # Handle subsection extraction\n                            pass\n\n        # Save last chapter\n        if current_chapter:\n            current_chapter.content = '\n'.join(current_content)\n            current_chapter.metadata.end_line = len(lines) - 1\n            current_chapter.metadata.word_count = len(current_chapter.content.split())\n            current_chapter.metadata.character_count = len(current_chapter.content)\n            chapters.append(current_chapter)\n\n        # Apply filters\n        chapters = self._apply_filters(chapters, config)\n\n        return chapters\n\n    def _extract_chapter_number(self, match) -> Optional[int]:\n        """Extract chapter number from regex match."""\n        try:\n            # Try to find numeric group\n            for group in match.groups():\n                if group and group.isdigit():\n                    return int(group)\n        except:\n            pass\n        return None\n\n    def _apply_filters(\n        self,\n        chapters: List[Chapter],\n        config: ExtractionConfig\n    ) -> List[Chapter]:\n        """Apply length and other filters to chapters."""\n        filtered = []\n\n        for chapter in chapters:\n            # Apply min length filter\n            if len(chapter.content) < config.min_chapter_length:\n                logger.debug(f"Skipping chapter '{chapter.metadata.title}' - too short")\n                continue\n\n            # Apply max length filter\n            if config.max_chapter_length and len(chapter.content) > config.max_chapter_length:\n                logger.debug(f"Skipping chapter '{chapter.metadata.title}' - too long")\n                continue\n\n            filtered.append(chapter)\n\n        return filtered\n\n    def _generate_cache_key(self, content: str, config: ExtractionConfig) -> str:\n        """Generate cache key for extraction."""\n        content_hash = hashlib.md5(content.encode()).hexdigest()\n        config_hash = hashlib.md5(config.json().encode()).hexdigest()\n        return f"chapters:{content_hash}:{config_hash}"\n\n    async def export(\n        self,\n        chapters: List[Chapter],\n        format: ExportFormat\n    ) -> Union[str, bytes]:\n        """Export chapters in specified format."""\n        if format == ExportFormat.JSON:\n            return json.dumps([ch.dict() for ch in chapters], indent=2)\n        elif format == ExportFormat.MARKDOWN:\n            return self._export_markdown(chapters)\n        elif format == ExportFormat.HTML:\n            return self._export_html(chapters)\n        elif format == ExportFormat.PDF:\n            return await self._export_pdf(chapters)\n        elif format == ExportFormat.DOCX:\n            return await self._export_docx(chapters)\n        else:\n            raise ValueError(f"Unsupported format: {format}")\n\n    def _export_markdown(self, chapters: List[Chapter]) -> str:\n        """Export chapters as Markdown."""\n        md_content = []\n\n        for chapter in chapters:\n            # Add chapter heading\n            md_content.append(f"# {chapter.metadata.title}
")
            
            # Add metadata if available
            if chapter.metadata.tags:
                md_content.append(f"*Tags: {', '.join(chapter.metadata.tags)}*
")
            
            # Add content
            md_content.append(chapter.content)
            md_content.append("\n---
")
        
        return '
'.join(md_content)
    
    def _export_html(self, chapters: List[Chapter]) -> str:
        """Export chapters as HTML."""
        html_content = [
            "<!DOCTYPE html>",
            "<html><head>",
            "<title>Extracted Chapters</title>",
            "<style>",
            "body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }",
            "h1 { color: #333; border-bottom: 2px solid #333; padding-bottom: 10px; }",
            ".chapter { margin-bottom: 50px; }",
            ".metadata { color: #666; font-size: 0.9em; margin-bottom: 20px; }",
            "</style>",
            "</head><body>"
        ]
        
        for chapter in chapters:
            html_content.append('<div class="chapter">')
            html_content.append(f'<h1>{chapter.metadata.title}</h1>')
            
            if chapter.metadata.tags:
                html_content.append(f'<div class="metadata">Tags: {", ".join(chapter.metadata.tags)}</div>')
            
            # Convert content to paragraphs
            paragraphs = chapter.content.split('\n
')
            for para in paragraphs:
                if para.strip():
                    html_content.append(f'<p>{para.strip()}</p>')
            
            html_content.append('</div>')
        
        html_content.append("</body></html>")
        return '
'.join(html_content)
    
    async def _export_pdf(self, chapters: List[Chapter]) -> bytes:
        """Export chapters as PDF."""
        # Implementation would use a library like reportlab or weasyprint
        raise NotImplementedError("PDF export not yet implemented")
    
    async def _export_docx(self, chapters: List[Chapter]) -> bytes:
        """Export chapters as DOCX."""
        # Implementation would use python-docx
        raise NotImplementedError("DOCX export not yet implemented")

# ===== RESTFUL API ENDPOINTS =====

router = APIRouter(prefix="/api/v1/chapters", tags=["chapters"])

@router.post("/extract", response_model=ExtractionResponse)
@track_api_request("chapter_extraction")
async def extract_chapters(
    request: ExtractionRequest,
    background_tasks: BackgroundTasks,
    user=Depends(require_auth)
):
    """
    Extract chapters from a document.
    
    Supports multiple input sources:
    - Direct text content
    - File path
    - URL
    
    Can process synchronously or asynchronously.
    """
    job_id = str(uuid4())
    
    if request.async_processing:
        # Queue for background processing
        background_tasks.add_task(
            process_extraction_async,
            job_id,
            request
        )
        
        return ExtractionResponse(
            job_id=job_id,
            status=ProcessingStatus.PENDING,
            total_chapters=0
        )
    else:
        # Process synchronously
        try:
            extractor = ChapterExtractor()
            
            # Determine source
            source = request.content or request.file_path or request.url
            if not source:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="No content source provided"
                )
            
            # Extract chapters
            chapters = await extractor.extract(source, request.config)
            
            # Export if requested
            export_url = None
            if request.output_format != ExportFormat.JSON:
                exported = await extractor.export(chapters, request.output_format)
                # Store exported file and return URL
                export_url = await store_export(job_id, exported, request.output_format)
            
            return ExtractionResponse(
                job_id=job_id,
                status=ProcessingStatus.COMPLETED,
                chapters=chapters,
                total_chapters=len(chapters),
                export_url=export_url
            )
            
        except Exception as e:
            logger.error(f"Extraction failed: {str(e)}")
            return ExtractionResponse(
                job_id=job_id,
                status=ProcessingStatus.FAILED,
                error=str(e)
            )

@router.post("/extract/file", response_model=ExtractionResponse)
@track_api_request("chapter_extraction_file")
async def extract_chapters_from_file(
    file: UploadFile = File(...),
    config: str = Query(None, description="JSON-encoded extraction config"),
    output_format: ExportFormat = ExportFormat.JSON,
    user=Depends(require_auth)
):
    """Extract chapters from an uploaded file."""
    try:
        # Parse config if provided
        extraction_config = ExtractionConfig()
        if config:
            extraction_config = ExtractionConfig(**json.loads(config))
        
        # Create request
        request = ExtractionRequest(
            config=extraction_config,
            output_format=output_format
        )
        
        # Extract chapters
        extractor = ChapterExtractor()
        chapters = await extractor.extract(file, extraction_config)
        
        job_id = str(uuid4())
        
        return ExtractionResponse(
            job_id=job_id,
            status=ProcessingStatus.COMPLETED,
            chapters=chapters,
            total_chapters=len(chapters)
        )
        
    except Exception as e:
        logger.error(f"File extraction failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.post("/batch", response_model=List[ExtractionResponse])
@track_api_request("chapter_extraction_batch")
async def batch_extract_chapters(
    request: BatchExtractionRequest,
    background_tasks: BackgroundTasks,
    user=Depends(require_auth)
):
    """Extract chapters from multiple files in batch."""
    responses = []
    
    if request.parallel_processing:
        # Process files in parallel with concurrency limit
        semaphore = asyncio.Semaphore(request.max_concurrent)
        
        async def process_file(file_path):
            async with semaphore:
                job_id = str(uuid4())
                try:
                    extractor = ChapterExtractor()
                    chapters = await extractor.extract(file_path, request.config)
                    
                    return ExtractionResponse(
                        job_id=job_id,
                        status=ProcessingStatus.COMPLETED,
                        chapters=chapters,
                        total_chapters=len(chapters)
                    )
                except Exception as e:
                    return ExtractionResponse(
                        job_id=job_id,
                        status=ProcessingStatus.FAILED,
                        error=str(e)
                    )
        
        # Process all files
        tasks = [process_file(file_path) for file_path in request.files]
        responses = await asyncio.gather(*tasks)
    else:
        # Process sequentially
        for file_path in request.files:
            job_id = str(uuid4())
            try:
                extractor = ChapterExtractor()
                chapters = await extractor.extract(file_path, request.config)
                
                responses.append(ExtractionResponse(
                    job_id=job_id,
                    status=ProcessingStatus.COMPLETED,
                    chapters=chapters,
                    total_chapters=len(chapters)
                ))
            except Exception as e:
                responses.append(ExtractionResponse(
                    job_id=job_id,
                    status=ProcessingStatus.FAILED,
                    error=str(e)
                ))
    
    return responses

@router.get("/job/{job_id}", response_model=ExtractionResponse)
@track_api_request("chapter_extraction_status")
async def get_extraction_status(
    job_id: str,
    user=Depends(require_auth)
):
    """Get status of an extraction job."""
    # Retrieve job status from storage/cache
    job_status = await get_job_status(job_id)
    
    if not job_status:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job {job_id} not found"
        )
    
    return job_status

@router.post("/search", response_model=Dict[str, Any])
@track_api_request("chapter_search")
async def search_chapters(
    query: SearchQuery,
    user=Depends(require_auth)
):
    """Search through extracted chapters."""
    searcher = ChapterSearcher()
    results = await searcher.search(query)
    
    return {
        "query": query.query,
        "total_results": results["total"],
        "results": results["chapters"],
        "facets": results.get("facets", {})
    }

@router.get("/export/{job_id}/{format}")
@track_api_request("chapter_export")
async def export_chapters(
    job_id: str,
    format: ExportFormat,
    user=Depends(require_auth)
):
    """Export extracted chapters in specified format."""
    # Retrieve chapters for job
    job_status = await get_job_status(job_id)
    
    if not job_status or job_status.status != ProcessingStatus.COMPLETED:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chapters not found or extraction not completed"
        )
    
    extractor = ChapterExtractor()
    exported = await extractor.export(job_status.chapters, format)
    
    # Return appropriate response based on format
    if format == ExportFormat.JSON:
        return {"chapters": json.loads(exported)}
    else:
        # Return file response
        filename = f"chapters_{job_id}.{format.value}"
        media_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        
        return StreamingResponse(
            io.BytesIO(exported.encode() if isinstance(exported, str) else exported),
            media_type=media_type,
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

# ===== WEBSOCKET API =====

class ConnectionManager:
    """Manage WebSocket connections."""
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.subscriptions: Dict[str, List[str]] = {}
    
    async def connect(self, websocket: WebSocket, client_id: str):
        """Accept new WebSocket connection."""
        await websocket.accept()
        self.active_connections[client_id] = websocket
        self.subscriptions[client_id] = []
        logger.info(f"Client {client_id} connected")
    
    def disconnect(self, client_id: str):
        """Handle client disconnection."""
        if client_id in self.active_connections:
            del self.active_connections[client_id]
            del self.subscriptions[client_id]
            logger.info(f"Client {client_id} disconnected")
    
    async def send_message(self, client_id: str, message: dict):
        """Send message to specific client."""
        if client_id in self.active_connections:
            websocket = self.active_connections[client_id]
            try:
                await websocket.send_json(message)
            except Exception as e:
                logger.error(f"Error sending to {client_id}: {e}")
                self.disconnect(client_id)
    
    async def broadcast(self, message: dict, job_id: str = None):
        """Broadcast message to all connected clients or job subscribers."""
        disconnected = []
        
        for client_id, websocket in self.active_connections.items():
            # Check if client is subscribed to this job
            if job_id and job_id not in self.subscriptions.get(client_id, []):
                continue
            
            try:
                await websocket.send_json(message)
            except Exception as e:
                logger.error(f"Error broadcasting to {client_id}: {e}")
                disconnected.append(client_id)
        
        # Clean up disconnected clients
        for client_id in disconnected:
            self.disconnect(client_id)
    
    def subscribe(self, client_id: str, job_id: str):
        """Subscribe client to job updates."""
        if client_id in self.subscriptions:
            self.subscriptions[client_id].append(job_id)

manager = ConnectionManager()

@router.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    """WebSocket endpoint for real-time chapter extraction updates."""
    await manager.connect(websocket, client_id)
    
    try:
        while True:
            # Receive message from client
            data = await websocket.receive_json()
            
            # Handle different message types
            message_type = data.get("type")
            
            if message_type == "subscribe":
                # Subscribe to job updates
                job_id = data.get("job_id")
                if job_id:
                    manager.subscribe(client_id, job_id)
                    await manager.send_message(client_id, {
                        "type": "subscribed",
                        "job_id": job_id
                    })
            
            elif message_type == "extract":
                # Start extraction
                request_data = data.get("request", {})
                request = ExtractionRequest(**request_data)
                
                # Process extraction with progress updates
                job_id = str(uuid4())
                asyncio.create_task(
                    process_extraction_with_updates(
                        job_id, request, client_id
                    )
                )
                
                await manager.send_message(client_id, {
                    "type": "extraction_started",
                    "job_id": job_id
                })
            
            elif message_type == "ping":
                # Respond to ping
                await manager.send_message(client_id, {"type": "pong"})
            
    except WebSocketDisconnect:
        manager.disconnect(client_id)
    except Exception as e:
        logger.error(f"WebSocket error for {client_id}: {e}")
        manager.disconnect(client_id)

async def process_extraction_with_updates(
    job_id: str, 
    request: ExtractionRequest, 
    client_id: str
):
    """Process extraction with progress updates via WebSocket."""
    try:
        # Send initial update
        await manager.send_message(client_id, {
            "type": "progress",
            "job_id": job_id,
            "status": "loading",
            "progress": 10
        })
        
        extractor = ChapterExtractor()
        
        # Load content
        source = request.content or request.file_path or request.url
        await manager.send_message(client_id, {
            "type": "progress",
            "job_id": job_id,
            "status": "extracting",
            "progress": 30
        })
        
        # Extract chapters
        chapters = await extractor.extract(source, request.config)
        
        await manager.send_message(client_id, {
            "type": "progress",
            "job_id": job_id,
            "status": "processing",
            "progress": 70
        })
        
        # Export if needed
        export_url = None
        if request.output_format != ExportFormat.JSON:
            exported = await extractor.export(chapters, request.output_format)
            export_url = await store_export(job_id, exported, request.output_format)
        
        # Send completion
        await manager.send_message(client_id, {
            "type": "completed",
            "job_id": job_id,
            "result": {
                "status": "completed",
                "chapters": [ch.dict() for ch in chapters],
                "total_chapters": len(chapters),
                "export_url": export_url
            }
        })
        
    except Exception as e:
        # Send error
        await manager.send_message(client_id, {
            "type": "error",
            "job_id": job_id,
            "error": str(e)
        })

# ===== GRAPHQL SCHEMA =====

class ChapterGraphQL(ObjectType):
    """GraphQL type for Chapter."""
    id = String()
    title = String()
    number = Int()
    level = Int()
    content = String()
    word_count = Int()
    character_count = Int()
    tags = GrapheneList(String)
    subsections = GrapheneList(lambda: ChapterGraphQL)

class ExtractionConfigInput(InputObjectType):
    """GraphQL input type for extraction configuration."""
    chapter_pattern = String(default_value=r"^(Chapter|CHAPTER)\s+(\d+)")
    section_pattern = String()
    min_chapter_length = Int(default_value=100)
    max_chapter_length = Int()
    include_metadata = Boolean(default_value=True)
    preserve_formatting = Boolean(default_value=True)
    extract_subsections = Boolean(default_value=True)

class Query(ObjectType):
    """GraphQL queries for chapter extraction."""
    
    chapters = GrapheneList(
        ChapterGraphQL,
        job_id=String(required=True)
    )
    
    search_chapters = GrapheneList(
        ChapterGraphQL,
        query=String(required=True),
        limit=Int(default_value=10),
        offset=Int(default_value=0)
    )
    
    job_status = Field(
        lambda: JobStatus,
        job_id=String(required=True)
    )
    
    async def resolve_chapters(self, info, job_id):
        """Resolve chapters for a job."""
        job_status = await get_job_status(job_id)
        if job_status and job_status.chapters:
            return job_status.chapters
        return []
    
    async def resolve_search_chapters(self, info, query, limit=10, offset=0):
        """Search chapters."""
        searcher = ChapterSearcher()
        search_query = SearchQuery(
            query=query,
            limit=limit,
            offset=offset
        )
        results = await searcher.search(search_query)
        return results.get("chapters", [])
    
    async def resolve_job_status(self, info, job_id):
        """Get job status."""
        return await get_job_status(job_id)

class ExtractChaptersMutation(Mutation):
    """GraphQL mutation for extracting chapters."""
    
    class Arguments:
        source = String(required=True)
        config = ExtractionConfigInput()
        format = String(default_value="json")
    
    job_id = String()
    status = String()
    
    async def mutate(self, info, source, config=None, format="json"):
        """Execute chapter extraction."""
        job_id = str(uuid4())
        
        # Create extraction request
        extraction_config = ExtractionConfig()
        if config:
            extraction_config = ExtractionConfig(**config)
        
        request = ExtractionRequest(
            content=source,
            config=extraction_config,
            output_format=ExportFormat(format),
            async_processing=True
        )
        
        # Queue for processing
        asyncio.create_task(process_extraction_async(job_id, request))
        
        return ExtractChaptersMutation(
            job_id=job_id,
            status="pending"
        )

class Mutation(ObjectType):
    """GraphQL mutations."""
    extract_chapters = ExtractChaptersMutation.Field()

# Create GraphQL schema
graphql_schema = Schema(query=Query, mutation=Mutation)

# ===== EVENT-DRIVEN API =====

class FileMonitor:
    """Monitor files for changes and trigger extraction."""
    
    def __init__(self):
        self.watched_paths: Dict[str, ExtractionConfig] = {}
        self.event_handlers: Dict[str, List[callable]] = {}
        self._monitoring = False
    
    async def watch(
        self, 
        path: Union[str, Path], 
        config: ExtractionConfig,
        on_change: callable = None
    ):
        """Watch a file or directory for changes."""
        path = Path(path)
        self.watched_paths[str(path)] = config
        
        if on_change:
            if str(path) not in self.event_handlers:
                self.event_handlers[str(path)] = []
            self.event_handlers[str(path)].append(on_change)
        
        if not self._monitoring:
            asyncio.create_task(self._monitor_loop())
            self._monitoring = True
    
    async def _monitor_loop(self):
        """Main monitoring loop."""
        import aionotify
        
        watcher = aionotify.Watcher()
        
        # Add watches
        for path in self.watched_paths:
            watcher.watch(
                path,
                aionotify.Flags.MODIFY | aionotify.Flags.CREATE
            )
        
        # Start watching
        await watcher.setup()
        
        try:
            while self._monitoring:
                event = await watcher.get_event()
                await self._handle_event(event)
        finally:
            watcher.close()
    
    async def _handle_event(self, event):
        """Handle file system event."""
        file_path = event.path
        
        # Find matching watch
        for watched_path, config in self.watched_paths.items():
            if str(file_path).startswith(watched_path):
                # Extract chapters from changed file
                extractor = ChapterExtractor()
                chapters = await extractor.extract(file_path, config)
                
                # Notify handlers
                handlers = self.event_handlers.get(watched_path, [])
                for handler in handlers:
                    await handler({
                        "event": "file_changed",
                        "path": str(file_path),
                        "chapters": chapters
                    })
                
                # Broadcast via WebSocket
                await manager.broadcast({
                    "type": "file_changed",
                    "path": str(file_path),
                    "chapters": [ch.dict() for ch in chapters]
                })

# ===== SEARCH AND FILTERING =====

class ChapterSearcher:
    """Advanced chapter search functionality."""
    
    def __init__(self):
        self.index = {}  # Simple in-memory index
    
    async def index_chapters(self, job_id: str, chapters: List[Chapter]):
        """Index chapters for searching."""
        for chapter in chapters:
            # Create searchable document
            doc = {
                "job_id": job_id,
                "chapter_id": chapter.metadata.id,
                "title": chapter.metadata.title,
                "content": chapter.content,
                "tags": chapter.metadata.tags,
                "word_count": chapter.metadata.word_count
            }
            
            # Add to index
            self.index[chapter.metadata.id] = doc
    
    async def search(self, query: SearchQuery) -> Dict[str, Any]:
        """Search indexed chapters."""
        results = []
        
        # Simple text search (in production, use Elasticsearch or similar)
        query_lower = query.query.lower()
        
        for doc_id, doc in self.index.items():
            # Check title and content
            if (query_lower in doc["title"].lower() or 
                query_lower in doc["content"].lower()):
                
                # Apply filters
                if self._match_filters(doc, query.filters):
                    results.append(doc)
        
        # Sort results
        results = self._sort_results(results, query.sort_by)
        
        # Paginate
        total = len(results)
        results = results[query.offset:query.offset + query.limit]
        
        # Format response
        return {
            "total": total,
            "chapters": results,
            "facets": self._calculate_facets(results)
        }
    
    def _match_filters(self, doc: dict, filters: dict) -> bool:
        """Check if document matches filters."""
        for key, value in filters.items():
            if key == "min_words" and doc["word_count"] < value:
                return False
            elif key == "max_words" and doc["word_count"] > value:
                return False
            elif key == "tags" and not any(tag in doc["tags"] for tag in value):
                return False
        return True
    
    def _sort_results(self, results: list, sort_by: str) -> list:
        """Sort search results."""
        if sort_by == "relevance":
            # Simple relevance scoring
            return results
        elif sort_by == "word_count":
            return sorted(results, key=lambda x: x["word_count"], reverse=True)
        elif sort_by == "title":
            return sorted(results, key=lambda x: x["title"])
        return results
    
    def _calculate_facets(self, results: list) -> dict:
        """Calculate search facets."""
        facets = {
            "tags": {},
            "word_count_ranges": {
                "0-1000": 0,
                "1000-5000": 0,
                "5000-10000": 0,
                "10000+": 0
            }
        }
        
        for result in results:
            # Count tags
            for tag in result.get("tags", []):
                facets["tags"][tag] = facets["tags"].get(tag, 0) + 1
            
            # Count word ranges
            word_count = result["word_count"]
            if word_count < 1000:
                facets["word_count_ranges"]["0-1000"] += 1
            elif word_count < 5000:
                facets["word_count_ranges"]["1000-5000"] += 1
            elif word_count < 10000:
                facets["word_count_ranges"]["5000-10000"] += 1
            else:
                facets["word_count_ranges"]["10000+"] += 1
        
        return facets

# ===== HELPER FUNCTIONS =====

async def process_extraction_async(job_id: str, request: ExtractionRequest):
    """Process extraction asynchronously."""
    try:
        # Update status
        await update_job_status(job_id, ProcessingStatus.PROCESSING)
        
        extractor = ChapterExtractor()
        source = request.content or request.file_path or request.url
        
        # Extract chapters
        chapters = await extractor.extract(source, request.config)
        
        # Index for search
        searcher = ChapterSearcher()
        await searcher.index_chapters(job_id, chapters)
        
        # Export if needed
        export_url = None
        if request.output_format != ExportFormat.JSON:
            exported = await extractor.export(chapters, request.output_format)
            export_url = await store_export(job_id, exported, request.output_format)
        
        # Update final status
        await update_job_status(
            job_id, 
            ProcessingStatus.COMPLETED,
            chapters=chapters,
            export_url=export_url
        )
        
    except Exception as e:
        logger.error(f"Async extraction failed: {str(e)}")
        await update_job_status(
            job_id,
            ProcessingStatus.FAILED,
            error=str(e)
        )

async def get_job_status(job_id: str) -> Optional[ExtractionResponse]:
    """Get job status from storage."""
    # Implementation would retrieve from Redis/database
    # For now, return mock data
    return None

async def update_job_status(
    job_id: str, 
    status: ProcessingStatus,
    chapters: List[Chapter] = None,
    export_url: str = None,
    error: str = None
):
    """Update job status in storage."""
    # Implementation would update Redis/database
    pass

async def store_export(
    job_id: str, 
    content: Union[str, bytes], 
    format: ExportFormat
) -> str:
    """Store exported content and return URL."""
    # Implementation would store in S3/filesystem
    # For now, return mock URL
    return f"/api/v1/chapters/download/{job_id}.{format.value}"

# ===== RATE LIMITING AND CACHING =====

# Rate limiter instance
rate_limiter = RateLimiter(
    max_requests_per_minute=60,
    max_requests_per_hour=1000
)

# Apply rate limiting to endpoints
@router.middleware("http")
async def rate_limit_middleware(request, call_next):
    """Apply rate limiting to API requests."""
    # Get client identifier (IP or API key)
    client_id = request.headers.get("X-API-Key", request.client.host)
    
    # Check rate limit
    if not await rate_limiter.check(client_id):
        return JSONResponse(
            status_code=429,
            content={"error": "Rate limit exceeded"},
            headers={"Retry-After": "60"}
        )
    
    # Process request
    response = await call_next(request)
    return response

# ===== API DOCUMENTATION =====

api_description = """
# Chapter Extraction API

This API provides comprehensive chapter extraction capabilities with multiple interfaces:

## Features

- **Multiple Input Sources**: Files, URLs, or direct text
- **Flexible Extraction**: Customizable patterns and filters
- **Multiple Output Formats**: JSON, Markdown, HTML, PDF, DOCX
- **Real-time Updates**: WebSocket support for live progress
- **Batch Processing**: Extract from multiple files efficiently
- **Advanced Search**: Full-text search with faceted filtering
- **GraphQL Support**: Flexible queries for complex needs
- **Event-driven**: File monitoring with automatic extraction

## Authentication

All endpoints require authentication via API key in the `X-API-Key` header.

## Rate Limits

- 60 requests per minute
- 1000 requests per hour

## Versioning

This API uses URL versioning. Current version: v1

## Export Formats

- `json`: Structured JSON with metadata
- `markdown`: Human-readable Markdown
- `html`: Styled HTML document
- `pdf`: Formatted PDF (coming soon)
- `docx`: Microsoft Word document (coming soon)
"""

# Create FastAPI app with the router
app = FastAPI(
    title="Chapter Extraction API",
    description=api_description,
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

app.include_router(router)

# Add GraphQL endpoint
from starlette.graphql import GraphQLApp
app.add_route("/api/v1/graphql", GraphQLApp(schema=graphql_schema))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)