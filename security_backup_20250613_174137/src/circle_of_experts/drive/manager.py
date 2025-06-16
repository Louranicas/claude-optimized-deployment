"""
Google Drive integration for Circle of Experts.

Handles file operations with the shared Google Drive folder.
"""

from __future__ import annotations
import os
import json
import asyncio
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime
import logging

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
from googleapiclient.errors import HttpError
import io

from src.circle_of_experts.models.query import ExpertQuery
from src.circle_of_experts.models.response import ExpertResponse, ExpertType
from src.circle_of_experts.utils.retry import RetryPolicy, with_retry

__all__ = [
    "DriveManager"
]


logger = logging.getLogger(__name__)


class DriveManager:
    """
    Manages Google Drive operations for the Circle of Experts.
    
    This class handles authentication, file uploads/downloads, and folder monitoring
    for the expert query/response system.
    """
    
    def __init__(
        self,
        credentials_path: Optional[str] = None,
        queries_folder_id: str = "1ob-NYNWMXaE3oiyPzRAk2-VpNbMvfFMS",
        responses_folder_id: str = "1YWh7lD1x8z8HrF-1FS6qPCw64ZQwvUHv",
        scopes: Optional[List[str]] = None
    ):
        """
        Initialize the Drive Manager.
        
        Args:
            credentials_path: Path to service account credentials JSON
            queries_folder_id: ID of the queries folder in Drive
            responses_folder_id: ID of the responses folder in Drive
            scopes: OAuth scopes for Drive access
        """
        self.credentials_path = credentials_path or os.getenv("GOOGLE_CREDENTIALS_PATH")
        self.queries_folder_id = queries_folder_id
        self.responses_folder_id = responses_folder_id
        self.scopes = scopes or ['https://www.googleapis.com/auth/drive']
        
        self._service = None
        self._retry_policy = RetryPolicy(max_attempts=3, backoff_factor=2.0)
    
    @property
    def service(self):
        """Lazy-load Drive service."""
        if self._service is None:
            self._service = self._build_service()
        return self._service
    
    def _build_service(self):
        """Build Google Drive service with credentials."""
        if not self.credentials_path:
            raise ValueError("Google credentials path not provided")
        
        if not os.path.exists(self.credentials_path):
            raise FileNotFoundError(f"Credentials file not found: {self.credentials_path}")
        
        credentials = service_account.Credentials.from_service_account_file(
            self.credentials_path,
            scopes=self.scopes
        )
        
        return build('drive', 'v3', credentials=credentials)
    
    @with_retry()
    async def ensure_responses_folder(self) -> str:
        """
        Ensure the responses folder exists and return its ID.
        
        Returns:
            ID of the responses folder
        """
        if self._responses_folder_id:
            return self._responses_folder_id
        
        # Search for existing folder
        query = (
            f"name='{self.responses_folder_name}' and "
            f"'{self.queries_folder_id}' in parents and "
            f"mimeType='application/vnd.google-apps.folder' and "
            f"trashed=false"
        )
        
        results = await asyncio.to_thread(
            self.service.files().list(q=query, fields="files(id, name)").execute
        )
        
        files = results.get('files', [])
        
        if files:
            self._responses_folder_id = files[0]['id']
            logger.info(f"Found existing responses folder: {self._responses_folder_id}")
        else:
            # Create the folder
            file_metadata = {
                'name': self.responses_folder_name,
                'mimeType': 'application/vnd.google-apps.folder',
                'parents': [self.queries_folder_id]
            }
            
            folder = await asyncio.to_thread(
                self.service.files().create(body=file_metadata, fields='id').execute
            )
            
            self._responses_folder_id = folder.get('id')
            logger.info(f"Created responses folder: {self._responses_folder_id}")
        
        return self._responses_folder_id
    
    @with_retry()
    async def upload_query(self, query: ExpertQuery) -> str:
        """
        Upload a query to Google Drive.
        
        Args:
            query: The query to upload
            
        Returns:
            File ID of the uploaded query
        """
        filename = f"query_{query.id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md"
        content = query.to_markdown()
        
        # Create temporary file
        temp_path = Path(f"/tmp/{filename}")
        temp_path.write_text(content, encoding='utf-8')
        
        try:
            file_metadata = {
                'name': filename,
                'parents': [self.queries_folder_id],
                'description': f"Expert query: {query.title}"
            }
            
            media = MediaFileUpload(
                str(temp_path),
                mimetype='text/markdown',
                resumable=True
            )
            
            file = await asyncio.to_thread(
                self.service.files().create(
                    body=file_metadata,
                    media_body=media,
                    fields='id'
                ).execute
            )
            
            file_id = file.get('id')
            logger.info(f"Uploaded query {query.id} as file {file_id}")
            return file_id
            
        finally:
            # Clean up temp file
            if temp_path.exists():
                temp_path.unlink()
    
    @with_retry()
    async def list_queries(self, max_results: int = 100) -> List[Dict[str, Any]]:
        """
        List query files in the queries folder.
        
        Args:
            max_results: Maximum number of results to return
            
        Returns:
            List of file metadata dictionaries
        """
        query = (
            f"'{self.queries_folder_id}' in parents and "
            f"name contains 'query_' and "
            f"mimeType='text/markdown' and "
            f"trashed=false"
        )
        
        results = await asyncio.to_thread(
            self.service.files().list(
                q=query,
                pageSize=max_results,
                fields="files(id, name, createdTime, modifiedTime, description)"
            ).execute
        )
        
        return results.get('files', [])
    
    @with_retry()
    async def download_file(self, file_id: str) -> str:
        """
        Download a file's content from Drive.
        
        Args:
            file_id: ID of the file to download
            
        Returns:
            Content of the file as string
        """
        request = self.service.files().get_media(fileId=file_id)
        fh = io.BytesIO()
        
        downloader = MediaIoBaseDownload(fh, request)
        done = False
        
        while not done:
            status, done = await asyncio.to_thread(downloader.next_chunk)
            if status:
                logger.debug(f"Download {int(status.progress() * 100)}% complete")
        
        content = fh.getvalue().decode('utf-8')
        return content
    
    @with_retry()
    async def upload_response(self, response: ExpertResponse) -> str:
        """
        Upload an expert response to the responses folder.
        
        Args:
            response: The response to upload
            
        Returns:
            File ID of the uploaded response
        """
        filename = (
            f"response_{response.expert_type.value}_{response.query_id}_"
            f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md"
        )
        content = response.to_markdown()
        
        # Create temporary file
        temp_path = Path(f"/tmp/{filename}")
        temp_path.write_text(content, encoding='utf-8')
        
        try:
            file_metadata = {
                'name': filename,
                'parents': [self.responses_folder_id],
                'description': f"Response from {response.expert_type.value} for query {response.query_id}"
            }
            
            media = MediaFileUpload(
                str(temp_path),
                mimetype='text/markdown',
                resumable=True
            )
            
            file = await asyncio.to_thread(
                self.service.files().create(
                    body=file_metadata,
                    media_body=media,
                    fields='id'
                ).execute
            )
            
            file_id = file.get('id')
            logger.info(f"Uploaded response from {response.expert_type.value} as file {file_id}")
            return file_id
            
        finally:
            # Clean up temp file
            if temp_path.exists():
                temp_path.unlink()
    
    @with_retry()
    async def list_responses(self, query_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List response files, optionally filtered by query ID.
        
        Args:
            query_id: Optional query ID to filter responses
            
        Returns:
            List of response file metadata
        """
        query_parts = [
            f"'{self.responses_folder_id}' in parents",
            f"name contains 'response_'",
            f"mimeType='text/markdown'",
            f"trashed=false"
        ]
        
        if query_id:
            query_parts.append(f"name contains '{query_id}'")
        
        query = " and ".join(query_parts)
        
        results = await asyncio.to_thread(
            self.service.files().list(
                q=query,
                fields="files(id, name, createdTime, modifiedTime, description)"
            ).execute
        )
        
        return results.get('files', [])
    
    async def watch_for_responses(
        self,
        query_id: str,
        timeout: float = 300.0,
        poll_interval: float = 10.0
    ) -> List[ExpertResponse]:
        """
        Watch for new responses to a specific query.
        
        Args:
            query_id: ID of the query to watch responses for
            timeout: Maximum time to wait for responses (seconds)
            poll_interval: How often to check for new responses
            
        Returns:
            List of new responses found
        """
        start_time = asyncio.get_event_loop().time()
        seen_files = set()
        responses = []
        
        while (asyncio.get_event_loop().time() - start_time) < timeout:
            try:
                # List current responses
                response_files = await self.list_responses(query_id)
                
                for file in response_files:
                    file_id = file['id']
                    if file_id not in seen_files:
                        seen_files.add(file_id)
                        
                        # Download and parse the response
                        content = await self.download_file(file_id)
                        
                        # Extract expert type from filename
                        filename = file['name']
                        for expert_type in ExpertType:
                            if expert_type.value in filename:
                                response = ExpertResponse.from_markdown(
                                    content,
                                    expert_type,
                                    query_id
                                )
                                responses.append(response)
                                logger.info(f"Found new response from {expert_type.value}")
                                break
                
            except Exception as e:
                logger.error(f"Error checking for responses: {e}")
            
            # Wait before next poll
            await asyncio.sleep(poll_interval)
        
        return responses
