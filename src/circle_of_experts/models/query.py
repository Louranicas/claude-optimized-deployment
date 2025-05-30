"""
Query model for Circle of Experts system.

Defines the structure and validation for expert queries.
"""

from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, List, Any
from pydantic import BaseModel, Field, validator
import uuid


class QueryPriority(str, Enum):
    """Priority levels for expert queries."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class QueryType(str, Enum):
    """Types of queries that can be submitted."""
    TECHNICAL = "technical"
    ARCHITECTURAL = "architectural"
    OPTIMIZATION = "optimization"
    REVIEW = "review"
    RESEARCH = "research"
    GENERAL = "general"


class ExpertQuery(BaseModel):
    """
    Represents a query to be submitted to the circle of experts.
    
    Attributes:
        id: Unique identifier for the query
        title: Brief title of the query
        content: Detailed query content
        query_type: Type of query being submitted
        priority: Priority level of the query
        context: Additional context for the experts
        constraints: Any constraints or requirements
        expected_format: Expected format of the response
        requester: Identity of the requester
        created_at: Timestamp of query creation
        deadline: Optional deadline for responses
        tags: Tags for categorization
        metadata: Additional metadata
    """
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str = Field(..., min_length=1, max_length=200)
    content: str = Field(..., min_length=10, max_length=10000)
    query_type: QueryType = Field(default=QueryType.GENERAL)
    priority: QueryPriority = Field(default=QueryPriority.MEDIUM)
    context: Optional[Dict[str, Any]] = Field(default_factory=dict)
    constraints: List[str] = Field(default_factory=list)
    expected_format: str = Field(default="markdown")
    requester: str = Field(..., min_length=1)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    deadline: Optional[datetime] = None
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    @validator('deadline')
    def validate_deadline(cls, v: Optional[datetime], values: dict) -> Optional[datetime]:
        """Ensure deadline is in the future."""
        if v and 'created_at' in values:
            if v <= values['created_at']:
                raise ValueError("Deadline must be after creation time")
        return v
    
    @validator('tags')
    def validate_tags(cls, v: List[str]) -> List[str]:
        """Ensure tags are lowercase and unique."""
        return list(set(tag.lower().strip() for tag in v if tag.strip()))
    
    def to_markdown(self) -> str:
        """
        Convert query to markdown format for file storage.
        
        Returns:
            Formatted markdown string
        """
        md_lines = [
            f"# {self.title}",
            f"",
            f"**Query ID:** {self.id}",
            f"**Type:** {self.query_type.value}",
            f"**Priority:** {self.priority.value}",
            f"**Requester:** {self.requester}",
            f"**Created:** {self.created_at.isoformat()}",
        ]
        
        if self.deadline:
            md_lines.append(f"**Deadline:** {self.deadline.isoformat()}")
        
        if self.tags:
            md_lines.append(f"**Tags:** {', '.join(self.tags)}")
        
        md_lines.extend([
            f"",
            f"## Query",
            f"",
            self.content,
            f"",
        ])
        
        if self.context:
            md_lines.extend([
                f"## Context",
                f"",
                "```json",
                str(self.context),
                "```",
                f"",
            ])
        
        if self.constraints:
            md_lines.extend([
                f"## Constraints",
                f"",
            ])
            for constraint in self.constraints:
                md_lines.append(f"- {constraint}")
            md_lines.append("")
        
        md_lines.extend([
            f"## Expected Response Format",
            f"",
            f"{self.expected_format}",
            f"",
        ])
        
        return "\n".join(md_lines)
    
    @classmethod
    def from_markdown(cls, markdown: str, metadata: Optional[Dict[str, Any]] = None) -> ExpertQuery:
        """
        Parse a query from markdown format.
        
        Args:
            markdown: Markdown content to parse
            metadata: Additional metadata to include
            
        Returns:
            ExpertQuery instance
        """
        # This is a simplified parser - in production, use a proper markdown parser
        lines = markdown.strip().split('\n')
        
        # Extract basic fields from markdown
        # This would need more robust parsing in production
        title = lines[0].replace('# ', '').strip()
        
        # Create query with parsed data
        return cls(
            title=title,
            content=markdown,  # Store full content for now
            metadata=metadata or {}
        )
    
    class Config:
        """Pydantic configuration."""
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
