"""
Response model for Circle of Experts system.

Defines the structure and validation for expert responses.
"""

from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, List, Any
from pydantic import BaseModel, Field, validator
import uuid

__all__ = [
    "ExpertType",
    "ResponseStatus",
    "ExpertResponse",
    "ConsensusResponse"
]



class ExpertType(str, Enum):
    """Types of AI experts in the circle."""
    CLAUDE = "claude"
    GPT4 = "gpt4"
    GEMINI = "gemini"
    SUPERGROK = "supergrok"
    DEEPSEEK = "deepseek"
    HUMAN = "human"  # For manual expert responses
    
    # Backwards compatibility aliases
    TECHNICAL = "claude"  # Maps to Claude for technical expertise
    DOMAIN = "gpt4"  # Maps to GPT-4 for domain knowledge
    INTEGRATION = "gemini"  # Maps to Gemini for integration
    PERFORMANCE = "deepseek"  # Maps to DeepSeek for performance optimization
    RESEARCH = "supergrok"  # Maps to SuperGrok for research
    INFRASTRUCTURE = "claude"  # Maps to Claude for infrastructure
    SECURITY = "gpt4"  # Maps to GPT-4 for security
    ARCHITECTURAL = "gemini"  # Maps to Gemini for architecture


class ResponseStatus(str, Enum):
    """Status of an expert response."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class ExpertResponse(BaseModel):
    """
    Represents a response from an expert in the circle.
    
    Attributes:
        id: Unique identifier for the response
        query_id: ID of the query being responded to
        expert_type: Type of expert providing the response
        content: The actual response content
        confidence: Confidence level of the response (0-1)
        status: Current status of the response
        created_at: When the response was created
        completed_at: When the response was completed
        processing_time: Time taken to generate response (seconds)
        references: Any references or sources cited
        code_snippets: Code snippets included in response
        recommendations: Specific recommendations made
        limitations: Any limitations or caveats
        metadata: Additional metadata
    """
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    query_id: str = Field(..., min_length=1)
    expert_type: ExpertType
    content: str = Field(default="")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    status: ResponseStatus = Field(default=ResponseStatus.PENDING)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    processing_time: Optional[float] = None
    references: List[str] = Field(default_factory=list)
    code_snippets: List[Dict[str, str]] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    @validator('completed_at')
    def validate_completed_at(cls, v: Optional[datetime], values: dict) -> Optional[datetime]:
        """Ensure completion time is after creation time."""
        if v and 'created_at' in values:
            if v < values['created_at']:
                raise ValueError("Completion time must be after creation time")
        return v
    
    @validator('processing_time')
    def validate_processing_time(cls, v: Optional[float]) -> Optional[float]:
        """Ensure processing time is positive."""
        if v is not None and v < 0:
            raise ValueError("Processing time must be positive")
        return v
    
    @validator('code_snippets')
    def validate_code_snippets(cls, v: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """Validate code snippet structure."""
        for snippet in v:
            if not isinstance(snippet, dict):
                raise ValueError("Each code snippet must be a dictionary")
            if 'language' not in snippet or 'code' not in snippet:
                raise ValueError("Code snippets must have 'language' and 'code' fields")
        return v
    
    def to_markdown(self) -> str:
        """
        Convert response to markdown format for file storage.
        
        Returns:
            Formatted markdown string
        """
        md_lines = [
            f"# Expert Response: {self.expert_type.value.upper()}",
            f"",
            f"**Response ID:** {self.id}",
            f"**Query ID:** {self.query_id}",
            f"**Status:** {self.status.value}",
            f"**Confidence:** {self.confidence:.2f}",
            f"**Created:** {self.created_at.isoformat()}",
        ]
        
        if self.completed_at:
            md_lines.append(f"**Completed:** {self.completed_at.isoformat()}")
        
        if self.processing_time:
            md_lines.append(f"**Processing Time:** {self.processing_time:.2f}s")
        
        md_lines.extend([
            f"",
            f"## Response",
            f"",
            self.content,
            f"",
        ])
        
        if self.code_snippets:
            md_lines.extend([
                f"## Code Examples",
                f"",
            ])
            for i, snippet in enumerate(self.code_snippets, 1):
                title = snippet.get('title', f'Example {i}')
                md_lines.extend([
                    f"### {title}",
                    f"",
                    f"```{snippet['language']}",
                    snippet['code'],
                    f"```",
                    f"",
                ])
        
        if self.recommendations:
            md_lines.extend([
                f"## Recommendations",
                f"",
            ])
            for rec in self.recommendations:
                md_lines.append(f"- {rec}")
            md_lines.append("")
        
        if self.limitations:
            md_lines.extend([
                f"## Limitations",
                f"",
            ])
            for limitation in self.limitations:
                md_lines.append(f"- {limitation}")
            md_lines.append("")
        
        if self.references:
            md_lines.extend([
                f"## References",
                f"",
            ])
            for ref in self.references:
                md_lines.append(f"- {ref}")
            md_lines.append("")
        
        return "\n".join(md_lines)
    
    @classmethod
    def from_markdown(cls, markdown: str, expert_type: ExpertType, query_id: str) -> ExpertResponse:
        """
        Parse a response from markdown format.
        
        Args:
            markdown: Markdown content to parse
            expert_type: Type of expert that created this response
            query_id: ID of the query being responded to
            
        Returns:
            ExpertResponse instance
        """
        # Simplified parser - production would use proper markdown parsing
        return cls(
            query_id=query_id,
            expert_type=expert_type,
            content=markdown,
            status=ResponseStatus.COMPLETED
        )
    
    def mark_completed(self) -> None:
        """Mark the response as completed."""
        self.status = ResponseStatus.COMPLETED
        self.completed_at = datetime.utcnow()
        if self.created_at:
            self.processing_time = (self.completed_at - self.created_at).total_seconds()
    
    def mark_failed(self, reason: str) -> None:
        """Mark the response as failed."""
        self.status = ResponseStatus.FAILED
        self.limitations.append(f"Failed: {reason}")
        self.completed_at = datetime.utcnow()
    
    class Config:
        """Pydantic configuration."""
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class ConsensusResponse(BaseModel):
    """
    Represents a consensus built from multiple expert responses.
    
    Attributes:
        query_id: ID of the original query
        average_confidence: Average confidence across all responses
        participating_experts: List of experts who responded
        common_recommendations: Recommendations that appeared frequently
        unique_limitations: All unique limitations mentioned
        consensus_level: Overall consensus level (high/medium/low)
        consensus_analysis: Detailed analysis from Rust module (if available)
    """
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    query_id: str
    average_confidence: float = Field(ge=0.0, le=1.0)
    participating_experts: List[ExpertType]
    common_recommendations: List[str] = Field(default_factory=list)
    unique_limitations: List[str] = Field(default_factory=list)
    consensus_level: str = "medium"
    consensus_analysis: Optional[Dict[str, Any]] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "query_id": self.query_id,
            "average_confidence": self.average_confidence,
            "participating_experts": [e.value for e in self.participating_experts],
            "common_recommendations": self.common_recommendations,
            "unique_limitations": self.unique_limitations,
            "consensus_level": self.consensus_level,
            "consensus_analysis": self.consensus_analysis,
            "created_at": self.created_at.isoformat()
        }
    
    class Config:
        """Pydantic configuration."""
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
