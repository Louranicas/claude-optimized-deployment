"""
Integration module for Hyper Narrative Synthor
Seamlessly integrates academic search into the writing workflow
"""

import asyncio
from typing import List, Dict, Optional, Any, Callable
from dataclasses import dataclass
import logging
from datetime import datetime

from .bridge import AcademicMCPBridge, Paper, CitationStyle

logger = logging.getLogger(__name__)


@dataclass
class CitationContext:
    """Context for citation insertion"""
    selected_text: str
    cursor_position: int
    current_paragraph: str
    document_id: str
    citation_style: CitationStyle


class SynthorAcademicIntegration:
    """
    Integration layer for Hyper Narrative Synthor
    Provides real-time academic search and citation capabilities
    """
    
    def __init__(self, synthor_instance: Any):
        self.synthor = synthor_instance
        self.bridge = AcademicMCPBridge()
        self.active_searches = {}
        self.reference_library = {}
        self._setup_hooks()
        
    def _setup_hooks(self):
        """Setup integration hooks with Synthor"""
        # Register event handlers
        self.synthor.on_text_selection = self.handle_text_selection
        self.synthor.on_citation_request = self.handle_citation_request
        self.synthor.on_reference_list_update = self.handle_reference_update
        self.synthor.on_export_bibliography = self.handle_bibliography_export
        
    async def handle_text_selection(self, selection: str, context: Dict):
        """
        Handle text selection for potential citation
        Provides intelligent citation suggestions
        """
        if len(selection) < 10:  # Ignore very short selections
            return
            
        # Extract potential search terms
        search_query = self._extract_search_terms(selection)
        
        # Perform background search
        search_id = f"search_{datetime.now().timestamp()}"
        self.active_searches[search_id] = asyncio.create_task(
            self._background_search(search_query, search_id)
        )
        
        # Notify UI of pending search
        await self.synthor.notify_search_started(search_id)
        
    async def _background_search(self, query: str, search_id: str):
        """Perform search in background"""
        try:
            results = await self.bridge.search(query, limit=5)
            
            # Process results for UI display
            suggestions = []
            for paper in results:
                suggestion = {
                    "id": paper.id,
                    "title": paper.title,
                    "authors": paper.authors[:3],  # First 3 authors
                    "year": paper.year,
                    "relevance_score": self._calculate_relevance(query, paper)
                }
                suggestions.append(suggestion)
            
            # Sort by relevance
            suggestions.sort(key=lambda x: x["relevance_score"], reverse=True)
            
            # Notify UI of results
            await self.synthor.display_citation_suggestions(search_id, suggestions)
            
        except Exception as e:
            logger.error(f"Background search failed: {e}")
            await self.synthor.notify_search_failed(search_id, str(e))
        finally:
            del self.active_searches[search_id]
    
    async def handle_citation_request(self, paper_id: str, context: CitationContext):
        """
        Insert citation at current position
        Handles both in-text citation and reference list update
        """
        # Get paper details
        paper = await self.bridge.get_paper(paper_id)
        if not paper:
            logger.error(f"Paper not found: {paper_id}")
            return
            
        # Format citation
        citation_text = await self.bridge.format_citation(paper, context.citation_style)
        
        # Insert in-text citation
        in_text_citation = self._format_in_text_citation(paper, context.citation_style)
        await self.synthor.insert_text_at_cursor(in_text_citation)
        
        # Add to reference library
        self.reference_library[paper.id] = {
            "paper": paper,
            "citation": citation_text,
            "used_count": 1,
            "first_used": datetime.now()
        }
        
        # Update reference list
        await self._update_reference_list()
        
    def _format_in_text_citation(self, paper: Paper, style: CitationStyle) -> str:
        """Format in-text citation based on style"""
        if style == CitationStyle.APA:
            if paper.authors:
                first_author = paper.authors[0].split()[-1]  # Last name
                return f"({first_author}, {paper.year})"
            return f"({paper.title[:20]}..., {paper.year})"
        elif style == CitationStyle.MLA:
            if paper.authors:
                first_author = paper.authors[0].split()[-1]
                return f"({first_author})"
            return f"({paper.title[:20]}...)"
        else:
            return f"[{len(self.reference_library) + 1}]"
    
    async def _update_reference_list(self):
        """Update document reference list"""
        # Sort references by first use
        sorted_refs = sorted(
            self.reference_library.items(),
            key=lambda x: x[1]["first_used"]
        )
        
        # Format reference list
        reference_text = "\n\nReferences\n\n"
        for i, (paper_id, ref_data) in enumerate(sorted_refs, 1):
            reference_text += f"{i}. {ref_data['citation']}\n"
        
        # Update in document
        await self.synthor.update_reference_section(reference_text)
    
    def _extract_search_terms(self, text: str) -> str:
        """Extract meaningful search terms from selected text"""
        # Simple implementation - can be enhanced with NLP
        import re
        
        # Remove common words
        stopwords = {"the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for"}
        words = re.findall(r'\w+', text.lower())
        keywords = [w for w in words if w not in stopwords and len(w) > 3]
        
        return " ".join(keywords[:5])  # Top 5 keywords
    
    def _calculate_relevance(self, query: str, paper: Paper) -> float:
        """Calculate relevance score for ranking"""
        score = 0.0
        query_lower = query.lower()
        
        # Title match
        if query_lower in paper.title.lower():
            score += 0.5
            
        # Abstract match
        if paper.abstract and query_lower in paper.abstract.lower():
            score += 0.3
            
        # Recent papers get slight boost
        if paper.year and paper.year >= 2020:
            score += 0.1
            
        # High citation count boost
        if paper.citations and paper.citations > 100:
            score += 0.1
            
        return score
