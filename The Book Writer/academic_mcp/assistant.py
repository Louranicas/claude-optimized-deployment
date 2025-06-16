"""
Academic Assistant for Hyper Narrative Synthor
AI-powered academic writing assistance with real-time search
"""

import asyncio
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass
import logging
from datetime import datetime
import re

from .bridge import AcademicMCPBridge, Paper, CitationStyle
from .synthor_integration import SynthorAcademicIntegration

logger = logging.getLogger(__name__)


@dataclass
class WritingContext:
    """Context for academic writing assistance"""
    current_text: str
    cursor_position: int
    document_type: str  # paper, thesis, book, article
    field: str  # computer_science, biology, etc.
    citation_style: CitationStyle


class AcademicAssistant:
    """
    AI-powered academic writing assistant
    Provides intelligent suggestions and automated features
    """
    
    def __init__(self, synthor_integration: SynthorAcademicIntegration):
        self.integration = synthor_integration
        self.bridge = synthor_integration.bridge
        self.suggestion_cache = {}
        self.writing_patterns = self._load_writing_patterns()
        
    def _load_writing_patterns(self) -> Dict[str, List[str]]:
        """Load common academic writing patterns"""
        return {
            "introduction": [
                "Recent studies have shown",
                "Previous research indicates",
                "It has been demonstrated that",
                "According to recent literature"
            ],
            "methodology": [
                "We employed",
                "The methodology consists of",
                "Data was collected using",
                "The experimental design"
            ],
            "results": [
                "Our findings suggest",
                "The results indicate",
                "Statistical analysis revealed",
                "We observed that"
            ],
            "discussion": [
                "These findings align with",
                "In contrast to previous studies",
                "The implications of these results",
                "Future research should"
            ]
        }
    
    async def suggest_citations(
        self,
        context: WritingContext,
        num_suggestions: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Suggest relevant citations based on writing context
        Uses AI to understand context and find appropriate papers
        """
        # Extract key concepts from current paragraph
        key_concepts = self._extract_key_concepts(context.current_text)
        
        # Build intelligent search query
        search_query = self._build_contextual_query(key_concepts, context)
        
        # Search for relevant papers
        papers = await self.bridge.search(
            search_query,
            limit=num_suggestions * 2,  # Get extra for filtering
            filters={"field": context.field}
        )
        
        # Rank papers by relevance to context
        ranked_papers = self._rank_papers_by_context(papers, context)
        
        # Format suggestions
        suggestions = []
        for paper in ranked_papers[:num_suggestions]:
            suggestion = {
                "paper": paper,
                "relevance_score": self._calculate_contextual_relevance(paper, context),
                "preview": await self._generate_citation_preview(paper, context),
                "insertion_text": self._generate_insertion_text(paper, context)
            }
            suggestions.append(suggestion)
        
        return suggestions
    
    def _extract_key_concepts(self, text: str) -> List[str]:
        """Extract key concepts using NLP techniques"""
        # Remove common words
        stopwords = {
            "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for",
            "of", "with", "by", "from", "up", "about", "into", "through", "during",
            "including", "until", "against", "among", "throughout", "despite", "towards",
            "upon", "concerning", "of", "to", "in", "for", "on", "by", "about", "like",
            "through", "over", "before", "between", "after", "since", "without",
            "under", "within", "along", "following", "across", "behind", "beyond",
            "plus", "except", "but", "up", "out", "around", "down", "off", "above"
        }
        
        # Extract noun phrases and important terms
        words = re.findall(r'\w+', text.lower())
        concepts = []
        
        # Look for technical terms (containing numbers, capitals, or long)
        for word in words:
            if (word not in stopwords and 
                (len(word) > 6 or any(c.isdigit() for c in word) or
                 any(c.isupper() for c in text if text.count(word) > 0))):
                concepts.append(word)
        
        # Look for multi-word concepts
        bigrams = [f"{words[i]} {words[i+1]}" 
                   for i in range(len(words)-1) 
                   if words[i] not in stopwords and words[i+1] not in stopwords]
        
        concepts.extend(bigrams[:3])  # Top 3 bigrams
        
        return concepts[:7]  # Return top 7 concepts
    
    def _build_contextual_query(
        self,
        concepts: List[str],
        context: WritingContext
    ) -> str:
        """Build search query based on context"""
        # Identify section type from patterns
        section = self._identify_section(context.current_text)
        
        # Adjust query based on section
        if section == "introduction":
            query_prefix = "review survey state-of-the-art"
        elif section == "methodology":
            query_prefix = "methods techniques approach"
        elif section == "results":
            query_prefix = "evaluation results performance"
        else:
            query_prefix = ""
        
        # Combine concepts with contextual prefix
        query = f"{query_prefix} {' '.join(concepts[:5])}"
        
        return query.strip()
    
    def _identify_section(self, text: str) -> str:
        """Identify which section of paper based on patterns"""
        text_lower = text.lower()
        
        for section, patterns in self.writing_patterns.items():
            for pattern in patterns:
                if pattern.lower() in text_lower:
                    return section
        
        return "general"
    
    def _rank_papers_by_context(
        self,
        papers: List[Paper],
        context: WritingContext
    ) -> List[Paper]:
        """Rank papers by relevance to writing context"""
        scored_papers = []
        
        for paper in papers:
            score = 0.0
            
            # Recency bonus
            if paper.year and paper.year >= datetime.now().year - 2:
                score += 0.2
            
            # Citation count bonus
            if paper.citations and paper.citations > 50:
                score += 0.1
            
            # Field match
            if context.field.lower() in (paper.title + " " + (paper.abstract or "")).lower():
                score += 0.3
            
            # Keyword match in title
            for concept in self._extract_key_concepts(context.current_text):
                if concept.lower() in paper.title.lower():
                    score += 0.2
                elif paper.abstract and concept.lower() in paper.abstract.lower():
                    score += 0.1
            
            scored_papers.append((score, paper))
        
        # Sort by score
        scored_papers.sort(key=lambda x: x[0], reverse=True)
        
        return [paper for _, paper in scored_papers]
    
    def _calculate_contextual_relevance(
        self,
        paper: Paper,
        context: WritingContext
    ) -> float:
        """Calculate relevance score for UI display"""
        score = 0.0
        
        # Title relevance
        title_concepts = set(self._extract_key_concepts(paper.title))
        context_concepts = set(self._extract_key_concepts(context.current_text))
        
        overlap = len(title_concepts & context_concepts)
        score += overlap * 0.2
        
        # Recency
        if paper.year:
            years_old = datetime.now().year - paper.year
            score += max(0, (10 - years_old) / 10) * 0.3
        
        # Authority (citation count)
        if paper.citations:
            score += min(paper.citations / 100, 1.0) * 0.5
        
        return min(score, 1.0)
    
    async def _generate_citation_preview(
        self,
        paper: Paper,
        context: WritingContext
    ) -> str:
        """Generate preview of how citation would look"""
        citation = await self.bridge.format_citation(paper, context.citation_style)
        
        # Create preview with context
        preview = f"...{context.current_text[-50:]} "
        preview += self._generate_insertion_text(paper, context)
        preview += f" {context.current_text[context.cursor_position:context.cursor_position+50]}..."
        
        return preview
    
    def _generate_insertion_text(
        self,
        paper: Paper,
        context: WritingContext
    ) -> str:
        """Generate text to insert for citation"""
        if context.citation_style == CitationStyle.APA:
            if paper.authors and paper.year:
                first_author = paper.authors[0].split(',')[0]
                if len(paper.authors) == 1:
                    return f"({first_author}, {paper.year})"
                elif len(paper.authors) == 2:
                    second_author = paper.authors[1].split(',')[0]
                    return f"({first_author} & {second_author}, {paper.year})"
                else:
                    return f"({first_author} et al., {paper.year})"
            return f"(Unknown, {paper.year or 'n.d.'})"
            
        elif context.citation_style == CitationStyle.MLA:
            if paper.authors:
                first_author = paper.authors[0].split(',')[0]
                return f"({first_author})"
            return f"(Unknown)"
            
        else:  # Numeric styles
            # Would need to track citation numbers
            return "[REF]"
    
    async def check_citation_completeness(
        self,
        document_text: str,
        reference_list: List[str]
    ) -> Dict[str, Any]:
        """
        Check if all citations in text have corresponding references
        and vice versa
        """
        # Extract in-text citations
        in_text_citations = self._extract_in_text_citations(document_text)
        
        # Extract references
        reference_keys = self._extract_reference_keys(reference_list)
        
        # Find discrepancies
        missing_references = []
        for citation in in_text_citations:
            if not any(citation in ref for ref in reference_keys):
                missing_references.append(citation)
        
        unused_references = []
        for ref_key in reference_keys:
            if not any(ref_key in cite for cite in in_text_citations):
                unused_references.append(ref_key)
        
        return {
            "complete": len(missing_references) == 0 and len(unused_references) == 0,
            "missing_references": missing_references,
            "unused_references": unused_references,
            "total_citations": len(in_text_citations),
            "total_references": len(reference_keys)
        }
    
    def _extract_in_text_citations(self, text: str) -> List[str]:
        """Extract in-text citations from document"""
        citations = []
        
        # APA style: (Author, Year) or (Author et al., Year)
        apa_pattern = r'\(([A-Z][a-z]+(?:\s+et\s+al\.)?),\s*(\d{4})\)'
        citations.extend(re.findall(apa_pattern, text))
        
        # Numeric style: [1], [2,3], [1-5]
        numeric_pattern = r'\[(\d+(?:[-,]\d+)*)\]'
        citations.extend(re.findall(numeric_pattern, text))
        
        return citations
    
    def _extract_reference_keys(self, references: List[str]) -> List[str]:
        """Extract identifiable keys from references"""
        keys = []
        
        for ref in references:
            # Extract author and year
            author_match = re.search(r'^([A-Z][a-z]+)', ref)
            year_match = re.search(r'\((\d{4})\)', ref)
            
            if author_match and year_match:
                keys.append(f"{author_match.group(1)}, {year_match.group(1)}")
        
        return keys
    
    async def suggest_writing_improvements(
        self,
        text: str,
        context: WritingContext
    ) -> List[Dict[str, Any]]:
        """
        Suggest improvements to academic writing
        Checks for common issues and suggests alternatives
        """
        suggestions = []
        
        # Check for passive voice
        passive_matches = re.finditer(
            r'\b(was|were|been|being|is|are|am)\s+\w+ed\b',
            text,
            re.IGNORECASE
        )
        for match in passive_matches:
            suggestions.append({
                "type": "passive_voice",
                "position": match.start(),
                "text": match.group(),
                "suggestion": "Consider using active voice",
                "severity": "info"
            })
        
        # Check for informal language
        informal_words = {
            "a lot": "many/much",
            "get": "obtain/receive",
            "got": "obtained/received",
            "thing": "aspect/element",
            "stuff": "material/content"
        }
        
        for informal, formal in informal_words.items():
            if informal in text.lower():
                pos = text.lower().find(informal)
                suggestions.append({
                    "type": "informal_language",
                    "position": pos,
                    "text": informal,
                    "suggestion": f"Consider using '{formal}'",
                    "severity": "warning"
                })
        
        # Check for citation density
        sentences = text.split('.')
        for i, sentence in enumerate(sentences):
            if len(sentence) > 50 and not re.search(r'\([^)]+\d{4}[^)]*\)', sentence):
                suggestions.append({
                    "type": "missing_citation",
                    "position": sum(len(s) + 1 for s in sentences[:i]),
                    "text": sentence[:50] + "...",
                    "suggestion": "Consider adding a citation to support this claim",
                    "severity": "info"
                })
        
        return suggestions