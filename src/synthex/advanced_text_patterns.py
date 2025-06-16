#!/usr/bin/env python3
"""
Advanced Text Pattern Recognition for SYNTHEX Chapter Detection
Handles edge cases, multi-format documents, and complex hierarchical structures
"""

import re
from typing import List, Dict, Tuple, Optional, Union, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import unicodedata
from collections import defaultdict
import xml.etree.ElementTree as ET
from pathlib import Path


class PatternComplexity(Enum):
    """Complexity levels for pattern matching"""
    SIMPLE = "simple"      # Basic patterns
    MODERATE = "moderate"  # Multi-line patterns
    COMPLEX = "complex"    # Context-aware patterns
    ADVANCED = "advanced"  # ML-assisted patterns


@dataclass
class ContextualPattern:
    """Pattern that considers surrounding context"""
    primary_pattern: str
    context_before: Optional[str] = None
    context_after: Optional[str] = None
    max_distance: int = 5  # Lines to look ahead/behind
    confidence_boost: float = 0.1
    complexity: PatternComplexity = PatternComplexity.MODERATE


class EdgeCaseHandler:
    """Handles special cases and edge scenarios in chapter detection"""
    
    def __init__(self):
        self.special_patterns = self._initialize_special_patterns()
        self.unicode_normalizer = UnicodeNormalizer()
        self.ambiguity_resolver = AmbiguityResolver()
    
    def _initialize_special_patterns(self) -> Dict[str, List[ContextualPattern]]:
        """Initialize patterns for edge cases"""
        return {
            'legal_documents': [
                ContextualPattern(
                    r'^Article\s+([IVXLCDM]+|\d+)(?:\s*[:\-–—]\s*(.+))?$',
                    context_after=r'^Section\s+\d+'
                ),
                ContextualPattern(
                    r'^§\s*(\d+(?:\.\d+)*)\s+(.+)$',
                    complexity=PatternComplexity.MODERATE
                ),
            ],
            'screenplay': [
                ContextualPattern(
                    r'^(INT\.|EXT\.|INT/EXT\.)\s+(.+?)(?:\s*[-–—]\s*(.+))?$',
                    context_after=r'^[A-Z\s]+(\s*\([^)]+\))?$'
                ),
                ContextualPattern(
                    r'^FADE\s+(IN|OUT|TO BLACK|TO WHITE):?$',
                    complexity=PatternComplexity.SIMPLE
                ),
            ],
            'poetry': [
                ContextualPattern(
                    r'^Canto\s+([IVXLCDM]+)$',
                    context_after=r'^\s*$'  # Often followed by blank line
                ),
                ContextualPattern(
                    r'^(?:Sonnet|Poem|Verse)\s+(\d+)(?:\s*[:\-–—]\s*(.+))?$'
                ),
            ],
            'religious_texts': [
                ContextualPattern(
                    r'^(?:Book|Psalm|Surah|Sura)\s+(\d+)(?:\s*[:\-–—]\s*(.+))?$'
                ),
                ContextualPattern(
                    r'^(\d+):(\d+)(?:\s*[-–—]\s*(\d+))?',  # Verse references
                    context_before=r'^(?:Chapter|Book)\s+\d+'
                ),
            ],
            'code_documentation': [
                ContextualPattern(
                    r'^"""(.+?)"""$',  # Python docstrings
                    complexity=PatternComplexity.COMPLEX
                ),
                ContextualPattern(
                    r'^/\*\*(.+?)\*/$',  # JSDoc style
                    complexity=PatternComplexity.COMPLEX
                ),
                ContextualPattern(
                    r'^#+\s*@(\w+)\s+(.+)$',  # Annotation style
                ),
            ],
            'mixed_numbering': [
                ContextualPattern(
                    r'^(\d+)-([A-Z])\s+(.+)$',  # e.g., "1-A Introduction"
                ),
                ContextualPattern(
                    r'^([A-Z])\.(\d+)\s+(.+)$',  # e.g., "A.1 Overview"
                ),
                ContextualPattern(
                    r'^(\d+)\.([a-z])\)\s+(.+)$',  # e.g., "1.a) Details"
                ),
            ]
        }
    
    def detect_edge_cases(self, content: str) -> List[Dict[str, Any]]:
        """Detect and handle edge cases in document structure"""
        lines = content.split('
')
        detected_patterns = []
        
        for category, patterns in self.special_patterns.items():
            for i, line in enumerate(lines):
                line = self.unicode_normalizer.normalize(line.strip())
                
                for pattern in patterns:
                    if self._matches_contextual_pattern(pattern, lines, i):
                        detected_patterns.append({
                            'category': category,
                            'line_number': i,
                            'line': line,
                            'pattern': pattern.primary_pattern,
                            'confidence': self._calculate_confidence(pattern, lines, i)
                        })
        
        return detected_patterns
    
    def _matches_contextual_pattern(self, pattern: ContextualPattern, lines: List[str], index: int) -> bool:
        """Check if pattern matches with context"""
        line = lines[index].strip()
        
        # Check primary pattern
        if not re.match(pattern.primary_pattern, line):
            return False
        
        # Check context before
        if pattern.context_before:
            for i in range(max(0, index - pattern.max_distance), index):
                if re.match(pattern.context_before, lines[i].strip()):
                    break
            else:
                return False
        
        # Check context after
        if pattern.context_after:
            for i in range(index + 1, min(len(lines), index + pattern.max_distance + 1)):
                if re.match(pattern.context_after, lines[i].strip()):
                    break
            else:
                return False
        
        return True
    
    def _calculate_confidence(self, pattern: ContextualPattern, lines: List[str], index: int) -> float:
        """Calculate confidence score for pattern match"""
        base_confidence = 0.7
        
        # Boost for matching context
        if pattern.context_before or pattern.context_after:
            base_confidence += pattern.confidence_boost
        
        # Adjust for complexity
        complexity_multipliers = {
            PatternComplexity.SIMPLE: 1.0,
            PatternComplexity.MODERATE: 0.95,
            PatternComplexity.COMPLEX: 0.9,
            PatternComplexity.ADVANCED: 0.85
        }
        
        return base_confidence * complexity_multipliers[pattern.complexity]


class UnicodeNormalizer:
    """Handles Unicode normalization and special characters"""
    
    def __init__(self):
        self.replacements = {
            # Various dashes and hyphens
            '\u2010': '-',  # Hyphen
            '\u2011': '-',  # Non-breaking hyphen
            '\u2012': '-',  # Figure dash
            '\u2013': '–',  # En dash
            '\u2014': '—',  # Em dash
            '\u2015': '—',  # Horizontal bar
            
            # Quotation marks
            '\u2018': "'",  # Left single quote
            '\u2019': "'",  # Right single quote
            '\u201C': '"',  # Left double quote
            '\u201D': '"',  # Right double quote
            
            # Special spaces
            '\u00A0': ' ',  # Non-breaking space
            '\u2009': ' ',  # Thin space
            '\u200A': ' ',  # Hair space
        }
    
    def normalize(self, text: str) -> str:
        """Normalize Unicode text for consistent pattern matching"""
        # Normalize to NFKC form
        text = unicodedata.normalize('NFKC', text)
        
        # Replace special characters
        for old, new in self.replacements.items():
            text = text.replace(old, new)
        
        # Remove zero-width characters
        text = re.sub(r'[\u200B\u200C\u200D\uFEFF]', '', text)
        
        return text
    
    def detect_special_numbering(self, text: str) -> Optional[Dict[str, Any]]:
        """Detect special Unicode numbering systems"""
        # Circled numbers ① ② ③
        circled_match = re.search(r'[\u2460-\u2473]', text)
        if circled_match:
            char = circled_match.group()
            number = ord(char) - 0x2460 + 1
            return {'type': 'circled', 'number': number, 'char': char}
        
        # Roman numerals in Unicode block
        roman_match = re.search(r'[\u2160-\u217F]', text)
        if roman_match:
            char = roman_match.group()
            # Convert Unicode Roman to ASCII
            ascii_roman = unicodedata.normalize('NFKC', char)
            return {'type': 'unicode_roman', 'number': ascii_roman, 'char': char}
        
        # Parenthesized numbers ⑴ ⑵ ⑶
        paren_match = re.search(r'[\u2474-\u2487]', text)
        if paren_match:
            char = paren_match.group()
            number = ord(char) - 0x2474 + 1
            return {'type': 'parenthesized', 'number': number, 'char': char}
        
        return None


class AmbiguityResolver:
    """Resolves ambiguous patterns in document structure"""
    
    def __init__(self):
        self.ambiguous_patterns = {
            'number_only': re.compile(r'^(\d+)\s*$'),
            'roman_only': re.compile(r'^([IVXLCDM]+)\s*$'),
            'letter_only': re.compile(r'^([A-Z])\s*$'),
            'title_case': re.compile(r'^[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*$'),
        }
        
    def resolve_ambiguity(self, candidates: List[Dict[str, Any]], context: Dict[str, Any]) -> Dict[str, Any]:
        """Resolve ambiguous structure detection"""
        if not candidates:
            return None
        
        if len(candidates) == 1:
            return candidates[0]
        
        # Score each candidate
        scored_candidates = []
        for candidate in candidates:
            score = self._score_candidate(candidate, context)
            scored_candidates.append((score, candidate))
        
        # Return highest scoring candidate
        scored_candidates.sort(key=lambda x: x[0], reverse=True)
        return scored_candidates[0][1]
    
    def _score_candidate(self, candidate: Dict[str, Any], context: Dict[str, Any]) -> float:
        """Score a candidate based on various factors"""
        score = candidate.get('confidence', 0.5)
        
        # Boost score for consistent numbering
        if context.get('prev_numbering_system') == candidate.get('numbering_system'):
            score += 0.2
        
        # Boost score for expected sequence
        if self._is_sequential(candidate, context):
            score += 0.3
        
        # Penalty for isolated elements
        if candidate.get('isolated', False):
            score -= 0.2
        
        return min(1.0, max(0.0, score))
    
    def _is_sequential(self, candidate: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Check if candidate follows expected sequence"""
        prev_number = context.get('prev_number')
        curr_number = candidate.get('number')
        
        if not prev_number or not curr_number:
            return False
        
        # Handle different number types
        try:
            if isinstance(prev_number, str) and isinstance(curr_number, str):
                # Try to convert to int
                prev_int = self._to_int(prev_number)
                curr_int = self._to_int(curr_number)
                return curr_int == prev_int + 1
        except:
            return False
        
        return False
    
    def _to_int(self, value: str) -> int:
        """Convert various number formats to integer"""
        # Try direct conversion
        try:
            return int(value)
        except ValueError:
            pass
        
        # Try Roman numerals
        roman_values = {'I': 1, 'V': 5, 'X': 10, 'L': 50, 'C': 100, 'D': 500, 'M': 1000}
        if all(c in roman_values for c in value.upper()):
            total = 0
            prev_value = 0
            for char in reversed(value.upper()):
                curr_value = roman_values[char]
                if curr_value < prev_value:
                    total -= curr_value
                else:
                    total += curr_value
                prev_value = curr_value
            return total
        
        # Try alphabetic
        if len(value) == 1 and value.isalpha():
            return ord(value.upper()) - ord('A') + 1
        
        raise ValueError(f"Cannot convert {value} to integer")


class HierarchicalStructureAnalyzer:
    """Analyzes and validates hierarchical document structures"""
    
    def __init__(self):
        self.hierarchy_rules = self._initialize_hierarchy_rules()
    
    def _initialize_hierarchy_rules(self) -> Dict[str, List[str]]:
        """Define valid hierarchy patterns"""
        return {
            'book': ['part', 'chapter', 'section', 'subsection'],
            'academic': ['section', 'subsection', 'subsubsection', 'paragraph'],
            'technical': ['module', 'class', 'method', 'parameter'],
            'legal': ['title', 'article', 'section', 'subsection', 'paragraph'],
            'outline': ['h1', 'h2', 'h3', 'h4', 'h5', 'h6'],
        }
    
    def validate_hierarchy(self, elements: List[Dict[str, Any]]) -> Tuple[bool, List[str]]:
        """Validate if detected hierarchy is logical"""
        issues = []
        
        # Check for orphaned elements
        orphans = self._find_orphans(elements)
        if orphans:
            issues.append(f"Found {len(orphans)} orphaned elements")
        
        # Check for skipped levels
        level_skips = self._find_level_skips(elements)
        if level_skips:
            issues.append(f"Found {len(level_skips)} level skips")
        
        # Check for inconsistent numbering
        numbering_issues = self._check_numbering_consistency(elements)
        if numbering_issues:
            issues.extend(numbering_issues)
        
        return len(issues) == 0, issues
    
    def _find_orphans(self, elements: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find elements without proper parents"""
        orphans = []
        
        for i, element in enumerate(elements):
            if element['level'] > 1:
                # Look for parent
                parent_found = False
                for j in range(i - 1, -1, -1):
                    if elements[j]['level'] == element['level'] - 1:
                        parent_found = True
                        break
                    elif elements[j]['level'] < element['level'] - 1:
                        break
                
                if not parent_found:
                    orphans.append(element)
        
        return orphans
    
    def _find_level_skips(self, elements: List[Dict[str, Any]]) -> List[Tuple[int, int]]:
        """Find places where hierarchy levels are skipped"""
        skips = []
        prev_level = 0
        
        for element in elements:
            curr_level = element['level']
            if curr_level > prev_level + 1:
                skips.append((prev_level, curr_level))
            prev_level = curr_level
        
        return skips
    
    def _check_numbering_consistency(self, elements: List[Dict[str, Any]]) -> List[str]:
        """Check for consistent numbering within levels"""
        issues = []
        level_numbering = defaultdict(list)
        
        for element in elements:
            if element.get('number'):
                level_numbering[element['level']].append(element['number'])
        
        for level, numbers in level_numbering.items():
            # Check for duplicates
            seen = set()
            duplicates = []
            for num in numbers:
                if num in seen:
                    duplicates.append(num)
                seen.add(num)
            
            if duplicates:
                issues.append(f"Level {level} has duplicate numbers: {duplicates}")
            
            # Check for gaps in sequence
            try:
                int_numbers = [self._to_int_safe(n) for n in numbers if self._to_int_safe(n) is not None]
                if int_numbers:
                    int_numbers.sort()
                    gaps = []
                    for i in range(1, len(int_numbers)):
                        if int_numbers[i] - int_numbers[i-1] > 1:
                            gaps.append((int_numbers[i-1], int_numbers[i]))
                    
                    if gaps:
                        issues.append(f"Level {level} has numbering gaps: {gaps}")
            except:
                pass
        
        return issues
    
    def _to_int_safe(self, value: str) -> Optional[int]:
        """Safely convert to integer, return None if not possible"""
        try:
            return int(value)
        except:
            return None
    
    def suggest_corrections(self, elements: List[Dict[str, Any]], issues: List[str]) -> List[Dict[str, Any]]:
        """Suggest corrections for hierarchy issues"""
        corrections = []
        
        for issue in issues:
            if "orphaned" in issue:
                corrections.append({
                    'type': 'add_parent',
                    'description': 'Add missing parent sections for orphaned elements'
                })
            elif "level skips" in issue:
                corrections.append({
                    'type': 'adjust_levels',
                    'description': 'Adjust element levels to avoid skips'
                })
            elif "duplicate numbers" in issue:
                corrections.append({
                    'type': 'renumber',
                    'description': 'Renumber elements to avoid duplicates'
                })
            elif "numbering gaps" in issue:
                corrections.append({
                    'type': 'check_missing',
                    'description': 'Check for missing sections in numbering sequence'
                })
        
        return corrections


class MultiFormatParser:
    """Handles parsing of documents with mixed formats"""
    
    def __init__(self):
        self.format_detectors = {
            'latex': self._detect_latex,
            'html': self._detect_html,
            'xml': self._detect_xml,
            'restructuredtext': self._detect_rst,
            'asciidoc': self._detect_asciidoc,
            'org_mode': self._detect_org,
        }
    
    def detect_mixed_formats(self, content: str) -> Dict[str, List[Tuple[int, int]]]:
        """Detect regions of different formats within document"""
        format_regions = {}
        lines = content.split('
')
        
        for format_name, detector in self.format_detectors.items():
            regions = detector(lines)
            if regions:
                format_regions[format_name] = regions
        
        return format_regions
    
    def _detect_latex(self, lines: List[str]) -> List[Tuple[int, int]]:
        """Detect LaTeX formatted regions"""
        regions = []
        in_latex = False
        start = 0
        
        for i, line in enumerate(lines):
            if re.match(r'^\\(chapter|section|subsection|subsubsection)\{', line):
                if not in_latex:
                    in_latex = True
                    start = i
            elif in_latex and not line.strip().startswith('\\'):
                # End of LaTeX region
                regions.append((start, i))
                in_latex = False
        
        if in_latex:
            regions.append((start, len(lines)))
        
        return regions
    
    def _detect_html(self, lines: List[str]) -> List[Tuple[int, int]]:
        """Detect HTML formatted regions"""
        regions = []
        in_html = False
        start = 0
        
        html_pattern = re.compile(r'<(h[1-6]|div|section|article|p).*?>', re.IGNORECASE)
        
        for i, line in enumerate(lines):
            if html_pattern.search(line):
                if not in_html:
                    in_html = True
                    start = i
            elif in_html and not re.search(r'<[^>]+>', line):
                regions.append((start, i))
                in_html = False
        
        if in_html:
            regions.append((start, len(lines)))
        
        return regions
    
    def _detect_xml(self, lines: List[str]) -> List[Tuple[int, int]]:
        """Detect XML formatted regions"""
        # Similar to HTML but with different patterns
        regions = []
        in_xml = False
        start = 0
        
        for i, line in enumerate(lines):
            if re.match(r'^<\?xml', line) or re.match(r'^<[a-zA-Z]+.*?>', line):
                if not in_xml:
                    in_xml = True
                    start = i
            elif in_xml and line.strip() and not re.search(r'<[^>]+>', line):
                regions.append((start, i))
                in_xml = False
        
        if in_xml:
            regions.append((start, len(lines)))
        
        return regions
    
    def _detect_rst(self, lines: List[str]) -> List[Tuple[int, int]]:
        """Detect reStructuredText formatted regions"""
        regions = []
        
        # RST uses underlines for headers
        for i in range(len(lines) - 1):
            if lines[i].strip() and re.match(r'^[=\-~`#"^+*]{3,}$', lines[i + 1]):
                # Found RST header
                start = max(0, i - 5)
                end = min(len(lines), i + 10)
                regions.append((start, end))
        
        # Merge overlapping regions
        return self._merge_regions(regions)
    
    def _detect_asciidoc(self, lines: List[str]) -> List[Tuple[int, int]]:
        """Detect AsciiDoc formatted regions"""
        regions = []
        
        for i, line in enumerate(lines):
            if re.match(r'^={1,6}\s+\S', line):  # AsciiDoc headers
                regions.append((i, i + 1))
            elif re.match(r'^\[.*\]$', line):  # AsciiDoc attributes
                regions.append((i, i + 1))
        
        return self._merge_regions(regions)
    
    def _detect_org(self, lines: List[str]) -> List[Tuple[int, int]]:
        """Detect Org-mode formatted regions"""
        regions = []
        
        for i, line in enumerate(lines):
            if re.match(r'^\*+\s+\S', line):  # Org headers
                regions.append((i, i + 1))
            elif re.match(r'^#\+\w+:', line):  # Org directives
                regions.append((i, i + 1))
        
        return self._merge_regions(regions)
    
    def _merge_regions(self, regions: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
        """Merge overlapping or adjacent regions"""
        if not regions:
            return []
        
        regions.sort()
        merged = [regions[0]]
        
        for start, end in regions[1:]:
            last_start, last_end = merged[-1]
            if start <= last_end + 1:
                # Merge regions
                merged[-1] = (last_start, max(last_end, end))
            else:
                merged.append((start, end))
        
        return merged


class PDFStructureExtractor:
    """Extract structure from PDF bookmarks and outline"""
    
    def extract_from_pdf_metadata(self, pdf_metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract chapter structure from PDF metadata"""
        structure = []
        
        if 'bookmarks' in pdf_metadata:
            structure = self._process_bookmarks(pdf_metadata['bookmarks'])
        elif 'outline' in pdf_metadata:
            structure = self._process_outline(pdf_metadata['outline'])
        
        return structure
    
    def _process_bookmarks(self, bookmarks: List[Dict[str, Any]], level: int = 1) -> List[Dict[str, Any]]:
        """Process PDF bookmarks into structure"""
        structure = []
        
        for bookmark in bookmarks:
            element = {
                'level': level,
                'title': bookmark.get('title', ''),
                'page': bookmark.get('page', 0),
                'type': self._infer_type_from_title(bookmark.get('title', ''), level)
            }
            
            # Extract number if present
            number_match = re.match(r'^(?:Chapter|Section)?\s*(\d+)', element['title'])
            if number_match:
                element['number'] = number_match.group(1)
            
            structure.append(element)
            
            # Process children
            if 'children' in bookmark:
                children = self._process_bookmarks(bookmark['children'], level + 1)
                element['children'] = children
        
        return structure
    
    def _process_outline(self, outline: List[Tuple[int, str, int]]) -> List[Dict[str, Any]]:
        """Process PDF outline (level, title, page) tuples"""
        structure = []
        
        for level, title, page in outline:
            element = {
                'level': level,
                'title': title,
                'page': page,
                'type': self._infer_type_from_title(title, level)
            }
            
            # Extract number
            number_match = re.match(r'^(?:Chapter|Section)?\s*(\d+)', title)
            if number_match:
                element['number'] = number_match.group(1)
            
            structure.append(element)
        
        return structure
    
    def _infer_type_from_title(self, title: str, level: int) -> str:
        """Infer element type from title and level"""
        title_lower = title.lower()
        
        if 'chapter' in title_lower:
            return 'chapter'
        elif 'section' in title_lower:
            return 'section'
        elif 'part' in title_lower:
            return 'part'
        elif 'appendix' in title_lower:
            return 'appendix'
        elif level == 1:
            return 'chapter'
        elif level == 2:
            return 'section'
        else:
            return 'subsection'


class EPUBStructureExtractor:
    """Extract structure from EPUB navigation"""
    
    def extract_from_epub_nav(self, nav_content: str) -> List[Dict[str, Any]]:
        """Extract structure from EPUB navigation document"""
        try:
            root = ET.fromstring(nav_content)
            nav_element = root.find('.//{http://www.w3.org/1999/xhtml}nav[@epub:type="toc"]', 
                                   {'epub': 'http://www.idpf.org/2007/ops'})
            
            if nav_element is not None:
                ol_element = nav_element.find('.//{http://www.w3.org/1999/xhtml}ol')
                if ol_element is not None:
                    return self._process_nav_list(ol_element)
        except:
            pass
        
        return []
    
    def _process_nav_list(self, ol_element: ET.Element, level: int = 1) -> List[Dict[str, Any]]:
        """Process navigation list element"""
        structure = []
        
        for li in ol_element.findall('.//{http://www.w3.org/1999/xhtml}li'):
            a_element = li.find('.//{http://www.w3.org/1999/xhtml}a')
            if a_element is not None:
                element = {
                    'level': level,
                    'title': a_element.text or '',
                    'href': a_element.get('href', ''),
                    'type': self._infer_type_from_level(level)
                }
                
                # Check for nested list
                nested_ol = li.find('.//{http://www.w3.org/1999/xhtml}ol')
                if nested_ol is not None:
                    element['children'] = self._process_nav_list(nested_ol, level + 1)
                
                structure.append(element)
        
        return structure
    
    def _infer_type_from_level(self, level: int) -> str:
        """Infer element type from hierarchy level"""
        if level == 1:
            return 'chapter'
        elif level == 2:
            return 'section'
        else:
            return 'subsection'


# Integration with main chapter detection engine
class AdvancedChapterDetector:
    """Advanced chapter detection with edge case handling"""
    
    def __init__(self):
        self.edge_case_handler = EdgeCaseHandler()
        self.hierarchy_analyzer = HierarchicalStructureAnalyzer()
        self.multi_format_parser = MultiFormatParser()
        self.pdf_extractor = PDFStructureExtractor()
        self.epub_extractor = EPUBStructureExtractor()
    
    def enhance_detection(self, basic_structure: List[Dict[str, Any]], 
                         content: str, 
                         metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Enhance basic detection with advanced features"""
        
        # Detect edge cases
        edge_cases = self.edge_case_handler.detect_edge_cases(content)
        
        # Detect mixed formats
        format_regions = self.multi_format_parser.detect_mixed_formats(content)
        
        # Validate hierarchy
        is_valid, hierarchy_issues = self.hierarchy_analyzer.validate_hierarchy(basic_structure)
        
        # Suggest corrections if needed
        corrections = []
        if not is_valid:
            corrections = self.hierarchy_analyzer.suggest_corrections(basic_structure, hierarchy_issues)
        
        # Handle special metadata
        special_structure = []
        if metadata:
            if metadata.get('type') == 'pdf' and 'pdf_metadata' in metadata:
                special_structure = self.pdf_extractor.extract_from_pdf_metadata(metadata['pdf_metadata'])
            elif metadata.get('type') == 'epub' and 'nav_content' in metadata:
                special_structure = self.epub_extractor.extract_from_epub_nav(metadata['nav_content'])
        
        return {
            'enhanced_structure': self._merge_structures(basic_structure, special_structure),
            'edge_cases': edge_cases,
            'format_regions': format_regions,
            'hierarchy_validation': {
                'is_valid': is_valid,
                'issues': hierarchy_issues,
                'corrections': corrections
            },
            'special_features': self._detect_special_features(content)
        }
    
    def _merge_structures(self, basic: List[Dict[str, Any]], special: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Merge basic and special structures"""
        if not special:
            return basic
        
        # Simple merge - in practice, would be more sophisticated
        merged = basic.copy()
        
        # Add any elements from special not in basic
        basic_titles = {elem.get('title', '').lower() for elem in basic}
        for elem in special:
            if elem.get('title', '').lower() not in basic_titles:
                merged.append(elem)
        
        return merged
    
    def _detect_special_features(self, content: str) -> Dict[str, Any]:
        """Detect special document features"""
        features = {
            'has_footnotes': bool(re.search(r'\[\^\d+\]|\d+\)', content)),
            'has_citations': bool(re.search(r'\[[^\]]+\d{4}[^\]]*\]|\(\w+,?\s*\d{4}\)', content)),
            'has_code_blocks': bool(re.search(r'```[\s\S]*?```|~~~[\s\S]*?~~~', content)),
            'has_tables': bool(re.search(r'\|.*\|.*\||\+[-+]+\+', content)),
            'has_mathematical_notation': bool(re.search(r'\$[^$]+\$|\\\[[\s\S]*?\\\]', content)),
            'has_cross_references': bool(re.search(r'(?:see|refer to)\s+(?:chapter|section)\s+\d+', content, re.IGNORECASE)),
        }
        
        return features


if __name__ == "__main__":
    # Example usage
    detector = AdvancedChapterDetector()
    
    # Test with edge case document
    edge_case_content = """
    Article I: General Provisions
    
    Section 1.1 - Definitions
    
    § 1.1.1 Terms and Conditions
    
    The following terms shall have the meanings...
    
    Section 1.2 - Scope
    
    This document applies to...
    
    Article II: Implementation
    
    Section 2.1 - Procedures
    """
    
    basic_structure = [
        {'level': 1, 'type': 'article', 'number': 'I', 'title': 'General Provisions'},
        {'level': 2, 'type': 'section', 'number': '1.1', 'title': 'Definitions'},
        {'level': 3, 'type': 'subsection', 'number': '1.1.1', 'title': 'Terms and Conditions'},
        {'level': 2, 'type': 'section', 'number': '1.2', 'title': 'Scope'},
        {'level': 1, 'type': 'article', 'number': 'II', 'title': 'Implementation'},
        {'level': 2, 'type': 'section', 'number': '2.1', 'title': 'Procedures'},
    ]
    
    enhanced = detector.enhance_detection(basic_structure, edge_case_content)
    
    import json
    print(json.dumps(enhanced, indent=2))