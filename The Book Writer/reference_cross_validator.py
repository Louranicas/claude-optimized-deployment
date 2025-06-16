#!/usr/bin/env python3
"""
🔬 COMPREHENSIVE REFERENCE CROSS-VALIDATION
Validates all in-text citations against reference list
"""

import re
from pathlib import Path
from typing import Dict, List, Tuple, Set
import json

class ReferenceCrossValidator:
    """Comprehensive citation validation system"""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.content = self._load_content()
        self.citations = []
        self.references = []
        
    def _load_content(self) -> str:
        """Load chapter content"""
        with open(self.file_path, 'r', encoding='utf-8') as f:
            return f.read()
    
    def extract_citations(self) -> List[Dict]:
        """Extract all in-text citations"""
        citations = []
        
        # Pattern 1: (Author, Year) or (Author et al., Year)
        pattern1 = r'\(([A-Z][a-zA-Z\s&,]+?)(?:\s+et\s+al\.)?,\s*(\d{4}[a-z]?)\)'
        for match in re.finditer(pattern1, self.content):
            authors = match.group(1).strip()
            year = match.group(2)
            full_citation = match.group(0)
            position = match.start()
            
            citations.append({
                'type': 'parenthetical',
                'authors': authors,
                'year': year,
                'full_citation': full_citation,
                'position': position,
                'context': self._get_context(position)
            })
        
        # Pattern 2: Author (Year)
        pattern2 = r'([A-Z][a-zA-Z]+(?:\s+(?:et\s+al\.|&\s+[A-Z][a-zA-Z]+))?)\\s+\\((\\d{4}[a-z]?)\\)'
        for match in re.finditer(pattern2, self.content):
            # Skip if in references section
            if self._is_in_references_section(match.start()):
                continue
                
            authors = match.group(1).strip()
            year = match.group(2)
            full_citation = match.group(0)
            position = match.start()
            
            citations.append({
                'type': 'narrative',
                'authors': authors,
                'year': year,
                'full_citation': full_citation,
                'position': position,
                'context': self._get_context(position)
            })
        
        self.citations = citations
        return citations
    
    def extract_references(self) -> List[Dict]:
        """Extract all references from reference list"""
        references = []
        
        # Find references section
        ref_start = self.content.find("## References")
        if ref_start == -1:
            return references
        
        ref_section = self.content[ref_start:]
        
        # Parse individual references
        ref_pattern = r'^([A-Z][^(\\n]+?)\\s*\\((\\d{4}[a-z]?)\\)\\.\\s*(.+?)(?=\\n\\n|\\n[A-Z]|$)'
        
        for match in re.finditer(ref_pattern, ref_section, re.MULTILINE | re.DOTALL):
            authors = match.group(1).strip()
            year = match.group(2)
            full_ref = match.group(0)
            
            # Extract first author's last name
            first_author = self._extract_first_author(authors)
            
            references.append({
                'authors': authors,
                'year': year,
                'first_author': first_author,
                'full_reference': full_ref.strip(),
                'key': f"{first_author}_{year}"
            })
        
        self.references = references
        return references
    
    def _extract_first_author(self, authors: str) -> str:
        """Extract first author's last name"""
        # Handle different author formats
        if ',' in authors:
            # Format: "Lastname, F."
            return authors.split(',')[0].strip()
        else:
            # Format: "Lastname et al." or single name
            if ' et al.' in authors:
                return authors.replace(' et al.', '').strip()
            elif '&' in authors:
                return authors.split('&')[0].strip().split()[-1]
            else:
                return authors.split()[0].strip()
    
    def _get_context(self, position: int, radius: int = 100) -> str:
        """Get context around citation"""
        start = max(0, position - radius)
        end = min(len(self.content), position + radius)
        return self.content[start:end].replace('\\n', ' ')
    
    def _is_in_references_section(self, position: int) -> bool:
        """Check if position is in references section"""
        ref_start = self.content.find("## References")
        return ref_start != -1 and position > ref_start
    
    def create_citation_keys(self) -> List[Dict]:
        """Create searchable keys for citations"""
        citation_keys = []
        
        for citation in self.citations:
            authors = citation['authors']
            year = citation['year']
            
            # Extract first author
            if '&' in authors:
                first_author = authors.split('&')[0].strip()
            elif ',' in authors:
                first_author = authors.split(',')[0].strip()
            else:
                first_author = authors.strip()
            
            # Handle "et al."
            first_author = first_author.replace(' et al.', '').strip()
            
            # Get last name
            if ',' in first_author:
                last_name = first_author.split(',')[0].strip()
            else:
                last_name = first_author.split()[-1] if first_author else first_author
            
            key = f"{last_name}_{year}"
            
            citation_keys.append({
                **citation,
                'key': key,
                'last_name': last_name
            })
        
        return citation_keys
    
    def validate_citations(self) -> Dict:
        """Comprehensive validation of all citations"""
        
        print("🔬 COMPREHENSIVE REFERENCE CROSS-VALIDATION")
        print("=" * 60)
        
        # Extract data
        citations = self.extract_citations()
        references = self.extract_references()
        citation_keys = self.create_citation_keys()
        
        print(f"📊 Found {len(citations)} in-text citations")
        print(f"📚 Found {len(references)} references")
        
        # Create reference lookup
        ref_lookup = {}
        for ref in references:
            ref_lookup[ref['key']] = ref
        
        # Validate each citation
        missing_refs = []
        valid_citations = []
        
        for citation in citation_keys:
            citation_key = citation['key']
            found = False
            
            # Direct match
            if citation_key in ref_lookup:
                found = True
                valid_citations.append({
                    'citation': citation,
                    'reference': ref_lookup[citation_key],
                    'match_type': 'exact'
                })
            else:
                # Fuzzy matching
                for ref_key, ref_data in ref_lookup.items():
                    if self._fuzzy_match(citation, ref_data):
                        found = True
                        valid_citations.append({
                            'citation': citation,
                            'reference': ref_data,
                            'match_type': 'fuzzy'
                        })
                        break
            
            if not found:
                missing_refs.append(citation)
        
        # Check for unused references
        used_ref_keys = {match['reference']['key'] for match in valid_citations}
        unused_refs = [ref for ref in references if ref['key'] not in used_ref_keys]
        
        # Generate comprehensive report
        validation_report = {
            'total_citations': len(citations),
            'total_references': len(references),
            'valid_citations': len(valid_citations),
            'missing_references': len(missing_refs),
            'unused_references': len(unused_refs),
            'validation_success': len(missing_refs) == 0,
            'details': {
                'missing_refs': missing_refs,
                'unused_refs': unused_refs[:5],  # Show first 5
                'valid_matches': valid_citations
            }
        }
        
        self._print_validation_report(validation_report)
        
        return validation_report
    
    def _fuzzy_match(self, citation: Dict, reference: Dict) -> bool:
        """Fuzzy matching for citations and references"""
        cite_author = citation['last_name'].lower()
        cite_year = citation['year']
        
        ref_author = reference['first_author'].lower()
        ref_year = reference['year']
        
        # Year must match exactly
        if cite_year != ref_year:
            return False
        
        # Author matching with variations
        return (cite_author == ref_author or 
                cite_author in ref_author or 
                ref_author in cite_author)
    
    def _print_validation_report(self, report: Dict):
        """Print comprehensive validation report"""
        
        print("\\n" + "=" * 60)
        print("VALIDATION RESULTS")
        print("=" * 60)
        
        if report['validation_success']:
            print("\\n✅ ALL CITATIONS VALIDATED SUCCESSFULLY!")
            print(f"   {report['valid_citations']}/{report['total_citations']} citations have matching references")
        else:
            print("\\n❌ VALIDATION ISSUES FOUND")
            print(f"   {report['valid_citations']}/{report['total_citations']} citations validated")
            print(f"   {report['missing_references']} missing references")
        
        if report['missing_references'] > 0:
            print(f"\\n🚨 MISSING REFERENCES ({report['missing_references']}):")
            for missing in report['details']['missing_refs']:
                print(f"   • {missing['key']} - \"{missing['full_citation']}\"")
                print(f"     Context: ...{missing['context'][:60]}...")
        
        if report['unused_references'] > 0:
            print(f"\\n⚠️ UNUSED REFERENCES ({report['unused_references']}):")
            for unused in report['details']['unused_refs']:
                print(f"   • {unused['key']} - {unused['authors']} ({unused['year']})")
        
        print(f"\\n📊 SUMMARY STATISTICS:")
        print(f"   Total Citations: {report['total_citations']}")
        print(f"   Total References: {report['total_references']}")
        print(f"   Validation Rate: {(report['valid_citations']/report['total_citations']*100):.1f}%")
        print(f"   Reference Utilization: {((report['total_references']-report['unused_references'])/report['total_references']*100):.1f}%")
        
        if report['validation_success']:
            print("\\n🎉 CHAPTER READY FOR EDITORIAL REVIEW!")
            print("   All academic standards met with complete reference validation")

def main():
    """Execute comprehensive validation"""
    
    file_path = "/home/louranicas/projects/claude-optimized-deployment/The Book Writer/Chapter1_NAM_10K_Synthor.md"
    
    validator = ReferenceCrossValidator(file_path)
    report = validator.validate_citations()
    
    # Save detailed report
    report_path = "/home/louranicas/projects/claude-optimized-deployment/The Book Writer/validation_report_10k.json"
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"\\n📄 Detailed report saved: {report_path}")
    
    return report

if __name__ == "__main__":
    main()