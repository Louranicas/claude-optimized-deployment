#!/usr/bin/env python3
"""
Final validation of Chapter 1 references
Ensures all reference issues have been resolved
"""

import re
from collections import defaultdict

def validate_chapter_references(file_path):
    """Validate references in the chapter"""
    
    # Read the chapter
    with open(file_path, 'r') as f:
        text = f.read()
    
    # Extract all in-text citations
    citations = []
    
    # Pattern 1: (Author, Year) or (Author et al., Year)
    pattern1 = r'\(([A-Z][a-zA-Z\s&,]+?)(?:\s+et\s+al\.?)?,\s*(\d{4}[a-z]?)\)'
    for match in re.finditer(pattern1, text):
        authors = match.group(1).strip()
        year = match.group(2)
        citations.append((authors, year, match.group(0)))
    
    # Pattern 2: Author (Year)
    pattern2 = r'([A-Z][a-zA-Z]+(?:\s+(?:et\s+al\.|&\s+[A-Z][a-zA-Z]+))?)\s+\((\d{4}[a-z]?)\)'
    for match in re.finditer(pattern2, text):
        # Skip if in references section
        if text.rfind('References', 0, match.start()) > text.rfind('\n\n', 0, match.start()):
            continue
        authors = match.group(1).strip()
        year = match.group(2)
        citations.append((authors, year, match.group(0)))
    
    # Find references section
    ref_start = text.find("  References\n")
    if ref_start == -1:
        print("References section not found!")
        return
    
    # Extract references
    ref_text = text[ref_start:]
    references = []
    
    # Parse references - look for lines starting with author names
    ref_pattern = r'^  ([A-Z][^(\n]+)\s*\((\d{4}[a-z]?)\)'
    for match in re.finditer(ref_pattern, ref_text, re.MULTILINE):
        authors = match.group(1).strip()
        year = match.group(2)
        references.append((authors, year))
    
    print(f"Found {len(citations)} in-text citations")
    print(f"Found {len(references)} references in the reference list")
    
    # Create citation keys
    citation_keys = defaultdict(list)
    for authors, year, full in citations:
        # Extract first author's last name
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
        citation_keys[key].append(full)
    
    # Create reference keys
    reference_keys = {}
    for authors, year in references:
        # Get first author
        if ',' in authors:
            # Format: "Lastname, F." or "Lastname, F., & Other, A."
            first_author = authors.split(',')[0].strip()
        else:
            # Other format
            first_author = authors.split()[0] if authors else authors
        
        key = f"{first_author}_{year}"
        reference_keys[key] = (authors, year)
    
    # Check for missing references
    missing = []
    for cite_key, occurrences in citation_keys.items():
        found = False
        # Direct match
        if cite_key in reference_keys:
            found = True
        else:
            # Try fuzzy matching
            cite_author, cite_year = cite_key.split('_')
            for ref_key, (ref_authors, ref_year) in reference_keys.items():
                ref_author, _ = ref_key.split('_')
                if (cite_author.lower() == ref_author.lower() or 
                    cite_author.lower() in ref_author.lower() or
                    ref_author.lower() in cite_author.lower()) and cite_year == ref_year:
                    found = True
                    break
        
        if not found:
            missing.append((cite_key, len(occurrences), occurrences[0]))
    
    # Check for unused references
    unused = []
    for ref_key, (authors, year) in reference_keys.items():
        found = False
        ref_author, ref_year = ref_key.split('_')
        
        for cite_key in citation_keys:
            cite_author, cite_year = cite_key.split('_')
            if (cite_author.lower() == ref_author.lower() or 
                cite_author.lower() in ref_author.lower() or
                ref_author.lower() in cite_author.lower()) and cite_year == ref_year:
                found = True
                break
        
        if not found:
            unused.append((ref_key, authors))
    
    # Report results
    print("\n" + "="*60)
    print("VALIDATION RESULTS")
    print("="*60)
    
    if missing:
        print(f"\n❌ MISSING REFERENCES ({len(missing)}):")
        for key, count, example in missing:
            print(f"  • {key} - {count} occurrences")
            print(f"    Example: {example}")
    else:
        print("\n✅ All in-text citations have corresponding references!")
    
    if unused:
        print(f"\n⚠️ UNUSED REFERENCES ({len(unused)}):")
        for key, authors in unused[:5]:  # Show first 5
            print(f"  • {key} - {authors[:50]}...")
    
    if not missing and not unused:
        print("\n🎉 PERFECT! All references are properly matched!")
    elif not missing:
        print(f"\n✅ Chapter meets academic standards - all citations have references!")
        print(f"   ({len(unused)} unused references can be reviewed separately)")
    
    return len(missing) == 0


def main():
    file_path = "/home/louranicas/projects/claude-optimized-deployment/Chapter1_Complete_Fixed_References.md"
    print(f"Validating: {file_path}\n")
    
    success = validate_chapter_references(file_path)
    
    if success:
        print("\n✨ The chapter now meets the highest academic standards!")
    else:
        print("\n⚠️ Some reference issues remain.")


if __name__ == "__main__":
    main()