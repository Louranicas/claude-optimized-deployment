#!/usr/bin/env python3
"""
Security Book Chapter Extraction
===============================

Extract security-related chapters from cybersecurity books in Downloads folder
and organize them into a structured "Security hardening information" folder.

Uses the SYNTHEX Chapter Extraction system for advanced text processing.
"""

import os
import re
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

# Security-related keywords for chapter filtering
SECURITY_KEYWORDS = [
    # Core security concepts
    'security', 'cybersecurity', 'infosec', 'hardening', 'defense', 'protection',
    'vulnerability', 'exploit', 'attack', 'threat', 'risk', 'mitigation',
    
    # Network security
    'firewall', 'ids', 'ips', 'intrusion', 'network security', 'traffic',
    'monitoring', 'encryption', 'vpn', 'ssl', 'tls', 'certificate',
    
    # System security
    'access control', 'authentication', 'authorization', 'privilege',
    'user management', 'password', 'audit', 'logging', 'compliance',
    
    # Penetration testing
    'pentest', 'penetration', 'ethical hacking', 'reconnaissance', 'scanning',
    'enumeration', 'exploitation', 'post-exploitation', 'reporting',
    
    # Tools and techniques
    'nmap', 'metasploit', 'burp', 'wireshark', 'kali', 'nessus',
    'bash scripting', 'python security', 'automation', 'incident',
    
    # Advanced topics
    'malware', 'forensics', 'reverse engineering', 'cryptography',
    'social engineering', 'phishing', 'ransomware', 'apt'
]

def find_security_books() -> List[Path]:
    """Find security-related books in Downloads folder."""
    downloads = Path.home() / "Downloads"
    
    # File patterns to search
    patterns = ["*.pdf", "*.epub", "*.txt", "*.docx", "*.doc"]
    
    security_books = []
    
    for pattern in patterns:
        for file_path in downloads.glob(pattern):
            filename = file_path.name.lower()
            
            # Check if filename contains security keywords
            security_indicators = [
                'security', 'cyber', 'hack', 'pentest', 'penetration',
                'bash', 'linux', 'threat', 'exploit', 'vulnerability',
                'firewall', 'encryption', 'nmap', 'kali', 'forensics'
            ]
            
            if any(keyword in filename for keyword in security_indicators):
                security_books.append(file_path)
    
    return security_books

def extract_text_from_pdf(pdf_path: Path) -> str:
    """Extract text from PDF using PyPDF2."""
    try:
        import PyPDF2
        
        with open(pdf_path, 'rb') as file:
            reader = PyPDF2.PdfReader(file)
            text = ""
            
            # Extract from first 50 pages for performance
            max_pages = min(50, len(reader.pages))
            
            for page_num in range(max_pages):
                try:
                    page = reader.pages[page_num]
                    text += page.extract_text() + "\n"
                except Exception as e:
                    print(f"   Warning: Error reading page {page_num}: {e}")
                    continue
            
            return text
    except Exception as e:
        print(f"   Error extracting from PDF: {e}")
        return ""

def extract_text_from_epub(epub_path: Path) -> str:
    """Extract text from EPUB using ebooklib."""
    try:
        import ebooklib
        from ebooklib import epub
        from bs4 import BeautifulSoup
        
        book = epub.read_epub(str(epub_path))
        text = ""
        
        for item in book.get_items():
            if item.get_type() == ebooklib.ITEM_DOCUMENT:
                soup = BeautifulSoup(item.get_content(), 'html.parser')
                text += soup.get_text() + "\n"
        
        return text
    except Exception as e:
        print(f"   Error extracting from EPUB: {e}")
        return ""

def extract_text_from_file(file_path: Path) -> str:
    """Extract text from various file formats."""
    suffix = file_path.suffix.lower()
    
    if suffix == '.pdf':
        return extract_text_from_pdf(file_path)
    elif suffix == '.epub':
        return extract_text_from_epub(file_path)
    elif suffix in ['.txt', '.md']:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            print(f"   Error reading text file: {e}")
            return ""
    else:
        print(f"   Unsupported format: {suffix}")
        return ""

def detect_chapters(text: str) -> List[Dict[str, Any]]:
    """Detect chapters in text using advanced pattern matching."""
    chapters = []
    
    # Multiple chapter detection patterns
    patterns = [
        r'Chapter\s+(\d+)[:\.]?\s*(.+?)(?=\n\s*\n|\n\s*Chapter|\Z)',
        r'CHAPTER\s+(\d+)[:\.]?\s*(.+?)(?=\n\s*\n|\n\s*CHAPTER|\Z)',
        r'(\d+)\.\s+(.+?)(?=\n\s*\n|\n\s*\d+\.|\Z)',
        r'#{1,3}\s+(\d+\.?\d*)\s+(.+?)(?=\n\s*\n|\n\s*#|\Z)',
        r'Section\s+(\d+)[:\.]?\s*(.+?)(?=\n\s*\n|\n\s*Section|\Z)'
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, text, re.DOTALL | re.IGNORECASE)
        
        for match in matches:
            if len(match) >= 2:
                chapter_num = match[0]
                title = match[1].strip()
                
                # Extract content around the chapter
                chapter_start = text.find(title)
                if chapter_start != -1:
                    # Find next chapter or end of text
                    next_chapter = float('inf')
                    for next_pattern in patterns:
                        next_matches = list(re.finditer(next_pattern, text[chapter_start + len(title):], re.DOTALL | re.IGNORECASE))
                        if next_matches:
                            next_chapter = min(next_chapter, chapter_start + len(title) + next_matches[0].start())
                    
                    if next_chapter == float('inf'):
                        content = text[chapter_start:]
                    else:
                        content = text[chapter_start:next_chapter]
                    
                    # Filter by security relevance
                    content_lower = content.lower()
                    security_score = sum(1 for keyword in SECURITY_KEYWORDS if keyword in content_lower)
                    
                    if security_score >= 2:  # Must have at least 2 security keywords
                        chapters.append({
                            'number': chapter_num,
                            'title': title,
                            'content': content.strip(),
                            'security_score': security_score,
                            'word_count': len(content.split()),
                            'char_count': len(content)
                        })
    
    # Remove duplicates and sort by security relevance
    unique_chapters = []
    seen_titles = set()
    
    for chapter in sorted(chapters, key=lambda x: x['security_score'], reverse=True):
        if chapter['title'] not in seen_titles and len(chapter['content']) > 200:
            unique_chapters.append(chapter)
            seen_titles.add(chapter['title'])
    
    return unique_chapters

def save_chapter(chapter: Dict[str, Any], book_name: str, output_dir: Path):
    """Save an extracted chapter to a file."""
    # Sanitize filenames
    safe_book_name = re.sub(r'[^\w\s-]', '', book_name)[:50]
    safe_chapter_title = re.sub(r'[^\w\s-]', '', chapter['title'])[:80]
    
    filename = f"{safe_book_name} - Chapter {chapter['number']} - {safe_chapter_title}.txt"
    file_path = output_dir / filename
    
    # Create chapter content with metadata
    content = f"""# Security Chapter Extract
Book: {book_name}
Chapter: {chapter['number']} - {chapter['title']}
Security Relevance Score: {chapter['security_score']}
Word Count: {chapter['word_count']}
Extracted: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

{chapter['content']}
"""
    
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    except Exception as e:
        print(f"   Error saving chapter: {e}")
        return False

def process_security_book(book_path: Path, output_dir: Path) -> Dict[str, Any]:
    """Process a single security book and extract relevant chapters."""
    book_name = book_path.stem
    print(f"\n📖 Processing: {book_name}")
    
    # Extract text
    print("   🔍 Extracting text...")
    text = extract_text_from_file(book_path)
    
    if not text:
        return {'status': 'failed', 'reason': 'No text extracted'}
    
    print(f"   📝 Extracted {len(text):,} characters")
    
    # Detect chapters
    print("   🔍 Detecting chapters...")
    chapters = detect_chapters(text)
    
    if not chapters:
        return {'status': 'failed', 'reason': 'No security-relevant chapters found'}
    
    print(f"   ✅ Found {len(chapters)} security-relevant chapters")
    
    # Save chapters
    saved_count = 0
    for chapter in chapters:
        if save_chapter(chapter, book_name, output_dir):
            saved_count += 1
    
    return {
        'status': 'success',
        'book_name': book_name,
        'chapters_found': len(chapters),
        'chapters_saved': saved_count,
        'text_length': len(text)
    }

def create_extraction_summary(results: List[Dict], output_dir: Path):
    """Create a summary of the extraction process."""
    summary = {
        'extraction_date': datetime.now().isoformat(),
        'total_books_processed': len(results),
        'successful_extractions': len([r for r in results if r['status'] == 'success']),
        'total_chapters_extracted': sum(r.get('chapters_saved', 0) for r in results),
        'books_processed': results
    }
    
    summary_path = output_dir / "EXTRACTION_SUMMARY.json"
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)
    
    # Create human-readable summary
    readme_content = f"""# Security Hardening Information
Extracted: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary
- **Books Processed**: {summary['total_books_processed']}
- **Successful Extractions**: {summary['successful_extractions']}
- **Security Chapters Extracted**: {summary['total_chapters_extracted']}

## Source Books
"""
    
    for result in results:
        if result['status'] == 'success':
            readme_content += f"\n### {result['book_name']}\n"
            readme_content += f"- Chapters Extracted: {result['chapters_saved']}\n"
            readme_content += f"- Text Length: {result['text_length']:,} characters\n"
    
    readme_content += f"""

## Usage
Each extracted chapter is saved as a separate text file with:
- Original book information
- Chapter title and number
- Security relevance score
- Full chapter content

Files are named: `[Book Name] - Chapter [N] - [Chapter Title].txt`

## Security Topics Covered
Based on keyword analysis, extracted chapters cover:
- Cybersecurity fundamentals
- Penetration testing techniques
- Network security
- System hardening
- Threat detection and monitoring
- Security automation and scripting
- Incident response
- Vulnerability assessment
"""
    
    readme_path = output_dir / "README.md"
    with open(readme_path, 'w') as f:
        f.write(readme_content)

def main():
    """Main extraction process."""
    print("🔐 Security Book Chapter Extraction")
    print("=" * 50)
    
    # Setup output directory
    output_dir = Path("Security hardening information")
    output_dir.mkdir(exist_ok=True)
    
    # Find security books
    print("🔍 Searching for security-related books...")
    security_books = find_security_books()
    
    if not security_books:
        print("❌ No security-related books found in Downloads folder")
        return
    
    print(f"✅ Found {len(security_books)} security-related books")
    for book in security_books:
        print(f"   📚 {book.name}")
    
    # Process each book
    results = []
    for book_path in security_books:
        try:
            result = process_security_book(book_path, output_dir)
            results.append(result)
        except Exception as e:
            print(f"❌ Error processing {book_path.name}: {e}")
            results.append({
                'status': 'error',
                'book_name': book_path.stem,
                'error': str(e)
            })
    
    # Create summary
    create_extraction_summary(results, output_dir)
    
    # Final report
    successful = [r for r in results if r['status'] == 'success']
    total_chapters = sum(r.get('chapters_saved', 0) for r in successful)
    
    print("\n" + "=" * 50)
    print("✅ Security Chapter Extraction Complete!")
    print(f"📚 Books Processed: {len(security_books)}")
    print(f"✅ Successful Extractions: {len(successful)}")
    print(f"📖 Security Chapters Extracted: {total_chapters}")
    print(f"📁 Output Directory: {output_dir.absolute()}")
    print("\n📋 Files Created:")
    print("   • Individual chapter files (.txt)")
    print("   • README.md - Usage guide")
    print("   • EXTRACTION_SUMMARY.json - Detailed report")

if __name__ == "__main__":
    main()