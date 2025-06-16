"""
SYNTHEX Text Parser Module
Efficient text extraction from various file formats
"""

import hashlib
import mimetypes
from abc import ABC, abstractmethod
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Union
import logging

from src.core.exceptions import SynthexError

logger = logging.getLogger(__name__)


class TextParsingError(SynthexError):
    """Raised when text parsing fails"""
    pass


class BaseTextParser(ABC):
    """Abstract base class for text parsers"""
    
    def __init__(self, preserve_formatting: bool = False, 
                 chunk_size: int = 1024 * 1024):  # 1MB default
        self.preserve_formatting = preserve_formatting
        self.chunk_size = chunk_size
        
    @abstractmethod
    def parse(self, file_path: Union[str, Path]) -> Iterator[Dict[str, Any]]:
        """Parse file and yield content chunks"""
        pass
        
    @abstractmethod
    def extract_metadata(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """Extract file metadata"""
        pass
        
    def validate_file(self, file_path: Union[str, Path]) -> Path:
        """Validate file exists and is readable"""
        path = Path(file_path)
        if not path.exists():
            raise TextParsingError(f"File not found: {file_path}")
        if not path.is_file():
            raise TextParsingError(f"Not a file: {file_path}")
        return path


class PDFParser(BaseTextParser):
    """Optimized PDF parser with multiple backend support"""
    
    def __init__(self, backend: str = 'auto', **kwargs):
        super().__init__(**kwargs)
        self.backend = backend
        self._backends = {
            'pymupdf': self._parse_with_pymupdf,
            'pdfplumber': self._parse_with_pdfplumber,
            'pypdf2': self._parse_with_pypdf2
        }
        
    def parse(self, file_path: Union[str, Path]) -> Iterator[Dict[str, Any]]:
        path = self.validate_file(file_path)
        
        if self.backend == 'auto':
            backend = self._detect_optimal_backend(path)
        else:
            backend = self.backend
            
        parser_func = self._backends.get(backend)
        if not parser_func:
            raise TextParsingError(f"Unknown backend: {backend}")
            
        yield from parser_func(path)
        
    def _detect_optimal_backend(self, path: Path) -> str:
        """Detect optimal backend based on PDF characteristics"""
        file_size_mb = path.stat().st_size / (1024 * 1024)
        
        # Use PyMuPDF for large files or when performance is critical
        if file_size_mb > 10:
            return 'pymupdf'\n\n        # Quick check for complex layouts (tables, forms)\n        try:\n            import pdfplumber\n            with pdfplumber.open(path) as pdf:\n                first_page = pdf.pages[0] if pdf.pages else None\n                if first_page and first_page.extract_tables():\n                    return 'pdfplumber'\n        except:\n            pass\n\n        return 'pymupdf'  # Default to fastest option\n\n    def _parse_with_pymupdf(self, path: Path) -> Iterator[Dict[str, Any]]:\n        """Parse PDF using PyMuPDF (fitz) - fastest option"""\n        try:\n            import fitz\n        except ImportError:\n            raise TextParsingError("PyMuPDF not installed. Install with: pip install PyMuPDF")\n\n        doc = fitz.open(path)\n        try:\n            for page_num in range(len(doc)):\n                page = doc[page_num]\n                text = page.get_text()\n\n                result = {\n                    'page': page_num + 1,\n                    'text': text,\n                    'type': 'pdf_page'\n                }\n\n                if self.preserve_formatting:\n                    result['blocks'] = page.get_text('blocks')\n                    result['links'] = [link for link in page.get_links()]\n\n                yield result\n\n                # Free memory for processed page\n                doc[page_num] = None\n\n        finally:\n            doc.close()\n\n    def _parse_with_pdfplumber(self, path: Path) -> Iterator[Dict[str, Any]]:\n        """Parse PDF using pdfplumber - best for complex layouts"""\n        try:\n            import pdfplumber\n        except ImportError:\n            raise TextParsingError("pdfplumber not installed. Install with: pip install pdfplumber")\n\n        with pdfplumber.open(path) as pdf:\n            for page_num, page in enumerate(pdf.pages):\n                text = page.extract_text() or ""\n\n                result = {\n                    'page': page_num + 1,\n                    'text': text,\n                    'type': 'pdf_page'\n                }\n\n                if self.preserve_formatting:\n                    tables = page.extract_tables()\n                    if tables:\n                        result['tables'] = tables\n\n                yield result\n\n    def _parse_with_pypdf2(self, path: Path) -> Iterator[Dict[str, Any]]:\n        """Parse PDF using PyPDF2 - lightweight option"""\n        try:\n            import PyPDF2\n        except ImportError:\n            raise TextParsingError("PyPDF2 not installed. Install with: pip install PyPDF2")\n\n        with open(path, 'rb') as file:\n            reader = PyPDF2.PdfReader(file)\n\n            for page_num, page in enumerate(reader.pages):\n                text = page.extract_text()\n\n                yield {\n                    'page': page_num + 1,\n                    'text': text,\n                    'type': 'pdf_page'\n                }\n\n    def extract_metadata(self, file_path: Union[str, Path]) -> Dict[str, Any]:\n        path = self.validate_file(file_path)\n\n        try:\n            import fitz\n            doc = fitz.open(path)\n            metadata = doc.metadata or {}\n            page_count = len(doc)\n            doc.close()\n\n            return {\n                'title': metadata.get('title', ''),\n                'author': metadata.get('author', ''),\n                'subject': metadata.get('subject', ''),\n                'pages': page_count,\n                'format': 'pdf'\n            }\n        except:\n            return {'format': 'pdf', 'error': 'Could not extract metadata'}\n\n\nclass DOCXParser(BaseTextParser):\n    """Parser for Microsoft Word documents"""\n\n    def parse(self, file_path: Union[str, Path]) -> Iterator[Dict[str, Any]]:\n        path = self.validate_file(file_path)\n\n        try:\n            from docx import Document\n        except ImportError:\n            raise TextParsingError("python-docx not installed. Install with: pip install python-docx")\n\n        doc = Document(path)\n\n        # Yield paragraphs in chunks\n        chunk_text = []\n        chunk_size = 0\n\n        for para_num, paragraph in enumerate(doc.paragraphs):\n            para_text = paragraph.text\n            para_size = len(para_text.encode('utf-8'))\n\n            if chunk_size + para_size > self.chunk_size and chunk_text:\n                yield {\n                    'text': '\n'.join(chunk_text),\n                    'type': 'docx_chunk',\n                    'start_paragraph': para_num - len(chunk_text),\n                    'end_paragraph': para_num - 1\n                }\n                chunk_text = []\n                chunk_size = 0\n\n            chunk_text.append(para_text)\n            chunk_size += para_size\n\n        # Yield remaining text\n        if chunk_text:\n            yield {\n                'text': '\n'.join(chunk_text),\n                'type': 'docx_chunk',\n                'start_paragraph': len(doc.paragraphs) - len(chunk_text),\n                'end_paragraph': len(doc.paragraphs) - 1\n            }\n\n    def extract_metadata(self, file_path: Union[str, Path]) -> Dict[str, Any]:\n        path = self.validate_file(file_path)\n\n        try:\n            from docx import Document\n            doc = Document(path)\n\n            core_props = doc.core_properties\n            return {\n                'title': core_props.title or '',\n                'author': core_props.author or '',\n                'created': str(core_props.created) if core_props.created else '',\n                'modified': str(core_props.modified) if core_props.modified else '',\n                'format': 'docx'\n            }\n        except:\n            return {'format': 'docx', 'error': 'Could not extract metadata'}\n\n\nclass PlainTextParser(BaseTextParser):\n    """Parser for plain text files with encoding detection"""\n\n    def __init__(self, encoding: Optional[str] = None,\n                 fallback_encodings: List[str] = None, **kwargs):\n        super().__init__(**kwargs)\n        self.encoding = encoding\n        self.fallback_encodings = fallback_encodings or ['utf-8', 'latin-1', 'cp1252']\n\n    def parse(self, file_path: Union[str, Path]) -> Iterator[Dict[str, Any]]:\n        path = self.validate_file(file_path)\n\n        encoding = self._detect_encoding(path)\n\n        with open(path, 'r', encoding=encoding) as file:\n            chunk_lines = []\n            chunk_size = 0\n            line_num = 0\n\n            for line in file:\n                line_size = len(line.encode('utf-8'))\n\n                if chunk_size + line_size > self.chunk_size and chunk_lines:\n                    yield {\n                        'text': ''.join(chunk_lines),\n                        'type': 'text_chunk',\n                        'start_line': line_num - len(chunk_lines) + 1,\n                        'end_line': line_num,\n                        'encoding': encoding\n                    }\n                    chunk_lines = []\n                    chunk_size = 0\n\n                chunk_lines.append(line)\n                chunk_size += line_size\n                line_num += 1\n\n            # Yield remaining text\n            if chunk_lines:\n                yield {\n                    'text': ''.join(chunk_lines),\n                    'type': 'text_chunk',\n                    'start_line': line_num - len(chunk_lines) + 1,\n                    'end_line': line_num,\n                    'encoding': encoding\n                }\n\n    def _detect_encoding(self, path: Path) -> str:\n        """Detect file encoding with fallbacks"""\n        if self.encoding:\n            return self.encoding\n\n        # Try chardet for automatic detection\n        try:\n            import chardet\n            with open(path, 'rb') as file:\n                raw_data = file.read(10000)  # Read first 10KB\n                result = chardet.detect(raw_data)\n                if result['confidence'] > 0.8:\n                    return result['encoding']\n        except:\n            pass\n\n        # Try fallback encodings\n        for encoding in self.fallback_encodings:\n            try:\n                with open(path, 'r', encoding=encoding) as file:\n                    file.read(1000)  # Try reading first 1KB\n                return encoding\n            except UnicodeDecodeError:\n                continue\n\n        raise TextParsingError(f"Could not detect encoding for {path}")\n\n    def extract_metadata(self, file_path: Union[str, Path]) -> Dict[str, Any]:\n        path = self.validate_file(file_path)\n\n        stat = path.stat()\n        return {\n            'size': stat.st_size,\n            'modified': stat.st_mtime,\n            'encoding': self._detect_encoding(path),\n            'format': 'text'\n        }\n\n\nclass EPUBParser(BaseTextParser):\n    """Parser for EPUB e-book files"""\n\n    def parse(self, file_path: Union[str, Path]) -> Iterator[Dict[str, Any]]:\n        path = self.validate_file(file_path)\n\n        try:\n            import ebooklib\n            from ebooklib import epub\n        except ImportError:\n            raise TextParsingError("ebooklib not installed. Install with: pip install EbookLib")\n\n        book = epub.read_epub(path)\n\n        for item in book.get_items():\n            if item.get_type() == ebooklib.ITEM_DOCUMENT:\n                try:\n                    content = item.get_content().decode('utf-8')\n\n                    # Extract text from HTML content\n                    text = self._extract_text_from_html(content)\n\n                    if text.strip():\n                        yield {\n                            'chapter': item.get_name(),\n                            'text': text,\n                            'type': 'epub_chapter',\n                            'spine_position': item.get_id()\n                        }\n                except Exception as e:\n                    logger.warning(f"Failed to parse chapter {item.get_name()}: {e}")\n\n    def _extract_text_from_html(self, html_content: str) -> str:\n        """Extract plain text from HTML content"""\n        try:\n            from bs4 import BeautifulSoup\n            soup = BeautifulSoup(html_content, 'html.parser')\n            return soup.get_text(separator='\n', strip=True)\n        except ImportError:\n            # Fallback to simple regex-based extraction\n            import re\n            text = re.sub(r'<[^>]+>', '', html_content)\n            return '\n'.join(line.strip() for line in text.split('
') if line.strip())
            
    def extract_metadata(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        path = self.validate_file(file_path)
        
        try:
            import ebooklib
            from ebooklib import epub
            
            book = epub.read_epub(path)
            
            # Extract metadata
            metadata = {}
            for key, value in book.metadata.items():
                if key.startswith('DC:') or key.startswith('OPF:'):
                    clean_key = key.split(':')[1] if ':' in key else key
                    if isinstance(value, list) and value:
                        metadata[clean_key] = value[0][0] if isinstance(value[0], tuple) else value[0]
                    
            return {
                'title': metadata.get('title', ''),
                'author': metadata.get('creator', ''),
                'language': metadata.get('language', ''),
                'publisher': metadata.get('publisher', ''),
                'format': 'epub'
            }
        except:
            return {'format': 'epub', 'error': 'Could not extract metadata'}


class HTMLParser(BaseTextParser):
    """Parser for HTML files"""
    
    def __init__(self, parser_backend: str = 'auto', **kwargs):
        super().__init__(**kwargs)
        self.parser_backend = parser_backend
        
    def parse(self, file_path: Union[str, Path]) -> Iterator[Dict[str, Any]]:
        path = self.validate_file(file_path)
        
        encoding = self._detect_encoding(path)
        
        with open(path, 'r', encoding=encoding) as file:
            content = file.read()
            
        # Parse HTML and extract text
        if self.parser_backend == 'auto':
            backend = self._detect_optimal_backend()
        else:
            backend = self.parser_backend
            
        if backend == 'lxml':
            text = self._parse_with_lxml(content)
        else:  # beautifulsoup
            text = self._parse_with_beautifulsoup(content)
            
        # Yield in chunks
        if len(text.encode('utf-8')) > self.chunk_size:
            for chunk in self._split_into_chunks(text):
                yield {
                    'text': chunk,
                    'type': 'html_chunk',
                    'encoding': encoding
                }
        else:
            yield {
                'text': text,
                'type': 'html_content',
                'encoding': encoding
            }
            
    def _detect_optimal_backend(self) -> str:
        """Detect best available HTML parser"""
        try:
            import lxml
            return 'lxml'
        except ImportError:
            return 'beautifulsoup'
            
    def _parse_with_lxml(self, content: str) -> str:
        """Parse HTML using lxml (faster)"""
        try:
            from lxml import html
            tree = html.fromstring(content)
            return tree.text_content()
        except ImportError:
            return self._parse_with_beautifulsoup(content)
            
    def _parse_with_beautifulsoup(self, content: str) -> str:
        """Parse HTML using BeautifulSoup (more robust)"""
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(content, 'html.parser')
            return soup.get_text(separator='
', strip=True)
        except ImportError:
            # Fallback to regex
            import re
            text = re.sub(r'<[^>]+>', '', content)
            return '
'.join(line.strip() for line in text.split('
') if line.strip())
            
    def _detect_encoding(self, path: Path) -> str:
        """Detect HTML file encoding"""
        try:
            import chardet
            with open(path, 'rb') as file:
                raw_data = file.read(10000)
                result = chardet.detect(raw_data)
                if result['confidence'] > 0.8:
                    return result['encoding']
        except:
            pass
            
        # Try common encodings
        for encoding in ['utf-8', 'latin-1', 'cp1252']:
            try:
                with open(path, 'r', encoding=encoding) as file:
                    file.read(1000)
                return encoding
            except UnicodeDecodeError:
                continue
                
        return 'utf-8'  # Default fallback
        
    def _split_into_chunks(self, text: str) -> Iterator[str]:
        """Split text into chunks"""
        words = text.split()
        current_chunk = []
        current_size = 0
        
        for word in words:
            word_size = len(word.encode('utf-8'))
            if current_size + word_size > self.chunk_size and current_chunk:
                yield ' '.join(current_chunk)
                current_chunk = [word]
                current_size = word_size
            else:
                current_chunk.append(word)
                current_size += word_size + 1  # +1 for space
                
        if current_chunk:
            yield ' '.join(current_chunk)
            
    def extract_metadata(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        path = self.validate_file(file_path)
        
        try:
            encoding = self._detect_encoding(path)
            with open(path, 'r', encoding=encoding) as file:
                content = file.read(2000)  # Read first 2KB for metadata
                
            # Extract basic HTML metadata
            metadata = {'format': 'html', 'encoding': encoding}
            
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(content, 'html.parser')
                
                # Extract title
                title_tag = soup.find('title')
                if title_tag:
                    metadata['title'] = title_tag.get_text().strip()
                    
                # Extract meta tags
                for meta in soup.find_all('meta'):
                    name = meta.get('name', '').lower()
                    if name in ['author', 'description', 'keywords']:
                        metadata[name] = meta.get('content', '')
                        
            except ImportError:
                # Fallback regex extraction
                import re
                title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
                if title_match:
                    metadata['title'] = title_match.group(1).strip()
                    
            return metadata
        except:
            return {'format': 'html', 'error': 'Could not extract metadata'}


class MarkdownParser(BaseTextParser):
    """Parser for Markdown files"""
    
    def parse(self, file_path: Union[str, Path]) -> Iterator[Dict[str, Any]]:
        path = self.validate_file(file_path)
        
        encoding = self._detect_encoding(path)
        
        with open(path, 'r', encoding=encoding) as file:
            # Parse markdown by sections
            current_section = []
            current_heading = ""
            
            for line_num, line in enumerate(file, 1):
                if line.startswith('#'):
                    # New heading found
                    if current_section:
                        yield {
                            'text': ''.join(current_section),
                            'heading': current_heading,
                            'type': 'markdown_section',
                            'encoding': encoding
                        }
                        current_section = []
                        
                    current_heading = line.strip()
                    
                current_section.append(line)
                
                # Check if we need to yield a chunk
                if len(''.join(current_section).encode('utf-8')) > self.chunk_size:
                    yield {
                        'text': ''.join(current_section),
                        'heading': current_heading,
                        'type': 'markdown_section',
                        'encoding': encoding
                    }
                    current_section = []
                    current_heading = ""
                    
            # Yield remaining content
            if current_section:
                yield {
                    'text': ''.join(current_section),
                    'heading': current_heading,
                    'type': 'markdown_section',
                    'encoding': encoding
                }
                
    def _detect_encoding(self, path: Path) -> str:
        """Detect file encoding"""
        for encoding in ['utf-8', 'latin-1', 'cp1252']:
            try:
                with open(path, 'r', encoding=encoding) as file:
                    file.read(1000)
                return encoding
            except UnicodeDecodeError:
                continue
        return 'utf-8'
        
    def extract_metadata(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        path = self.validate_file(file_path)
        
        encoding = self._detect_encoding(path)
        
        with open(path, 'r', encoding=encoding) as file:
            content = file.read(2000)  # Read first 2KB
            
        metadata = {'format': 'markdown', 'encoding': encoding}
        
        # Extract YAML frontmatter if present
        if content.startswith('---'):
            try:
                import yaml
                parts = content.split('---', 2)
                if len(parts) >= 2:
                    frontmatter = yaml.safe_load(parts[1])
                    if isinstance(frontmatter, dict):
                        metadata.update(frontmatter)
            except:
                pass
                
        # Extract first heading as title
        import re
        heading_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
        if heading_match and 'title' not in metadata:
            metadata['title'] = heading_match.group(1).strip()
            
        return metadata


class UnifiedTextParser:
    """Unified parser supporting multiple file formats"""
    
    def __init__(self, cache_dir: Optional[Path] = None,
                 max_workers: Optional[int] = None):
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.max_workers = max_workers
        
        self._parsers = {
            '.pdf': PDFParser,
            '.docx': DOCXParser,
            '.epub': EPUBParser,
            '.html': HTMLParser,
            '.htm': HTMLParser,
            '.md': MarkdownParser,
            '.markdown': MarkdownParser,
            '.txt': PlainTextParser,
            '.log': PlainTextParser,
        }
        
        if self.cache_dir:
            self.cache_dir.mkdir(exist_ok=True)
            
    def parse(self, file_path: Union[str, Path], 
              use_cache: bool = True, **parser_kwargs) -> Iterator[Dict[str, Any]]:
        """Parse file with appropriate parser"""
        path = Path(file_path)
        
        # Check cache first
        if use_cache and self.cache_dir:
            cached = self._get_cached(path)
            if cached:
                yield from cached
                return
                
        # Get appropriate parser
        parser_class = self._get_parser_class(path)
        parser = parser_class(**parser_kwargs)
        
        # Parse and optionally cache
        results = []
        for chunk in parser.parse(path):
            results.append(chunk)
            yield chunk
            
        if use_cache and self.cache_dir:
            self._cache_results(path, results)
            
    def parse_batch(self, file_paths: List[Union[str, Path]], 
                    parallel: bool = True, **parser_kwargs) -> Iterator[Dict[str, Any]]:
        """Parse multiple files in parallel"""
        if not parallel:
            for path in file_paths:
                for chunk in self.parse(path, **parser_kwargs):
                    yield {'file': str(path), 'chunk': chunk}
        else:
            with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
                futures = []
                for path in file_paths:
                    future = executor.submit(self._parse_file, path, parser_kwargs)
                    futures.append((path, future))
                    
                for path, future in futures:
                    try:
                        results = future.result(timeout=300)  # 5 min timeout
                        for chunk in results:
                            yield {'file': str(path), 'chunk': chunk}
                    except Exception as e:
                        logger.error(f"Failed to parse {path}: {e}")
                        yield {'file': str(path), 'error': str(e)}
                        
    def _parse_file(self, path: Union[str, Path], 
                    parser_kwargs: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse single file (for parallel execution)"""
        return list(self.parse(path, use_cache=False, **parser_kwargs))
        
    def _get_parser_class(self, path: Path) -> type:
        """Get appropriate parser class for file"""
        suffix = path.suffix.lower()
        parser_class = self._parsers.get(suffix)
        
        if not parser_class:
            # Try to detect by mimetype
            mime_type, _ = mimetypes.guess_type(str(path))
            if mime_type:
                if 'pdf' in mime_type:
                    parser_class = PDFParser
                elif 'word' in mime_type or 'document' in mime_type:
                    parser_class = DOCXParser
                else:
                    parser_class = PlainTextParser
            else:
                parser_class = PlainTextParser
                
        return parser_class
        
    def _get_cache_key(self, path: Path) -> str:
        """Generate cache key for file"""
        stat = path.stat()
        key_str = f"{path}:{stat.st_mtime}:{stat.st_size}"
        return hashlib.md5(key_str.encode()).hexdigest()
        
    def _get_cached(self, path: Path) -> Optional[List[Dict[str, Any]]]:
        """Get cached parse results"""
        if not self.cache_dir:
            return None
            
        cache_key = self._get_cache_key(path)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        if cache_file.exists():
            try:
                import json
                with open(cache_file, 'r') as f:
                    return json.load(f)
            except:
                pass
                
        return None
        
    def _cache_results(self, path: Path, results: List[Dict[str, Any]]):
        """Cache parse results"""
        if not self.cache_dir:
            return
            
        cache_key = self._get_cache_key(path)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        try:
            import json
            with open(cache_file, 'w') as f:
                json.dump(results, f)
        except Exception as e:
            logger.warning(f"Failed to cache results for {path}: {e}")


# Example usage
if __name__ == "__main__":
    # Initialize unified parser
    parser = UnifiedTextParser(cache_dir=Path("./text_cache"))
    
    # Parse single file
    for chunk in parser.parse("document.pdf", preserve_formatting=True):
        print(f"Chunk type: {chunk['type']}, size: {len(chunk['text'])}")
        
    # Parse multiple files in parallel
    files = ["doc1.pdf", "doc2.docx", "doc3.txt"]
    for result in parser.parse_batch(files, parallel=True):
        if 'error' in result:
            print(f"Error parsing {result['file']}: {result['error']}")
        else:
            print(f"Parsed {result['file']}: {result['chunk']['type']}")