#!/usr/bin/env python3
"""
Comprehensive Documentation Validation Suite
Validates and ensures consistency across all project documentation.
"""

import os
import re
import json
import requests
import yaml
from pathlib import Path
from collections import defaultdict, Counter
from typing import Dict, List, Set, Tuple
from urllib.parse import urljoin, urlparse
import logging
from dataclasses import dataclass
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class ValidationIssue:
    """Represents a documentation validation issue"""
    file_path: str
    issue_type: str
    severity: str  # critical, high, medium, low
    description: str
    line_number: int = 0
    suggested_fix: str = ""

@dataclass
class DocumentStats:
    """Statistics about a document"""
    file_path: str
    word_count: int
    line_count: int
    internal_links: List[str]
    external_links: List[str]
    code_blocks: int
    headers: List[str]
    last_modified: str

class DocumentationValidator:
    """Main documentation validation class"""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.issues: List[ValidationIssue] = []
        self.doc_stats: List[DocumentStats] = []
        self.all_files: Set[str] = set()
        self.terminology_map: Dict[str, Set[str]] = defaultdict(set)
        self.cross_references: Dict[str, List[str]] = defaultdict(list)
        
    def scan_all_documentation(self) -> None:
        """Scan and inventory all documentation files"""
        logger.info("Scanning all documentation files...")
        
        doc_patterns = [
            "**/*.md", "**/*.rst", "**/*.txt", "**/*.adoc",
            "**/README*", "**/CHANGELOG*", "**/LICENSE*"
        ]
        
        for pattern in doc_patterns:
            for file_path in self.project_root.glob(pattern):
                if self._should_include_file(file_path):
                    self.all_files.add(str(file_path.relative_to(self.project_root)))
                    
        logger.info(f"Found {len(self.all_files)} documentation files")
    
    def _should_include_file(self, file_path: Path) -> bool:
        """Check if file should be included in validation"""
        exclude_patterns = [
            'node_modules', '.git', '__pycache__', 'venv', '.venv',
            'target', '.pytest_cache', '.mypy_cache', 'dist', 'build'
        ]
        
        path_str = str(file_path)
        return not any(pattern in path_str for pattern in exclude_patterns)
    
    def analyze_document(self, file_path: str) -> DocumentStats:
        """Analyze a single document and extract statistics"""
        full_path = self.project_root / file_path
        
        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            logger.warning(f"Could not read {file_path}: {e}")
            return DocumentStats(file_path, 0, 0, [], [], 0, [], "")
        
        lines = content.split('\n')
        words = len(content.split())
        
        # Extract links
        internal_links = self._extract_internal_links(content)
        external_links = self._extract_external_links(content)
        
        # Count code blocks
        code_blocks = len(re.findall(r'```[\s\S]*?```|`[^`]+`', content))
        
        # Extract headers
        headers = re.findall(r'^#+\s+(.+)$', content, re.MULTILINE)
        
        # Get modification time
        last_modified = datetime.fromtimestamp(full_path.stat().st_mtime).isoformat()
        
        stats = DocumentStats(
            file_path=file_path,
            word_count=words,
            line_count=len(lines),
            internal_links=internal_links,
            external_links=external_links,
            code_blocks=code_blocks,
            headers=headers,
            last_modified=last_modified
        )
        
        self.doc_stats.append(stats)
        return stats
    
    def _extract_internal_links(self, content: str) -> List[str]:
        """Extract internal links from document content"""
        # Markdown links: [text](./path) or [text](path.md)
        internal_pattern = r'\[([^\]]+)\]\(([^)]+(?:\.md|\.rst|\.txt|\.adoc|#[^)]*)?)\)'
        matches = re.findall(internal_pattern, content)
        
        internal_links = []
        for text, link in matches:
            if not link.startswith(('http://', 'https://', 'mailto:')):
                internal_links.append(link)
        
        return internal_links
    
    def _extract_external_links(self, content: str) -> List[str]:
        """Extract external links from document content"""
        # External URLs
        external_pattern = r'\[([^\]]+)\]\((https?://[^)]+)\)'
        matches = re.findall(external_pattern, content)
        return [link for text, link in matches]
    
    def validate_cross_references(self) -> None:
        """Validate all cross-references and internal links"""
        logger.info("Validating cross-references and internal links...")
        
        for stats in self.doc_stats:
            base_dir = Path(stats.file_path).parent
            
            for link in stats.internal_links:
                # Skip anchor links for now
                if link.startswith('#'):
                    continue
                    
                # Resolve relative paths
                if link.startswith('./'):
                    link = link[2:]
                
                target_path = (base_dir / link).resolve()
                relative_target = target_path.relative_to(self.project_root)
                
                if str(relative_target) not in self.all_files:
                    # Check if it's a directory with README
                    if target_path.is_dir():
                        readme_candidates = ['README.md', 'README.rst', 'README.txt']
                        found_readme = False
                        for readme in readme_candidates:
                            readme_path = target_path / readme
                            if readme_path.exists():
                                found_readme = True
                                break
                        
                        if not found_readme:
                            self.issues.append(ValidationIssue(
                                file_path=stats.file_path,
                                issue_type="broken_internal_link",
                                severity="high",
                                description=f"Internal link points to directory without README: {link}"
                            ))
                    else:
                        self.issues.append(ValidationIssue(
                            file_path=stats.file_path,
                            issue_type="broken_internal_link",
                            severity="high",
                            description=f"Internal link points to non-existent file: {link}"
                        ))
    
    def validate_external_links(self) -> None:
        """Validate external links (with rate limiting)"""
        logger.info("Validating external links...")
        
        unique_external_links = set()
        for stats in self.doc_stats:
            unique_external_links.update(stats.external_links)
        
        logger.info(f"Found {len(unique_external_links)} unique external links")
        
        # Validate a sample of external links (to avoid rate limiting)
        import time
        for i, link in enumerate(list(unique_external_links)[:20]):  # Limit to first 20
            try:
                response = requests.head(link, timeout=10, allow_redirects=True)
                if response.status_code >= 400:
                    self.issues.append(ValidationIssue(
                        file_path="multiple",
                        issue_type="broken_external_link",
                        severity="medium",
                        description=f"External link returns {response.status_code}: {link}"
                    ))
                time.sleep(0.5)  # Rate limiting
            except Exception as e:
                self.issues.append(ValidationIssue(
                    file_path="multiple",
                    issue_type="broken_external_link",
                    severity="medium",
                    description=f"External link failed to load: {link} - {str(e)}"
                ))
    
    def analyze_terminology_consistency(self) -> None:
        """Analyze terminology usage across documents"""
        logger.info("Analyzing terminology consistency...")
        
        # Common technical terms that should be consistent
        key_terms = [
            'API', 'REST API', 'GraphQL', 'JSON', 'YAML', 'XML',
            'Docker', 'Kubernetes', 'k8s', 'MCP', 'Claude Code',
            'Python', 'Rust', 'JavaScript', 'TypeScript',
            'database', 'DB', 'PostgreSQL', 'Redis', 'MongoDB',
            'authentication', 'authorization', 'OAuth', 'JWT',
            'CI/CD', 'continuous integration', 'continuous deployment'
        ]
        
        term_usage = defaultdict(lambda: defaultdict(int))
        
        for stats in self.doc_stats:
            try:
                with open(self.project_root / stats.file_path, 'r', encoding='utf-8') as f:
                    content = f.read().lower()
                    
                for term in key_terms:
                    count = content.count(term.lower())
                    if count > 0:
                        term_usage[term][stats.file_path] = count
            except:
                continue
        
        # Check for inconsistent terminology
        for term, files in term_usage.items():
            if len(files) > 1:
                self.terminology_map[term] = set(files.keys())
    
    def check_formatting_consistency(self) -> None:
        """Check formatting consistency across documents"""
        logger.info("Checking formatting consistency...")
        
        header_styles = defaultdict(list)
        code_block_styles = defaultdict(list)
        
        for stats in self.doc_stats:
            try:
                with open(self.project_root / stats.file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                # Check header styles
                headers = re.findall(r'^(#+)\s+', content, re.MULTILINE)
                if headers:
                    header_styles[len(headers[0])].append(stats.file_path)
                
                # Check code block styles
                if '```' in content:
                    code_block_styles['fenced'].append(stats.file_path)
                if re.search(r'^    [^\s]', content, re.MULTILINE):
                    code_block_styles['indented'].append(stats.file_path)
                    
            except:
                continue
        
        # Report inconsistencies
        if len(code_block_styles) > 1:
            self.issues.append(ValidationIssue(
                file_path="multiple",
                issue_type="inconsistent_formatting",
                severity="low",
                description="Mixed code block styles found across documents"
            ))
    
    def validate_code_examples(self) -> None:
        """Validate code examples in documentation"""
        logger.info("Validating code examples...")
        
        for stats in self.doc_stats:
            try:
                with open(self.project_root / stats.file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                # Find code blocks
                code_blocks = re.findall(r'```(\w+)?\n(.*?)```', content, re.DOTALL)
                
                for language, code in code_blocks:
                    if language in ['python', 'py']:
                        self._validate_python_code(stats.file_path, code)
                    elif language in ['javascript', 'js']:
                        self._validate_javascript_code(stats.file_path, code)
                    elif language in ['bash', 'sh']:
                        self._validate_bash_code(stats.file_path, code)
                        
            except:
                continue
    
    def _validate_python_code(self, file_path: str, code: str) -> None:
        """Validate Python code syntax"""
        try:
            compile(code, '<string>', 'exec')
        except SyntaxError as e:
            self.issues.append(ValidationIssue(
                file_path=file_path,
                issue_type="invalid_code_example",
                severity="medium",
                description=f"Python syntax error in code example: {str(e)}"
            ))
    
    def _validate_javascript_code(self, file_path: str, code: str) -> None:
        """Basic JavaScript validation"""
        # Basic checks for common syntax issues
        if code.count('{') != code.count('}'):
            self.issues.append(ValidationIssue(
                file_path=file_path,
                issue_type="invalid_code_example",
                severity="medium",
                description="Mismatched braces in JavaScript code example"
            ))
    
    def _validate_bash_code(self, file_path: str, code: str) -> None:
        """Basic Bash validation"""
        # Check for common issues
        if re.search(r'[^\\]\$\([^)]*$', code):
            self.issues.append(ValidationIssue(
                file_path=file_path,
                issue_type="invalid_code_example",
                severity="low",
                description="Potentially unclosed command substitution in Bash code"
            ))
    
    def create_documentation_index(self) -> Dict:
        """Create comprehensive documentation index"""
        logger.info("Creating documentation index...")
        
        index = {
            "master_toc": [],
            "by_category": defaultdict(list),
            "cross_references": dict(self.cross_references),
            "statistics": {
                "total_files": len(self.all_files),
                "total_words": sum(s.word_count for s in self.doc_stats),
                "total_internal_links": sum(len(s.internal_links) for s in self.doc_stats),
                "total_external_links": sum(len(s.external_links) for s in self.doc_stats),
                "total_code_blocks": sum(s.code_blocks for s in self.doc_stats)
            }
        }
        
        # Categorize documents
        for file_path in self.all_files:
            path_parts = Path(file_path).parts
            if 'security' in path_parts:
                index["by_category"]["security"].append(file_path)
            elif 'performance' in path_parts:
                index["by_category"]["performance"].append(file_path)
            elif 'architecture' in path_parts:
                index["by_category"]["architecture"].append(file_path)
            elif 'development' in path_parts or 'dev' in path_parts:
                index["by_category"]["development"].append(file_path)
            elif 'deployment' in path_parts or 'infrastructure' in path_parts:
                index["by_category"]["infrastructure"].append(file_path)
            elif 'testing' in path_parts or 'test' in path_parts:
                index["by_category"]["testing"].append(file_path)
            else:
                index["by_category"]["general"].append(file_path)
        
        return index
    
    def generate_coverage_report(self) -> Dict:
        """Generate documentation coverage report"""
        logger.info("Generating coverage report...")
        
        # Analyze project structure to identify areas needing documentation
        source_dirs = []
        for pattern in ["src/**/*.py", "**/*.rs", "**/*.js", "**/*.ts"]:
            source_dirs.extend(self.project_root.glob(pattern))
        
        # Check if major components have documentation
        components_needing_docs = []
        documented_components = []
        
        # This is a simplified check - in practice, you'd want more sophisticated analysis
        major_dirs = ['src', 'api', 'core', 'auth', 'database', 'mcp']
        
        for dir_name in major_dirs:
            dir_path = self.project_root / dir_name
            if dir_path.exists():
                has_docs = any('README' in f.name for f in dir_path.glob('*'))
                if has_docs:
                    documented_components.append(dir_name)
                else:
                    components_needing_docs.append(dir_name)
        
        coverage_report = {
            "documentation_coverage": len(documented_components) / (len(documented_components) + len(components_needing_docs)) * 100 if (documented_components or components_needing_docs) else 100,
            "documented_components": documented_components,
            "components_needing_docs": components_needing_docs,
            "total_issues": len(self.issues),
            "issues_by_severity": Counter(issue.severity for issue in self.issues),
            "issues_by_type": Counter(issue.issue_type for issue in self.issues)
        }
        
        return coverage_report
    
    def create_maintenance_procedures(self) -> Dict:
        """Create documentation maintenance procedures"""
        procedures = {
            "regular_checks": [
                "Run documentation validator monthly",
                "Check external links quarterly",
                "Review terminology consistency after major updates",
                "Update documentation index when adding new docs"
            ],
            "automated_checks": [
                "Set up CI/CD pipeline to validate docs on PR",
                "Use link checker in automated tests",
                "Validate code examples in documentation",
                "Check for outdated information based on code changes"
            ],
            "quality_standards": [
                "All major features must have documentation",
                "API documentation must match implementation",
                "Use consistent terminology across all docs",
                "Include code examples for complex procedures",
                "Maintain cross-references between related docs"
            ]
        }
        return procedures
    
    def run_full_validation(self) -> Dict:
        """Run complete validation suite"""
        logger.info("Starting comprehensive documentation validation...")
        
        # Step 1: Scan all files
        self.scan_all_documentation()
        
        # Step 2: Analyze each document
        logger.info("Analyzing individual documents...")
        for file_path in self.all_files:
            self.analyze_document(file_path)
        
        # Step 3: Run all validations
        self.validate_cross_references()
        self.validate_external_links()
        self.analyze_terminology_consistency()
        self.check_formatting_consistency()
        self.validate_code_examples()
        
        # Step 4: Generate reports
        doc_index = self.create_documentation_index()
        coverage_report = self.generate_coverage_report()
        maintenance_procedures = self.create_maintenance_procedures()
        
        # Compile final report
        final_report = {
            "validation_timestamp": datetime.now().isoformat(),
            "project_root": str(self.project_root),
            "summary": {
                "total_files_analyzed": len(self.all_files),
                "total_issues_found": len(self.issues),
                "critical_issues": len([i for i in self.issues if i.severity == "critical"]),
                "high_issues": len([i for i in self.issues if i.severity == "high"]),
                "medium_issues": len([i for i in self.issues if i.severity == "medium"]),
                "low_issues": len([i for i in self.issues if i.severity == "low"])
            },
            "issues": [
                {
                    "file_path": issue.file_path,
                    "type": issue.issue_type,
                    "severity": issue.severity,
                    "description": issue.description,
                    "line_number": issue.line_number,
                    "suggested_fix": issue.suggested_fix
                }
                for issue in self.issues
            ],
            "documentation_index": doc_index,
            "coverage_report": coverage_report,
            "maintenance_procedures": maintenance_procedures,
            "document_statistics": [
                {
                    "file_path": stats.file_path,
                    "word_count": stats.word_count,
                    "line_count": stats.line_count,
                    "internal_links_count": len(stats.internal_links),
                    "external_links_count": len(stats.external_links),
                    "code_blocks": stats.code_blocks,
                    "headers_count": len(stats.headers),
                    "last_modified": stats.last_modified
                }
                for stats in self.doc_stats
            ]
        }
        
        return final_report

def main():
    """Main function to run documentation validation"""
    project_root = "/home/louranicas/projects/claude-optimized-deployment"
    
    validator = DocumentationValidator(project_root)
    report = validator.run_full_validation()
    
    # Save report
    output_file = Path(project_root) / "comprehensive_documentation_validation_report.json"
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    logger.info(f"Validation complete. Report saved to {output_file}")
    
    # Print summary
    print("\n" + "="*60)
    print("DOCUMENTATION VALIDATION SUMMARY")
    print("="*60)
    print(f"Total files analyzed: {report['summary']['total_files_analyzed']}")
    print(f"Total issues found: {report['summary']['total_issues_found']}")
    print(f"  Critical: {report['summary']['critical_issues']}")
    print(f"  High: {report['summary']['high_issues']}")
    print(f"  Medium: {report['summary']['medium_issues']}")
    print(f"  Low: {report['summary']['low_issues']}")
    print(f"\nDocumentation coverage: {report['coverage_report']['documentation_coverage']:.1f}%")
    print(f"Total words in documentation: {report['documentation_index']['statistics']['total_words']:,}")
    print(f"Total internal links: {report['documentation_index']['statistics']['total_internal_links']}")
    print(f"Total external links: {report['documentation_index']['statistics']['total_external_links']}")
    print("="*60)

if __name__ == "__main__":
    main()