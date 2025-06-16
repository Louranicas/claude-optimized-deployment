#!/usr/bin/env python3
"""
Auto-Updating Documentation Index System

This script automatically maintains up-to-date indexes of all documentation
with automatic updates when new .md files are added.
"""

import os
import json
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import hashlib
import argparse

class AutoIndexer:
    def __init__(self, ai_docs_path: str):
        self.ai_docs = Path(ai_docs_path)
        self.index_db_path = self.ai_docs / ".index_db.json"
        self.master_index_path = self.ai_docs / "00_MASTER_DOCUMENTATION_INDEX.md"
        self.timeline_index_path = self.ai_docs / "HISTORICAL_TIMELINE_INDEX.md"
        self.cross_ref_path = self.ai_docs / "CROSS_REFERENCE_INDEX.md"
        
        # Load existing index database
        self.index_db = self._load_index_db()
        
    def _load_index_db(self) -> Dict:
        """Load the index database with file metadata."""
        if self.index_db_path.exists():
            try:
                with open(self.index_db_path, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {
            "files": {},
            "last_scan": None,
            "categories": {},
            "tags": {},
            "cross_references": {}
        }
    
    def _save_index_db(self):
        """Save the index database."""
        with open(self.index_db_path, 'w') as f:
            json.dump(self.index_db, f, indent=2)
    
    def _get_file_hash(self, file_path: Path) -> str:
        """Get file content hash for change detection."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return hashlib.md5(content.encode()).hexdigest()
        except:
            return ""
    
    def _extract_metadata(self, file_path: Path) -> Dict:
        """Extract metadata from markdown file."""
        metadata = {
            "title": file_path.stem.replace('_', ' ').title(),
            "category": file_path.parent.name,
            "tags": [],
            "references": [],
            "date_created": None,
            "date_modified": None,
            "size": 0,
            "lines": 0
        }
        
        try:
            stat = file_path.stat()
            metadata["date_modified"] = datetime.fromtimestamp(stat.st_mtime).isoformat()
            metadata["size"] = stat.st_size
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
                metadata["lines"] = len(lines)
                
                # Extract title from first heading
                for line in lines[:20]:
                    if line.startswith('# '):
                        metadata["title"] = line[2:].strip()
                        break
                
                # Extract tags from content
                tags = re.findall(r'#(\w+)', content.lower())
                metadata["tags"] = list(set(tags))
                
                # Extract references to other documents
                refs = re.findall(r'\[([^\]]+)\]\(([^)]+\.md)\)', content)
                metadata["references"] = [ref[1] for ref in refs if ref[1].endswith('.md')]
                
                # Extract date from content
                date_patterns = [
                    r'(\d{4}-\d{2}-\d{2})',
                    r'(\d{4}/\d{2}/\d{2})',
                    r'Generated.*?(\d{4}-\d{2}-\d{2})',
                    r'Date.*?(\d{4}-\d{2}-\d{2})'
                ]
                for pattern in date_patterns:
                    match = re.search(pattern, content)
                    if match:
                        metadata["date_created"] = match.group(1)
                        break
                
        except Exception as e:
            print(f"Error extracting metadata from {file_path}: {e}")
        
        return metadata
    
    def scan_for_changes(self) -> List[Path]:
        """Scan for new or changed files."""
        changed_files = []
        
        for md_file in self.ai_docs.rglob("*.md"):
            if md_file.name.startswith('.'):
                continue
                
            rel_path = str(md_file.relative_to(self.ai_docs))
            current_hash = self._get_file_hash(md_file)
            
            if (rel_path not in self.index_db["files"] or 
                self.index_db["files"][rel_path].get("hash") != current_hash):
                changed_files.append(md_file)
                
                # Update file info in database
                metadata = self._extract_metadata(md_file)
                metadata["hash"] = current_hash
                metadata["last_indexed"] = datetime.now().isoformat()
                self.index_db["files"][rel_path] = metadata
        
        return changed_files
    
    def update_master_index(self):
        """Update the master documentation index."""
        # Group files by category
        categories = {}
        for rel_path, metadata in self.index_db["files"].items():
            category = metadata["category"]
            if category not in categories:
                categories[category] = []
            categories[category].append((rel_path, metadata))
        
        # Generate index content
        content = f"""# Master Documentation Index

**Last Updated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Auto-Generated**: This index is automatically updated when new documentation is added
**Total Documents**: {len(self.index_db["files"])}

## Quick Navigation

"""
        
        # Category links with counts
        for category in sorted(categories.keys()):
            count = len(categories[category])
            display_name = category.replace('_', ' ').title()
            anchor = category.replace('_', '-')
            content += f"- [{display_name}](#{anchor}) ({count} documents)\n"
        
        content += "\n## Documentation Categories\n\n"
        
        # Category descriptions
        category_descriptions = {
            "project_status": "Project status reports, roadmaps, and certification documents",
            "agent_reports": "Individual agent analysis and deliverable reports organized by agent",
            "security": "Security audits, vulnerability assessments, and compliance documentation",
            "performance": "Performance analysis, optimization reports, and benchmarks",
            "architecture": "System architecture, design documents, and technical specifications",
            "development": "Development guides, best practices, and coding standards",
            "infrastructure": "Deployment guides, container configurations, and operations documentation",
            "mcp_integration": "MCP server integration documentation and guides",
            "testing": "Testing reports, validation documentation, and quality assessments",
            "process_documentation": "Implementation processes, migration guides, and procedures",
            "benchmarks": "Performance benchmarks and measurement data",
            "configuration_guides": "Setup and configuration documentation",
            "historical": "Legacy documentation, deprecated guides, and project evolution"
        }
        
        # Generate category sections
        for category, files in sorted(categories.items()):
            if not files:
                continue
                
            display_name = category.replace('_', ' ').title()
            description = category_descriptions.get(category, "Documentation category")
            
            content += f"### {display_name}\n\n"
            content += f"{description}\n\n"
            
            # Sort files by name
            sorted_files = sorted(files, key=lambda x: x[1]["title"])
            
            for rel_path, metadata in sorted_files:
                title = metadata["title"]
                # Clean up relative path for links
                link_path = rel_path.replace('\\', '/')
                content += f"- [{title}]({link_path})\n"
            
            content += "\n"
        
        content += f"""
## Index Statistics

- **Total Documents**: {len(self.index_db["files"])}
- **Categories**: {len(categories)}
- **Last Scan**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Search and Navigation Tips

### Finding Documents
1. **By Category**: Use the category sections above
2. **By Agent**: Check agent_reports/ with subfolders for each agent
3. **By Topic**: Use your IDE's search function across ai_docs/
4. **By Date**: Check the [Historical Timeline Index](HISTORICAL_TIMELINE_INDEX.md)

### Understanding Categories
- **project_status/**: High-level project status and roadmaps
- **agent_reports/**: Detailed technical analysis organized by agent (1-10)
- **security/**: All security audits, mitigations, and compliance
- **performance/**: Performance optimization and benchmark documentation
- **architecture/**: System design and architectural specifications
- **development/**: Developer guides, standards, and best practices
- **infrastructure/**: Deployment, operations, and infrastructure guides

### Cross-References
See [Cross-Reference Index](CROSS_REFERENCE_INDEX.md) for document relationships and dependencies.

---

*Auto-generated by index system. Last scan: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""
        
        with open(self.master_index_path, 'w') as f:
            f.write(content)
    
    def update_cross_reference_index(self):
        """Generate cross-reference index showing document relationships."""
        content = f"""# Cross-Reference Documentation Index

**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Purpose**: Document relationships, dependencies, and cross-references

## Document Relationships

This index shows how documents reference each other, helping you navigate related content.

"""
        
        # Build reference map
        ref_map = {}
        back_ref_map = {}
        
        for rel_path, metadata in self.index_db["files"].items():
            title = metadata["title"]
            refs = metadata.get("references", [])
            
            if refs:
                ref_map[rel_path] = {
                    "title": title,
                    "references": refs
                }
                
                # Build back-references
                for ref in refs:
                    if ref not in back_ref_map:
                        back_ref_map[ref] = []
                    back_ref_map[ref].append(rel_path)
        
        # Generate reference sections
        content += "## Documents with References\n\n"
        
        for rel_path, info in sorted(ref_map.items()):
            title = info["title"]
            content += f"### [{title}]({rel_path})\n\n"
            content += "**References**:\n"
            
            for ref in info["references"]:
                # Try to find the referenced document
                ref_title = ref
                for file_path, metadata in self.index_db["files"].items():
                    if file_path.endswith(ref) or ref in file_path:
                        ref_title = metadata["title"]
                        break
                content += f"- [{ref_title}]({ref})\n"
            
            content += "\n"
        
        content += "## Frequently Referenced Documents\n\n"
        
        # Sort by number of back-references
        popular_docs = sorted(back_ref_map.items(), 
                            key=lambda x: len(x[1]), reverse=True)
        
        for ref_doc, referrers in popular_docs[:20]:  # Top 20
            if len(referrers) > 1:  # Only show if referenced multiple times
                # Find title for referenced document
                ref_title = ref_doc
                for file_path, metadata in self.index_db["files"].items():
                    if file_path.endswith(ref_doc) or ref_doc in file_path:
                        ref_title = metadata["title"]
                        break
                
                content += f"### {ref_title}\n"
                content += f"**Referenced by {len(referrers)} documents**:\n"
                
                for referrer in referrers[:10]:  # Show up to 10 referrers
                    referrer_title = self.index_db["files"].get(referrer, {}).get("title", referrer)
                    content += f"- [{referrer_title}]({referrer})\n"
                
                if len(referrers) > 10:
                    content += f"- ... and {len(referrers) - 10} more documents\n"
                
                content += "\n"
        
        content += """
## How to Use Cross-References

1. **Follow Document Chains**: Start with a document and follow its references
2. **Find Related Content**: Use back-references to find documents that cite a specific resource
3. **Understand Dependencies**: See which documents build upon others
4. **Navigate by Topic**: Related documents often reference each other

---

*Auto-generated by cross-reference analyzer*
"""
        
        with open(self.cross_ref_path, 'w') as f:
            f.write(content)
    
    def create_category_readmes(self):
        """Create README files for each category directory."""
        categories = {}
        for rel_path, metadata in self.index_db["files"].items():
            category = metadata["category"]
            if category not in categories:
                categories[category] = []
            categories[category].append((rel_path, metadata))
        
        category_descriptions = {
            "project_status": {
                "title": "Project Status Documentation",
                "description": "High-level project status reports, roadmaps, and certification documents tracking the overall progress and health of the Claude Optimized Deployment Engine.",
                "purpose": "Provides executive-level view of project completion, milestones, and current status.",
                "key_docs": ["PROJECT_STATUS.md", "PRODUCTION_CERTIFICATION.md", "CODE_PROJECT_ROADMAP_2025.md"]
            },
            "agent_reports": {
                "title": "Agent Analysis Reports", 
                "description": "Comprehensive technical analysis and deliverables from 10 parallel agents providing expert consultation across all aspects of the system.",
                "purpose": "Detailed technical assessments, recommendations, and implementation reports from specialized AI agents.",
                "key_docs": ["Agent 1-10 specific reports", "Circle of Experts analysis", "Performance benchmarks"]
            },
            "security": {
                "title": "Security Documentation",
                "description": "Security audits, vulnerability assessments, compliance documentation, and mitigation strategies.",
                "purpose": "Comprehensive security posture documentation including audits, fixes, and compliance validation.",
                "key_docs": ["COMPREHENSIVE_SECURITY_AUDIT_REPORT.md", "OWASP_TOP_10_2021_SECURITY_AUDIT.md", "Security mitigation matrices"]
            },
            "performance": {
                "title": "Performance Documentation",
                "description": "Performance analysis, optimization reports, benchmarks, and Rust acceleration documentation.",
                "purpose": "Documents the journey to achieving 2-20x performance improvements through Rust integration and optimization.",
                "key_docs": ["PERFORMANCE_OPTIMIZATION_REPORT.md", "Rust integration guides", "Memory optimization strategies"]
            },
            "architecture": {
                "title": "Architecture Documentation",
                "description": "System architecture, design documents, technical specifications, and architectural decision records.",
                "purpose": "Comprehensive system design documentation covering all architectural aspects of the platform.",
                "key_docs": ["COMPREHENSIVE_CODEBASE_MAP.md", "PROJECT_ARCHITECTURE_MINDMAP.md", "System design documents"]
            },
            "development": {
                "title": "Development Documentation",
                "description": "Development guides, coding standards, best practices, and contributor documentation.",
                "purpose": "Resources for developers working on the platform, including setup, standards, and best practices.",
                "key_docs": ["CONTRIBUTING.md", "CLAUDE_CODE_BEST_PRACTICES.md", "Development guidelines"]
            },
            "infrastructure": {
                "title": "Infrastructure Documentation",
                "description": "Deployment guides, container configurations, operations documentation, and infrastructure management.",
                "purpose": "Operational documentation for deploying, managing, and maintaining the platform infrastructure.",
                "key_docs": ["DEPLOYMENT_AND_OPERATIONS_GUIDE.md", "DATABASE_INTEGRATION_GUIDE.md", "MCP integration guides"]
            }
        }
        
        for category, files in categories.items():
            if not files or category in ["historical"]:  # Skip historical
                continue
                
            readme_path = self.ai_docs / category / "README.md"
            readme_path.parent.mkdir(parents=True, exist_ok=True)
            
            info = category_descriptions.get(category, {
                "title": category.replace('_', ' ').title(),
                "description": f"Documentation category: {category}",
                "purpose": "Category-specific documentation",
                "key_docs": []
            })
            
            content = f"""# {info["title"]}

{info["description"]}

## Purpose

{info["purpose"]}

## Documents in this Category

"""
            
            # List all files in category
            sorted_files = sorted(files, key=lambda x: x[1]["title"])
            for rel_path, metadata in sorted_files:
                filename = Path(rel_path).name
                title = metadata["title"]
                content += f"- [{title}]({filename})\n"
            
            if info["key_docs"]:
                content += f"""
## Key Documents

"""
                for key_doc in info["key_docs"]:
                    content += f"- {key_doc}\n"
            
            content += f"""
## Navigation

- [Back to Master Index](../00_MASTER_DOCUMENTATION_INDEX.md)
- [Historical Timeline](../HISTORICAL_TIMELINE_INDEX.md)
- [Cross-References](../CROSS_REFERENCE_INDEX.md)

---

*Category contains {len(files)} documents | Last updated: {datetime.now().strftime('%Y-%m-%d')}*
"""
            
            with open(readme_path, 'w') as f:
                f.write(content)
    
    def full_update(self):
        """Perform a full index update."""
        print("🔄 Scanning for documentation changes...")
        changed_files = self.scan_for_changes()
        
        if changed_files:
            print(f"📝 Found {len(changed_files)} changed files")
            for file in changed_files:
                print(f"   - {file.relative_to(self.ai_docs)}")
        else:
            print("✅ No changes detected")
        
        print("📊 Updating master index...")
        self.update_master_index()
        
        print("🔗 Updating cross-reference index...")
        self.update_cross_reference_index()
        
        print("📁 Creating category README files...")
        self.create_category_readmes()
        
        # Update scan timestamp
        self.index_db["last_scan"] = datetime.now().isoformat()
        self._save_index_db()
        
        print("✅ Index update complete!")

def main():
    parser = argparse.ArgumentParser(description="Auto-update documentation indexes")
    parser.add_argument("--ai-docs", default="/home/louranicas/projects/claude-optimized-deployment/ai_docs",
                       help="Path to ai_docs directory")
    parser.add_argument("--scan-only", action="store_true",
                       help="Only scan for changes, don't update indexes")
    
    args = parser.parse_args()
    
    indexer = AutoIndexer(args.ai_docs)
    
    if args.scan_only:
        changed_files = indexer.scan_for_changes()
        print(f"Found {len(changed_files)} changed files")
        for file in changed_files:
            print(f"  - {file}")
    else:
        indexer.full_update()

if __name__ == "__main__":
    main()