#!/usr/bin/env python3
"""
Documentation Organization Script for Claude Optimized Deployment Engine

This script organizes all .md files into logical categories within ai_docs/
with proper categorization, migration tracking, and index generation.
"""

import os
import shutil
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Set
import json

class DocumentationOrganizer:
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.ai_docs = self.project_root / "ai_docs"
        self.migration_log = []
        self.categories = {
            "project_status": [
                r"PROJECT_STATUS", r"PROJECT_SUMMARY", r"PROJECT_TREE", 
                r"PRODUCTION_CERTIFICATION", r"RELEASE_NOTES", r"ROADMAP",
                r"COMPLETION_SUMMARY", r"FINAL_VALIDATION", r"ASSESSMENT"
            ],
            "agent_reports": [
                r"AGENT_\d+", r"CIRCLE_OF_EXPERTS", r"ULTRATHINK"
            ],
            "security": [
                r"SECURITY", r"AUDIT", r"VULNERABILITY", r"CRYPTOGRAPHIC",
                r"COMPLIANCE", r"OWASP", r"GDPR", r"MITIGATION_MATRIX",
                r"THREAT_MODEL"
            ],
            "performance": [
                r"PERFORMANCE", r"OPTIMIZATION", r"BENCHMARK", r"MEMORY",
                r"RUST", r"CIRCUIT_BREAKER"
            ],
            "architecture": [
                r"ARCHITECTURE", r"MINDMAP", r"CODEBASE", r"MODULAR",
                r"INTEGRATION_POINTS", r"DESIGN"
            ],
            "development": [
                r"QUICKSTART", r"CONTRIBUTING", r"IMPORT_FIXES", 
                r"ERROR_HANDLING", r"EXCEPTION_MIGRATION", r"BEST_PRACTICES",
                r"STYLE_GUIDE", r"LOGGING"
            ],
            "infrastructure": [
                r"DEPLOYMENT", r"DOCKER", r"KUBERNETES", r"CONTAINER",
                r"DEVOPS", r"MCP_INTEGRATION", r"DATABASE"
            ],
            "mcp_integration": [
                r"MCP_", r"LEARNING_MCP", r"BASH_GOD"
            ],
            "testing": [
                r"TEST", r"VALIDATION", r"RELIABILITY", r"QUALITY"
            ],
            "process_documentation": [
                r"IMPLEMENTATION", r"MIGRATION", r"FIX_SUMMARY",
                r"IMMEDIATE_ACTION", r"BULLETPROOF", r"IMPLEMENTATION_TIMELINE"
            ]
        }
        
    def categorize_file(self, filename: str) -> str:
        """Categorize a file based on its name patterns."""
        filename_upper = filename.upper()
        
        # Special handling for agent reports
        if re.search(r"AGENT_\d+", filename_upper):
            return "agent_reports"
            
        # Check against category patterns
        for category, patterns in self.categories.items():
            for pattern in patterns:
                if re.search(pattern, filename_upper):
                    return category
                    
        # Default category
        return "historical"
    
    def get_agent_number(self, filename: str) -> str:
        """Extract agent number from filename for subcategorization."""
        match = re.search(r"AGENT_(\d+)", filename.upper())
        return f"agent_{match.group(1)}" if match else "general"
    
    def find_all_md_files(self) -> List[Path]:
        """Find all .md files in the project, excluding certain directories."""
        exclude_patterns = [
            "backup_*", "node_modules", ".git", "test_env", "venv_*",
            "target", "*_env", "ml_test_env", "security_*env"
        ]
        
        md_files = []
        for md_file in self.project_root.rglob("*.md"):
            # Skip if in excluded directory
            skip = False
            for exclude in exclude_patterns:
                if any(part.startswith(exclude.replace("*", "")) or 
                      (exclude.endswith("*") and part.startswith(exclude[:-1]))
                      for part in md_file.parts):
                    skip = True
                    break
            
            if not skip and md_file.exists():
                md_files.append(md_file)
        
        return md_files
    
    def move_file(self, source: Path, target_dir: str, subcategory: str = None) -> Path:
        """Move a file to the appropriate directory."""
        if subcategory:
            target_path = self.ai_docs / target_dir / subcategory / source.name
            target_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            target_path = self.ai_docs / target_dir / source.name
            target_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Skip if source is already in ai_docs
        if str(source).startswith(str(self.ai_docs)):
            return source
            
        # Create backup if target exists
        if target_path.exists():
            backup_path = target_path.with_suffix(f".backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md")
            shutil.move(str(target_path), str(backup_path))
            
        # Move file
        shutil.move(str(source), str(target_path))
        
        # Log migration
        self.migration_log.append({
            "source": str(source),
            "target": str(target_path),
            "category": target_dir,
            "subcategory": subcategory,
            "timestamp": datetime.now().isoformat()
        })
        
        return target_path
    
    def organize_all_files(self) -> Dict[str, List[Path]]:
        """Organize all markdown files into appropriate directories."""
        organized_files = {}
        md_files = self.find_all_md_files()
        
        print(f"Found {len(md_files)} markdown files to organize")
        
        for md_file in md_files:
            category = self.categorize_file(md_file.name)
            
            # Handle agent reports with subcategorization
            if category == "agent_reports":
                subcategory = self.get_agent_number(md_file.name)
                target_path = self.move_file(md_file, category, subcategory)
            else:
                target_path = self.move_file(md_file, category)
            
            if category not in organized_files:
                organized_files[category] = []
            organized_files[category].append(target_path)
            
            print(f"Moved {md_file.name} → {category}")
        
        return organized_files
    
    def generate_migration_report(self):
        """Generate a comprehensive migration report."""
        report_path = self.ai_docs / "DOCUMENTATION_MIGRATION_REPORT.md"
        
        # Count files by category
        category_counts = {}
        for entry in self.migration_log:
            cat = entry["category"]
            category_counts[cat] = category_counts.get(cat, 0) + 1
        
        report_content = f"""# Documentation Migration Report

**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Total Files Migrated**: {len(self.migration_log)}

## Migration Summary

### Files by Category
"""
        
        for category, count in sorted(category_counts.items()):
            report_content += f"- **{category}**: {count} files\n"
        
        report_content += """
## Directory Structure

```
ai_docs/
├── project_status/          # Project status, roadmaps, certifications
├── agent_reports/           # Agent analysis and deliverables
│   ├── agent_1/            # Agent 1 specific reports  
│   ├── agent_2/            # Agent 2 specific reports
│   └── ...                 # (agents 3-10)
├── security/               # Security audits and compliance
│   ├── audits/            # Security audit reports
│   ├── reports/           # Vulnerability assessments  
│   ├── mitigations/       # Security fix implementations
│   └── compliance/        # OWASP, GDPR compliance docs
├── performance/            # Performance analysis and optimization
├── architecture/           # System architecture and design
├── development/            # Development guides and best practices
├── infrastructure/         # Deployment and infrastructure docs
├── mcp_integration/        # MCP server integration documentation
├── testing/               # Testing reports and validation
├── benchmarks/            # Performance benchmarks and metrics
├── configuration_guides/   # Setup and configuration guides
├── process_documentation/ # Implementation processes and procedures
└── historical/            # Legacy and deprecated documentation
```

## Migration Details

| Source | Target | Category | Timestamp |
|--------|---------|----------|-----------|
"""
        
        for entry in self.migration_log:
            source_short = Path(entry["source"]).name
            target_short = str(Path(entry["target"]).relative_to(self.ai_docs))
            report_content += f"| {source_short} | {target_short} | {entry['category']} | {entry['timestamp']} |\n"
        
        with open(report_path, 'w') as f:
            f.write(report_content)
        
        print(f"Migration report saved to: {report_path}")
    
    def create_master_index(self):
        """Create the master documentation index."""
        index_path = self.ai_docs / "00_MASTER_DOCUMENTATION_INDEX.md"
        
        # Scan all directories for files
        all_files = {}
        for category_dir in self.ai_docs.iterdir():
            if category_dir.is_dir() and not category_dir.name.startswith("."):
                all_files[category_dir.name] = []
                for md_file in category_dir.rglob("*.md"):
                    if md_file.name != "README.md":
                        relative_path = md_file.relative_to(self.ai_docs)
                        all_files[category_dir.name].append(relative_path)
        
        # Generate index content
        index_content = f"""# Master Documentation Index

**Last Updated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Auto-Generated**: This index is automatically updated when new documentation is added

## Quick Navigation

"""
        
        # Add category links
        for category in sorted(all_files.keys()):
            count = len(all_files[category])
            index_content += f"- [{category.replace('_', ' ').title()}](#{category.replace('_', '-')}) ({count} documents)\n"
        
        index_content += "\n## Documentation Categories\n\n"
        
        # Add detailed sections
        category_descriptions = {
            "project_status": "Project status reports, roadmaps, and certification documents",
            "agent_reports": "Individual agent analysis and deliverable reports",
            "security": "Security audits, vulnerability assessments, and compliance documentation",
            "performance": "Performance analysis, optimization reports, and benchmarks",
            "architecture": "System architecture, design documents, and technical specifications",
            "development": "Development guides, best practices, and coding standards",
            "infrastructure": "Deployment guides, container configurations, and operations documentation",
            "mcp_integration": "MCP server integration documentation and guides",
            "testing": "Testing reports, validation documentation, and quality assessments",
            "process_documentation": "Implementation processes, migration guides, and procedures",
            "historical": "Legacy documentation and deprecated guides"
        }
        
        for category, files in sorted(all_files.items()):
            if files:  # Only include categories with files
                description = category_descriptions.get(category, "Documentation category")
                index_content += f"### {category.replace('_', ' ').title()}\n\n"
                index_content += f"{description}\n\n"
                
                for file_path in sorted(files):
                    file_name = file_path.name.replace('.md', '').replace('_', ' ')
                    index_content += f"- [{file_name}]({file_path})\n"
                
                index_content += "\n"
        
        index_content += """
## How to Use This Documentation

### Finding Information
1. **By Topic**: Use the category sections above
2. **By Agent**: Check the agent_reports/ directory for specific agent deliverables  
3. **By Date**: Most recent documents are in project_status/ and agent_reports/
4. **Search**: Use your IDE's search function across ai_docs/

### Contributing
- Follow the naming conventions shown in existing files
- Place new documentation in the appropriate category
- Update category README files when adding significant new content
- The master index will auto-update on the next documentation scan

### Categories Explained
- **project_status/**: High-level project information and current status
- **agent_reports/**: Detailed technical analysis from individual agents
- **security/**: All security-related documentation and audits
- **performance/**: Performance analysis and optimization documentation
- **architecture/**: System design and architectural documentation
- **development/**: Developer-focused guides and standards
- **infrastructure/**: Deployment, operations, and infrastructure guides
- **testing/**: Quality assurance and testing documentation

---

*This index is automatically generated. Last scan: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""
        
        with open(index_path, 'w') as f:
            f.write(index_content)
        
        print(f"Master index created: {index_path}")

def main():
    project_root = "/home/louranicas/projects/claude-optimized-deployment"
    organizer = DocumentationOrganizer(project_root)
    
    print("🗂️  Starting documentation organization...")
    
    # Organize all files
    organized_files = organizer.organize_all_files()
    
    # Generate reports
    organizer.generate_migration_report()
    organizer.create_master_index()
    
    print(f"\n✅ Documentation organization complete!")
    print(f"📁 Organized {len(organizer.migration_log)} files")
    print(f"📝 Created master index at ai_docs/00_MASTER_DOCUMENTATION_INDEX.md")
    print(f"📊 Migration report at ai_docs/DOCUMENTATION_MIGRATION_REPORT.md")

if __name__ == "__main__":
    main()