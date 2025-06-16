#!/usr/bin/env python3
"""
Fix Critical Documentation Links
Automatically fixes the most common broken internal links in documentation.
"""

import os
import re
import json
from pathlib import Path
import logging
from typing import Dict, List, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DocumentationLinkFixer:
    """Fixes broken internal links in documentation"""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.fixes_applied = []
        self.errors_encountered = []
        
        # Common link mappings (old -> new)
        self.link_mappings = {
            # AI Docs relocations
            '../docs/architecture.md': '../ai_docs/architecture/ARCHITECTURE.md',
            '../docs/performance.md': '../ai_docs/performance/PERFORMANCE_OPTIMIZATION_REPORT.md',
            '../deploy/README.md': '../docs/MCP_DEPLOYMENT_ORCHESTRATION_GUIDE.md',
            
            # Within ai_docs corrections
            'DOCUMENTATION_MINDMAP.md': '../DOCUMENTATION_MINDMAP.md',
            '00_AI_DOCS_INDEX.md': '../00_AI_DOCS_INDEX.md',
            'UPDATE_SUMMARY_2025-05-30.md': '../UPDATE_SUMMARY_2025-05-30.md',
            'DOCUMENTATION_MIGRATION_REPORT.md': '../DOCUMENTATION_MIGRATION_REPORT.md',
            'HISTORICAL_TIMELINE_INDEX.md': '../HISTORICAL_TIMELINE_INDEX.md',
            '01_INFRASTRUCTURE_AUTOMATION_COMMANDS.md': '../01_INFRASTRUCTURE_AUTOMATION_COMMANDS.md',
            '00_MASTER_DOCUMENTATION_INDEX.md': '../00_MASTER_DOCUMENTATION_INDEX.md',
            '02_PERFORMANCE_OPTIMIZATION_PATTERNS.md': '../02_PERFORMANCE_OPTIMIZATION_PATTERNS.md',
            '03_RUST_PYTHON_INFRASTRUCTURE_INTEGRATION.md': '../03_RUST_PYTHON_INFRASTRUCTURE_INTEGRATION.md',
            'CROSS_REFERENCE_INDEX.md': '../CROSS_REFERENCE_INDEX.md',
            'DOCUMENTATION_VALIDATION_REPORT.md': '../DOCUMENTATION_VALIDATION_REPORT.md',
            
            # Architecture directory fixes
            'architecture.md': './ARCHITECTURE.md',
            './architecture.md': './ARCHITECTURE.md',
            
            # Performance directory fixes
            'rust_design.md': './rust_design.md',
            'rust_integration.md': './rust_integration.md',
            
            # Security directory fixes
            'SECURITY.md': './SECURITY.md',
            
            # Common missing extensions
            'README': 'README.md',
            'CONTRIBUTING': 'CONTRIBUTING.md',
            'LICENSE': 'LICENSE.md',
        }
    
    def load_validation_report(self) -> List[Dict]:
        """Load the validation report to identify issues"""
        report_path = self.project_root / "comprehensive_documentation_validation_report.json"
        
        if not report_path.exists():
            logger.warning("Validation report not found. Run validator first.")
            return []
        
        try:
            with open(report_path, 'r') as f:
                data = json.load(f)
                return data.get('issues', [])
        except Exception as e:
            logger.error(f"Failed to load validation report: {e}")
            return []
    
    def fix_broken_internal_links(self) -> None:
        """Fix broken internal links based on validation report"""
        logger.info("Fixing broken internal links...")
        
        issues = self.load_validation_report()
        broken_link_issues = [i for i in issues if i['type'] == 'broken_internal_link']
        
        logger.info(f"Found {len(broken_link_issues)} broken internal link issues")
        
        # Group issues by file for efficient processing
        issues_by_file = {}
        for issue in broken_link_issues:
            file_path = issue['file_path']
            if file_path not in issues_by_file:
                issues_by_file[file_path] = []
            issues_by_file[file_path].append(issue)
        
        for file_path, file_issues in issues_by_file.items():
            self.fix_links_in_file(file_path, file_issues)
    
    def fix_links_in_file(self, file_path: str, issues: List[Dict]) -> None:
        """Fix broken links in a specific file"""
        full_path = self.project_root / file_path
        
        if not full_path.exists():
            logger.warning(f"File does not exist: {file_path}")
            return
        
        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original_content = content
            changes_made = False
            
            for issue in issues:
                broken_link = self.extract_broken_link(issue['description'])
                if broken_link:
                    new_link = self.find_replacement_link(broken_link, file_path)
                    if new_link:
                        # Replace the broken link
                        old_pattern = f"]({re.escape(broken_link)})"
                        new_pattern = f"]({new_link})"
                        
                        if old_pattern.replace('\\', '') in content:
                            content = content.replace(f"]({broken_link})", f"]({new_link})")
                            changes_made = True
                            self.fixes_applied.append({
                                'file': file_path,
                                'old_link': broken_link,
                                'new_link': new_link
                            })
                            logger.info(f"Fixed link in {file_path}: {broken_link} -> {new_link}")
            
            # Write back if changes were made
            if changes_made:
                with open(full_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                logger.info(f"Updated file: {file_path}")
            
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")
            self.errors_encountered.append({'file': file_path, 'error': str(e)})
    
    def extract_broken_link(self, description: str) -> str:
        """Extract the broken link from the issue description"""
        # Pattern: "Internal link points to non-existent file: LINK"
        match = re.search(r'non-existent file: (.+)$', description)
        if match:
            return match.group(1).strip()
        return ""
    
    def find_replacement_link(self, broken_link: str, source_file: str) -> str:
        """Find the correct replacement for a broken link"""
        # Check direct mappings first
        if broken_link in self.link_mappings:
            return self.link_mappings[broken_link]
        
        # Try to find the file by searching
        link_basename = Path(broken_link).name
        
        # Search for files with the same name
        for pattern in ['**/' + link_basename, '**/' + link_basename.replace('.md', '') + '.md']:
            matches = list(self.project_root.glob(pattern))
            if matches:
                # Find the best match (prefer closest to source file)
                source_dir = Path(source_file).parent
                best_match = self.find_closest_match(matches, source_dir)
                if best_match:
                    # Calculate relative path
                    try:
                        rel_path = os.path.relpath(best_match, self.project_root / source_dir)
                        return rel_path
                    except:
                        return str(best_match.relative_to(self.project_root))
        
        # Try common variations
        variations = [
            broken_link.replace('.md', '') + '.md',
            broken_link.replace('_', '-'),
            broken_link.replace('-', '_'),
            broken_link.upper(),
            broken_link.lower(),
        ]
        
        for variation in variations:
            if variation in self.link_mappings:
                return self.link_mappings[variation]
        
        return ""
    
    def find_closest_match(self, matches: List[Path], source_dir: Path) -> Path:
        """Find the match closest to the source directory"""
        if len(matches) == 1:
            return matches[0]
        
        # Calculate distances and return closest
        distances = []
        for match in matches:
            try:
                rel_source = source_dir.relative_to(self.project_root)
                rel_match = match.parent.relative_to(self.project_root)
                
                # Count common path components
                common = len(os.path.commonpath([str(rel_source), str(rel_match)]).split(os.sep))
                distances.append((common, match))
            except:
                distances.append((0, match))
        
        # Return match with highest common path length
        distances.sort(key=lambda x: x[0], reverse=True)
        return distances[0][1]
    
    def create_missing_files(self) -> None:
        """Create stub files for missing documentation that should exist"""
        logger.info("Creating missing documentation files...")
        
        missing_files = [
            # Core missing files that are frequently referenced
            'ai_docs/00_AI_DOCS_INDEX.md',
            'ai_docs/00_MASTER_DOCUMENTATION_INDEX.md',
            'deploy/README.md',
            'docs/architecture.md',
            'docs/performance.md',
        ]
        
        for file_path in missing_files:
            full_path = self.project_root / file_path
            
            if not full_path.exists():
                # Create directory if needed
                full_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Create appropriate content based on file type
                content = self.generate_stub_content(file_path)
                
                try:
                    with open(full_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    
                    logger.info(f"Created missing file: {file_path}")
                    self.fixes_applied.append({
                        'type': 'created_file',
                        'file': file_path,
                        'content_type': 'stub'
                    })
                    
                except Exception as e:
                    logger.error(f"Failed to create {file_path}: {e}")
                    self.errors_encountered.append({'file': file_path, 'error': str(e)})
    
    def generate_stub_content(self, file_path: str) -> str:
        """Generate appropriate stub content for missing files"""
        file_name = Path(file_path).stem
        
        if 'INDEX' in file_name:
            return f"""# {file_name.replace('_', ' ').title()}

**Status**: This is a stub file created during documentation validation.

## Purpose
This file should contain an index or overview of related documentation.

## TODO
- [ ] Add comprehensive content
- [ ] Link to related documentation
- [ ] Update cross-references

---
*Generated automatically on 2025-06-08*
"""
        
        elif file_path.endswith('README.md'):
            dir_name = Path(file_path).parent.name
            return f"""# {dir_name.title()}

**Status**: This is a stub README created during documentation validation.

## Overview
This directory contains documentation related to {dir_name}.

## Contents
*To be documented*

## Quick Start
*To be documented*

---
*Generated automatically on 2025-06-08*
"""
        
        else:
            return f"""# {file_name.replace('_', ' ').title()}

**Status**: This is a stub file created during documentation validation.

## Overview
*Content to be added*

## Details
*To be documented*

---
*Generated automatically on 2025-06-08*
"""
    
    def update_common_link_patterns(self) -> None:
        """Update common patterns that appear across multiple files"""
        logger.info("Updating common link patterns...")
        
        # Common patterns to fix
        patterns = [
            # Fix relative paths in ai_docs/ai_docs/ subdirectory
            {
                'search_pattern': r'\]\(([^)]+\.md)\)',
                'search_dir': 'ai_docs/ai_docs',
                'replacement_func': lambda match: f']({self.fix_ai_docs_path(match.group(1))})'
            },
        ]
        
        for pattern in patterns:
            search_dir = self.project_root / pattern['search_dir']
            if search_dir.exists():
                for md_file in search_dir.glob('*.md'):
                    self.apply_pattern_to_file(md_file, pattern)
    
    def fix_ai_docs_path(self, original_path: str) -> str:
        """Fix paths in ai_docs/ai_docs/ subdirectory"""
        # These files should reference parent directory
        if original_path in self.link_mappings:
            return self.link_mappings[original_path]
        
        # For files that should exist in parent
        parent_candidates = [
            '00_AI_DOCS_INDEX.md',
            '00_MASTER_DOCUMENTATION_INDEX.md',
            'DOCUMENTATION_MINDMAP.md',
            'UPDATE_SUMMARY_2025-05-30.md',
            'DOCUMENTATION_MIGRATION_REPORT.md',
            'HISTORICAL_TIMELINE_INDEX.md',
            '01_INFRASTRUCTURE_AUTOMATION_COMMANDS.md',
            '02_PERFORMANCE_OPTIMIZATION_PATTERNS.md',
            '03_RUST_PYTHON_INFRASTRUCTURE_INTEGRATION.md',
            'CROSS_REFERENCE_INDEX.md',
            'DOCUMENTATION_VALIDATION_REPORT.md',
        ]
        
        if original_path in parent_candidates:
            return f'../{original_path}'
        
        return original_path
    
    def apply_pattern_to_file(self, file_path: Path, pattern: Dict) -> None:
        """Apply a regex pattern replacement to a file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original_content = content
            
            # Apply pattern replacement
            content = re.sub(
                pattern['search_pattern'],
                pattern['replacement_func'],
                content
            )
            
            if content != original_content:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                logger.info(f"Applied pattern fix to: {file_path}")
                self.fixes_applied.append({
                    'type': 'pattern_fix',
                    'file': str(file_path.relative_to(self.project_root)),
                    'pattern': pattern['search_pattern']
                })
                
        except Exception as e:
            logger.error(f"Error applying pattern to {file_path}: {e}")
            self.errors_encountered.append({
                'file': str(file_path),
                'error': str(e)
            })
    
    def generate_fix_report(self) -> Dict:
        """Generate a report of all fixes applied"""
        return {
            'timestamp': '2025-06-08T10:30:00Z',
            'fixes_applied': len(self.fixes_applied),
            'errors_encountered': len(self.errors_encountered),
            'details': {
                'fixes': self.fixes_applied,
                'errors': self.errors_encountered
            },
            'summary': {
                'link_fixes': len([f for f in self.fixes_applied if 'old_link' in f]),
                'files_created': len([f for f in self.fixes_applied if f.get('type') == 'created_file']),
                'pattern_fixes': len([f for f in self.fixes_applied if f.get('type') == 'pattern_fix'])
            }
        }
    
    def run_all_fixes(self) -> Dict:
        """Run all available fixes"""
        logger.info("Starting comprehensive documentation link fixes...")
        
        # 1. Fix broken internal links
        self.fix_broken_internal_links()
        
        # 2. Create missing files
        self.create_missing_files()
        
        # 3. Update common patterns
        self.update_common_link_patterns()
        
        # 4. Generate report
        report = self.generate_fix_report()
        
        logger.info(f"Fix process complete. Applied {report['fixes_applied']} fixes with {report['errors_encountered']} errors.")
        
        return report

def main():
    """Main function"""
    project_root = "/home/louranicas/projects/claude-optimized-deployment"
    
    fixer = DocumentationLinkFixer(project_root)
    report = fixer.run_all_fixes()
    
    # Save fix report
    report_path = Path(project_root) / "documentation_link_fixes_report.json"
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    # Print summary
    print("\n" + "="*60)
    print("DOCUMENTATION LINK FIXES SUMMARY")
    print("="*60)
    print(f"Total fixes applied: {report['fixes_applied']}")
    print(f"  Link fixes: {report['summary']['link_fixes']}")
    print(f"  Files created: {report['summary']['files_created']}")
    print(f"  Pattern fixes: {report['summary']['pattern_fixes']}")
    print(f"Errors encountered: {report['errors_encountered']}")
    print(f"\nDetailed report saved to: {report_path}")
    print("="*60)

if __name__ == "__main__":
    main()