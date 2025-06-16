#!/usr/bin/env python3
"""
Documentation Organization Validation Script

Validates the entire documentation reorganization, tests all systems,
and ensures quality and completeness.
"""

import os
import json
from pathlib import Path
from typing import Dict, List, Set, Tuple
import re

class DocumentationValidator:
    def __init__(self, ai_docs_path: str):
        self.ai_docs = Path(ai_docs_path)
        self.project_root = self.ai_docs.parent
        self.errors = []
        self.warnings = []
        self.stats = {}
        
    def validate_file_migration(self) -> bool:
        """Validate that all .md files were properly migrated."""
        print("🔍 Validating file migration...")
        
        # Check if migration log exists
        migration_log_path = self.ai_docs / "DOCUMENTATION_MIGRATION_REPORT.md"
        if not migration_log_path.exists():
            self.errors.append("Migration report not found")
            return False
        
        # Count files in ai_docs
        ai_docs_files = list(self.ai_docs.rglob("*.md"))
        ai_docs_count = len([f for f in ai_docs_files if not f.name.startswith('.')])
        
        # Check for files left outside ai_docs (excluding certain directories)
        exclude_patterns = [
            "backup_*", "node_modules", ".git", "test_env", "venv_*",
            "target", "*_env", "ml_test_env", "security_*env", ".pytest_cache"
        ]
        
        remaining_files = []
        for md_file in self.project_root.rglob("*.md"):
            # Skip if in ai_docs
            if str(md_file).startswith(str(self.ai_docs)):
                continue
                
            # Skip if in excluded directory
            skip = False
            for exclude in exclude_patterns:
                if any(part.startswith(exclude.replace("*", "")) or 
                      (exclude.endswith("*") and part.startswith(exclude[:-1]))
                      for part in md_file.parts):
                    skip = True
                    break
            
            if not skip:
                remaining_files.append(md_file)
        
        self.stats["ai_docs_files"] = ai_docs_count
        self.stats["remaining_files"] = len(remaining_files)
        
        if remaining_files:
            self.warnings.append(f"Found {len(remaining_files)} .md files outside ai_docs")
            for file in remaining_files[:10]:  # Show first 10
                self.warnings.append(f"  - {file.relative_to(self.project_root)}")
        
        print(f"✅ Found {ai_docs_count} files in ai_docs")
        if remaining_files:
            print(f"⚠️  Found {len(remaining_files)} files outside ai_docs")
        
        return True
    
    def validate_directory_structure(self) -> bool:
        """Validate the logical organization and naming consistency."""
        print("🔍 Validating directory structure...")
        
        expected_categories = {
            "project_status", "agent_reports", "security", "performance",
            "architecture", "development", "infrastructure", "mcp_integration",
            "testing", "process_documentation", "historical"
        }
        
        # Check if main categories exist
        actual_categories = {d.name for d in self.ai_docs.iterdir() 
                           if d.is_dir() and not d.name.startswith('.')}
        
        missing_categories = expected_categories - actual_categories
        extra_categories = actual_categories - expected_categories
        
        if missing_categories:
            self.errors.append(f"Missing categories: {missing_categories}")
        
        if extra_categories:
            self.warnings.append(f"Unexpected categories: {extra_categories}")
        
        # Check agent_reports subcategories
        agent_reports_dir = self.ai_docs / "agent_reports"
        if agent_reports_dir.exists():
            agent_dirs = {d.name for d in agent_reports_dir.iterdir() if d.is_dir()}
            expected_agents = {f"agent_{i}" for i in range(1, 11)} | {"general"}
            
            missing_agents = expected_agents - agent_dirs
            if missing_agents:
                self.warnings.append(f"Missing agent directories: {missing_agents}")
        
        self.stats["categories"] = len(actual_categories)
        self.stats["missing_categories"] = len(missing_categories)
        
        print(f"✅ Found {len(actual_categories)} main categories")
        return len(missing_categories) == 0
    
    def validate_index_systems(self) -> bool:
        """Validate that index systems are working correctly."""
        print("🔍 Validating index systems...")
        
        required_indexes = [
            "00_MASTER_DOCUMENTATION_INDEX.md",
            "HISTORICAL_TIMELINE_INDEX.md", 
            "CROSS_REFERENCE_INDEX.md",
            "DOCUMENTATION_MIGRATION_REPORT.md"
        ]
        
        missing_indexes = []
        for index_file in required_indexes:
            if not (self.ai_docs / index_file).exists():
                missing_indexes.append(index_file)
        
        if missing_indexes:
            self.errors.append(f"Missing index files: {missing_indexes}")
            return False
        
        # Validate master index content
        master_index = self.ai_docs / "00_MASTER_DOCUMENTATION_INDEX.md"
        try:
            with open(master_index, 'r') as f:
                content = f.read()
                
            # Check for required sections
            required_sections = ["Quick Navigation", "Documentation Categories", "Index Statistics"]
            for section in required_sections:
                if section not in content:
                    self.warnings.append(f"Master index missing section: {section}")
                    
            # Check if it's recently updated
            if "Last Updated" in content:
                # Extract date and validate it's recent
                import datetime
                today = datetime.date.today().strftime('%Y-%m-%d')
                if today not in content:
                    self.warnings.append("Master index not updated today")
                    
        except Exception as e:
            self.errors.append(f"Error reading master index: {e}")
        
        print("✅ Index systems validated")
        return True
    
    def validate_link_integrity(self) -> bool:
        """Validate that internal links are functional and correct."""
        print("🔍 Validating link integrity...")
        
        broken_links = []
        total_links = 0
        
        for md_file in self.ai_docs.rglob("*.md"):
            try:
                with open(md_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Find markdown links
                links = re.findall(r'\[([^\]]+)\]\(([^)]+)\)', content)
                
                for link_text, link_url in links:
                    total_links += 1
                    
                    # Skip external links
                    if link_url.startswith(('http://', 'https://', 'mailto:')):
                        continue
                    
                    # Skip anchors
                    if link_url.startswith('#'):
                        continue
                    
                    # Resolve relative links
                    if link_url.startswith('./') or link_url.startswith('../'):
                        target_path = (md_file.parent / link_url).resolve()
                    else:
                        target_path = self.ai_docs / link_url
                    
                    if not target_path.exists():
                        broken_links.append({
                            "file": str(md_file.relative_to(self.ai_docs)),
                            "link_text": link_text,
                            "link_url": link_url,
                            "target": str(target_path)
                        })
                        
            except Exception as e:
                self.warnings.append(f"Error checking links in {md_file}: {e}")
        
        self.stats["total_links"] = total_links
        self.stats["broken_links"] = len(broken_links)
        
        if broken_links:
            self.errors.append(f"Found {len(broken_links)} broken links")
            for link in broken_links[:10]:  # Show first 10
                self.errors.append(f"  {link['file']}: {link['link_text']} -> {link['link_url']}")
        
        print(f"✅ Checked {total_links} links, found {len(broken_links)} broken")
        return len(broken_links) == 0
    
    def validate_cross_references(self) -> bool:
        """Validate that document relationships are properly mapped."""
        print("🔍 Validating cross-reference system...")
        
        cross_ref_path = self.ai_docs / "CROSS_REFERENCE_INDEX.md"
        if not cross_ref_path.exists():
            self.errors.append("Cross-reference index missing")
            return False
        
        try:
            with open(cross_ref_path, 'r') as f:
                content = f.read()
            
            # Check for required sections
            if "Document Relationships" not in content:
                self.warnings.append("Cross-reference index missing relationships section")
            
            if "Frequently Referenced Documents" not in content:
                self.warnings.append("Cross-reference index missing popular docs section")
                
        except Exception as e:
            self.errors.append(f"Error validating cross-references: {e}")
            return False
        
        print("✅ Cross-reference system validated")
        return True
    
    def validate_auto_update_system(self) -> bool:
        """Validate that auto-update systems are working."""
        print("🔍 Validating auto-update system...")
        
        # Check if index database exists
        index_db_path = self.ai_docs / ".index_db.json"
        if not index_db_path.exists():
            self.warnings.append("Index database not found - run auto_update_index.py")
            return True  # Not critical
        
        try:
            with open(index_db_path, 'r') as f:
                index_db = json.load(f)
            
            # Check database structure
            required_keys = ["files", "last_scan", "categories"]
            for key in required_keys:
                if key not in index_db:
                    self.warnings.append(f"Index database missing key: {key}")
            
            # Check if scan is recent
            if "last_scan" in index_db and index_db["last_scan"]:
                import datetime
                from dateutil import parser
                last_scan = parser.parse(index_db["last_scan"])
                now = datetime.datetime.now()
                hours_since_scan = (now - last_scan).total_seconds() / 3600
                
                if hours_since_scan > 24:
                    self.warnings.append("Index database is more than 24 hours old")
            
            self.stats["indexed_files"] = len(index_db.get("files", {}))
            
        except Exception as e:
            self.warnings.append(f"Error reading index database: {e}")
        
        print("✅ Auto-update system validated")
        return True
    
    def validate_documentation_discoverability(self) -> bool:
        """Validate that documentation is easy to find and access."""
        print("🔍 Validating documentation discoverability...")
        
        # Check README files in categories
        category_dirs = [d for d in self.ai_docs.iterdir() 
                        if d.is_dir() and not d.name.startswith('.')]
        
        readme_count = 0
        for cat_dir in category_dirs:
            readme_path = cat_dir / "README.md"
            if readme_path.exists():
                readme_count += 1
            else:
                if cat_dir.name not in ["historical", "decisions", "research"]:  # Optional for these
                    self.warnings.append(f"Missing README in {cat_dir.name}/")
        
        self.stats["category_readmes"] = readme_count
        self.stats["total_categories"] = len(category_dirs)
        
        # Check navigation aids
        navigation_files = [
            "00_MASTER_DOCUMENTATION_INDEX.md",
            "HISTORICAL_TIMELINE_INDEX.md"
        ]
        
        for nav_file in navigation_files:
            if not (self.ai_docs / nav_file).exists():
                self.errors.append(f"Missing navigation file: {nav_file}")
        
        print(f"✅ Found {readme_count}/{len(category_dirs)} category README files")
        return True
    
    def validate_performance(self) -> bool:
        """Test performance of index generation and documentation access."""
        print("🔍 Validating performance...")
        
        import time
        
        # Test file counting performance
        start_time = time.time()
        md_files = list(self.ai_docs.rglob("*.md"))
        file_count_time = time.time() - start_time
        
        # Test index loading performance
        index_db_path = self.ai_docs / ".index_db.json"
        if index_db_path.exists():
            start_time = time.time()
            try:
                with open(index_db_path, 'r') as f:
                    json.load(f)
                index_load_time = time.time() - start_time
            except:
                index_load_time = 0
        else:
            index_load_time = 0
        
        self.stats["file_count_time"] = file_count_time
        self.stats["index_load_time"] = index_load_time
        self.stats["total_md_files"] = len(md_files)
        
        # Performance thresholds
        if file_count_time > 5.0:
            self.warnings.append("File counting is slow (>5s)")
        
        if index_load_time > 1.0:
            self.warnings.append("Index loading is slow (>1s)")
        
        print(f"✅ Performance: {len(md_files)} files scanned in {file_count_time:.2f}s")
        return True
    
    def generate_validation_report(self) -> str:
        """Generate comprehensive validation report."""
        from datetime import datetime
        report = f"""# Documentation Organization Validation Report

**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Status**: {'✅ PASSED' if not self.errors else '❌ FAILED'}

## Validation Summary

"""
        
        if not self.errors:
            report += "✅ **All validation checks passed successfully!**\n\n"
        else:
            report += f"❌ **Found {len(self.errors)} critical issues**\n\n"
        
        if self.warnings:
            report += f"⚠️ **{len(self.warnings)} warnings detected**\n\n"
        
        # Statistics
        report += "## Statistics\n\n"
        for key, value in self.stats.items():
            formatted_key = key.replace('_', ' ').title()
            report += f"- **{formatted_key}**: {value}\n"
        
        # Errors
        if self.errors:
            report += "\n## Critical Issues\n\n"
            for i, error in enumerate(self.errors, 1):
                report += f"{i}. {error}\n"
        
        # Warnings
        if self.warnings:
            report += "\n## Warnings\n\n"
            for i, warning in enumerate(self.warnings, 1):
                report += f"{i}. {warning}\n"
        
        # Recommendations
        report += "\n## Recommendations\n\n"
        
        if self.errors:
            report += "### Critical Actions Needed\n"
            if any("missing" in error.lower() for error in self.errors):
                report += "- Fix missing files and directories\n"
            if any("broken" in error.lower() for error in self.errors):
                report += "- Repair broken links and references\n"
        
        if self.warnings:
            report += "### Improvements\n"
            if any("readme" in warning.lower() for warning in self.warnings):
                report += "- Add missing README files to categories\n"
            if any("index" in warning.lower() for warning in self.warnings):
                report += "- Update index systems regularly\n"
        
        report += "\n### Maintenance\n"
        report += "- Run `python3 auto_update_index.py` regularly to keep indexes current\n"
        report += "- Validate documentation organization after major changes\n"
        report += "- Monitor for broken links when moving or renaming files\n"
        
        return report
    
    def run_full_validation(self) -> bool:
        """Run complete validation suite."""
        from datetime import datetime
        
        print("🔍 Starting comprehensive documentation validation...")
        print("=" * 60)
        
        validation_functions = [
            ("File Migration", self.validate_file_migration),
            ("Directory Structure", self.validate_directory_structure),
            ("Index Systems", self.validate_index_systems),
            ("Link Integrity", self.validate_link_integrity),
            ("Cross-References", self.validate_cross_references),
            ("Auto-Update System", self.validate_auto_update_system),
            ("Documentation Discoverability", self.validate_documentation_discoverability),
            ("Performance", self.validate_performance)
        ]
        
        passed_tests = 0
        for test_name, test_func in validation_functions:
            try:
                if test_func():
                    passed_tests += 1
            except Exception as e:
                self.errors.append(f"{test_name}: Validation crashed - {e}")
        
        print("\n" + "=" * 60)
        print("📊 VALIDATION SUMMARY")
        print("=" * 60)
        
        success = len(self.errors) == 0
        status = "✅ SUCCESS" if success else "❌ FAILURE"
        
        print(f"{status}: {passed_tests}/{len(validation_functions)} tests passed")
        print(f"Errors: {len(self.errors)}")
        print(f"Warnings: {len(self.warnings)}")
        
        if success:
            print("\n🎉 Documentation organization validation completed successfully!")
            print("All systems are operational and properly organized.")
        else:
            print(f"\n⚠️ Validation found {len(self.errors)} critical issues.")
            print("Please review the validation report for details.")
        
        # Generate and save report
        report = self.generate_validation_report()
        report_path = self.ai_docs / "DOCUMENTATION_VALIDATION_REPORT.md"
        with open(report_path, 'w') as f:
            f.write(report)
        
        print(f"\n📄 Detailed report saved: {report_path}")
        
        return success

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Validate documentation organization")
    parser.add_argument("--ai-docs", 
                       default="/home/louranicas/projects/claude-optimized-deployment/ai_docs",
                       help="Path to ai_docs directory")
    
    args = parser.parse_args()
    
    validator = DocumentationValidator(args.ai_docs)
    success = validator.run_full_validation()
    
    return 0 if success else 1

if __name__ == "__main__":
    exit(main())