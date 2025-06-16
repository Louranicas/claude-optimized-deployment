#!/usr/bin/env python3
"""
Validation Script for Agent 3 Mitigation Matrix
Validates all fixes implemented based on the comprehensive mitigation strategies.
"""

import sys
import subprocess
import ast
import importlib.util
from pathlib import Path
import json
from typing import Dict, List, Tuple, Any
import time

class MitigationValidator:
    """Validates all mitigation strategies from Agent 3's matrix."""
    
    def __init__(self):
        self.project_root = Path(__file__).parent.parent
        self.results = {
            "rust_toolchain": {"status": "pending", "details": {}},
            "mcp_imports": {"status": "pending", "details": {}},
            "export_standards": {"status": "pending", "details": {}},
            "documentation": {"status": "pending", "details": {}}
        }
    
    def validate_rust_toolchain(self) -> Dict[str, Any]:
        """Validate Rust toolchain upgrade (Priority 1)."""
        print("🔍 Validating Rust Toolchain Update...")
        
        try:
            # Check Rust version
            rust_version = subprocess.run(
                ["rustc", "--version"], 
                capture_output=True, text=True, check=True
            )
            cargo_version = subprocess.run(
                ["cargo", "--version"], 
                capture_output=True, text=True, check=True
            )
            
            rust_ver = rust_version.stdout.strip()
            cargo_ver = cargo_version.stdout.strip()
            
            # Extract version numbers
            rust_num = rust_ver.split()[1]
            cargo_num = cargo_ver.split()[1]
            
            # Check if version is 1.78+
            rust_major_minor = float('.'.join(rust_num.split('.')[:2]))
            target_version = 1.78
            
            is_updated = rust_major_minor >= target_version
            
            # Test workspace compilation
            compilation_success = False
            try:
                result = subprocess.run(
                    ["cargo", "check", "--workspace"],
                    cwd=self.project_root / "rust_core",
                    capture_output=True, text=True, timeout=60
                )
                compilation_success = result.returncode == 0
            except subprocess.TimeoutExpired:
                compilation_success = False
            
            details = {
                "rust_version": rust_ver,
                "cargo_version": cargo_ver,
                "version_adequate": is_updated,
                "compilation_success": compilation_success,
                "target_version": target_version,
                "actual_version": rust_major_minor
            }
            
            status = "success" if is_updated and compilation_success else "failed"
            
            return {"status": status, "details": details}
            
        except Exception as e:
            return {"status": "error", "details": {"error": str(e)}}
    
    def validate_mcp_imports(self) -> Dict[str, Any]:
        """Validate MCP circular import resolution (Priority 2)."""
        print("🔍 Validating MCP Import Resolution...")
        
        try:
            # Test direct import
            import_success = False
            import_error = None
            
            try:
                # Change to project directory for imports
                sys.path.insert(0, str(self.project_root))
                
                # Test problematic imports
                from src.mcp import MCPClient, MCPManager
                from src.mcp.manager import MCPManager as DirectManager
                from src.mcp.servers import MCPServerRegistry
                
                import_success = True
            except ImportError as e:
                import_error = str(e)
            except Exception as e:
                import_error = f"Other error: {str(e)}"
            
            # Analyze import structure
            mcp_files = list((self.project_root / "src" / "mcp").rglob("*.py"))
            circular_patterns = []
            
            for file_path in mcp_files:
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                        
                    # Parse AST to find imports
                    tree = ast.parse(content)
                    
                    for node in ast.walk(tree):
                        if isinstance(node, ast.ImportFrom):
                            if node.module and "src.mcp" in node.module:
                                relative_path = file_path.relative_to(self.project_root / "src")
                                import_path = node.module
                                
                                # Check for potential circular patterns
                                if self._is_circular_pattern(str(relative_path), import_path):
                                    circular_patterns.append({
                                        "file": str(relative_path),
                                        "imports": import_path
                                    })
                except Exception:
                    continue
            
            details = {
                "import_success": import_success,
                "import_error": import_error,
                "circular_patterns_found": len(circular_patterns),
                "circular_details": circular_patterns[:5],  # First 5 patterns
                "total_mcp_files": len(mcp_files)
            }
            
            status = "success" if import_success and len(circular_patterns) == 0 else "failed"
            
            return {"status": status, "details": details}
            
        except Exception as e:
            return {"status": "error", "details": {"error": str(e)}}
    
    def _is_circular_pattern(self, file_path: str, import_path: str) -> bool:
        """Check if an import pattern could be circular."""
        # Simplified circular detection
        if "mcp/__init__.py" in file_path and "mcp.manager" in import_path:
            return True
        if "mcp/manager.py" in file_path and "mcp.servers" in import_path:
            return True
        if "mcp/servers.py" in file_path and "mcp.manager" in import_path:
            return True
        return False
    
    def validate_export_standards(self) -> Dict[str, Any]:
        """Validate export standardization (Priority 3)."""
        print("🔍 Validating Export Standardization...")
        
        try:
            # Find all __init__.py files with __all__ declarations
            init_files = list(self.project_root.rglob("src/**/__init__.py"))
            
            standardization_results = []
            total_files = len(init_files)
            compliant_files = 0
            
            for init_file in init_files:
                try:
                    with open(init_file, 'r') as f:
                        content = f.read()
                    
                    # Check for __all__ declaration
                    has_all = "__all__" in content
                    has_version = "__version__" in content
                    has_docstring = '"""' in content or "'''" in content
                    
                    # Parse AST to validate __all__ structure
                    try:
                        tree = ast.parse(content)
                        all_is_list = False
                        all_items = []
                        
                        for node in ast.walk(tree):
                            if (isinstance(node, ast.Assign) and 
                                len(node.targets) == 1 and
                                isinstance(node.targets[0], ast.Name) and
                                node.targets[0].id == "__all__"):
                                
                                if isinstance(node.value, ast.List):
                                    all_is_list = True
                                    all_items = [
                                        elt.s if isinstance(elt, ast.Str) else 
                                        elt.value if isinstance(elt, ast.Constant) else None
                                        for elt in node.value.elts
                                    ]
                        
                        is_compliant = has_all and all_is_list and len(all_items) > 0
                        if is_compliant:
                            compliant_files += 1
                        
                        standardization_results.append({
                            "file": str(init_file.relative_to(self.project_root)),
                            "has_all": has_all,
                            "has_version": has_version,
                            "has_docstring": has_docstring,
                            "all_is_list": all_is_list,
                            "export_count": len(all_items),
                            "compliant": is_compliant
                        })
                        
                    except SyntaxError:
                        standardization_results.append({
                            "file": str(init_file.relative_to(self.project_root)),
                            "error": "Syntax error in file"
                        })
                        
                except Exception as e:
                    standardization_results.append({
                        "file": str(init_file.relative_to(self.project_root)),
                        "error": str(e)
                    })
            
            compliance_rate = (compliant_files / total_files * 100) if total_files > 0 else 0
            
            details = {
                "total_files": total_files,
                "compliant_files": compliant_files,
                "compliance_rate": compliance_rate,
                "files_analyzed": standardization_results[:10]  # First 10 for brevity
            }
            
            status = "success" if compliance_rate >= 80 else "failed"
            
            return {"status": status, "details": details}
            
        except Exception as e:
            return {"status": "error", "details": {"error": str(e)}}
    
    def validate_documentation(self) -> Dict[str, Any]:
        """Validate documentation alignment (Priority 4)."""
        print("🔍 Validating Documentation Alignment...")
        
        try:
            # Find documentation files
            doc_files = list(self.project_root.rglob("*.md"))
            
            # Check for outdated version references
            version_issues = []
            example_issues = []
            
            for doc_file in doc_files:
                try:
                    with open(doc_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # Check for version references that might be outdated
                    if "1.75" in content:
                        version_issues.append({
                            "file": str(doc_file.relative_to(self.project_root)),
                            "issue": "Contains Rust 1.75 reference"
                        })
                    
                    # Check for code blocks that might need validation
                    if "```python" in content or "```rust" in content:
                        example_issues.append({
                            "file": str(doc_file.relative_to(self.project_root)),
                            "type": "Contains code examples"
                        })
                        
                except Exception:
                    continue
            
            # Check if mitigation matrix exists
            matrix_exists = (self.project_root / "COMPREHENSIVE_ERROR_MITIGATION_MATRIX_AGENT_3.md").exists()
            
            details = {
                "total_docs": len(doc_files),
                "version_issues": len(version_issues),
                "docs_with_examples": len(example_issues),
                "mitigation_matrix_created": matrix_exists,
                "version_issue_details": version_issues[:5],
                "example_files": [ex["file"] for ex in example_issues[:5]]
            }
            
            # Consider success if mitigation matrix exists and minimal version issues
            status = "success" if matrix_exists and len(version_issues) <= 2 else "needs_review"
            
            return {"status": status, "details": details}
            
        except Exception as e:
            return {"status": "error", "details": {"error": str(e)}}
    
    def run_comprehensive_validation(self) -> Dict[str, Any]:
        """Run all validation procedures."""
        print("🚀 Starting Comprehensive Mitigation Validation...")
        print("=" * 60)
        
        start_time = time.time()
        
        # Run all validations
        self.results["rust_toolchain"] = self.validate_rust_toolchain()
        self.results["mcp_imports"] = self.validate_mcp_imports()
        self.results["export_standards"] = self.validate_export_standards()
        self.results["documentation"] = self.validate_documentation()
        
        # Calculate overall results
        total_validations = len(self.results)
        successful_validations = sum(
            1 for result in self.results.values() 
            if result["status"] == "success"
        )
        
        end_time = time.time()
        duration = end_time - start_time
        
        overall_success_rate = (successful_validations / total_validations * 100)
        
        summary = {
            "validation_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "duration_seconds": round(duration, 2),
            "total_validations": total_validations,
            "successful_validations": successful_validations,
            "success_rate": round(overall_success_rate, 2),
            "overall_status": "PASS" if overall_success_rate >= 75 else "FAIL",
            "individual_results": self.results
        }
        
        print(f"\n📊 Validation Summary:")
        print(f"  Total Validations: {total_validations}")
        print(f"  Successful: {successful_validations}")
        print(f"  Success Rate: {overall_success_rate:.1f}%")
        print(f"  Duration: {duration:.2f} seconds")
        print(f"  Overall Status: {summary['overall_status']}")
        
        return summary

def main():
    """Main validation execution."""
    if len(sys.argv) > 1 and sys.argv[1] == "--json":
        # JSON output mode
        validator = MitigationValidator()
        results = validator.run_comprehensive_validation()
        print(json.dumps(results, indent=2))
    else:
        # Human-readable output
        validator = MitigationValidator()
        results = validator.run_comprehensive_validation()
        
        print("\n" + "=" * 60)
        print("DETAILED RESULTS:")
        print("=" * 60)
        
        for validation_name, result in results["individual_results"].items():
            print(f"\n{validation_name.upper()}:")
            print(f"  Status: {result['status']}")
            
            if "details" in result:
                for key, value in result["details"].items():
                    if isinstance(value, (list, dict)):
                        print(f"  {key}: {json.dumps(value, indent=4)}")
                    else:
                        print(f"  {key}: {value}")

if __name__ == "__main__":
    main()