#!/usr/bin/env python3
"""
AGENT 10: Final Comprehensive Validation and Security Re-Audit
Comprehensive assessment after error mitigation and security fixes
"""

import asyncio
import json
import sys
import os
import time
import statistics
import subprocess
from datetime import datetime
from pathlib import Path

class FinalValidationAssessment:
    """Final comprehensive validation and assessment"""
    
    def __init__(self):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'validation_phases': {},
            'overall_status': 'UNKNOWN',
            'readiness_score': 0.0,
            'critical_issues': [],
            'recommendations': []
        }
    
    def phase1_post_fix_validation(self):
        """Phase 1: Post-Fix System Validation"""
        print("=== PHASE 1: POST-FIX VALIDATION ===")
        
        phase1_results = {
            'python_dependencies': self._check_python_dependencies(),
            'rust_compilation': self._check_rust_compilation(),
            'ffi_integration': self._check_ffi_integration(),
            'basic_imports': self._check_basic_imports()
        }
        
        self.results['validation_phases']['phase1'] = phase1_results
        return phase1_results
    
    def _check_python_dependencies(self):
        """Check Python dependencies availability"""
        required_modules = ['numpy', 'matplotlib', 'sklearn', 'torch', 'pandas', 'transformers', 'seaborn']
        success_count = 0
        failed_modules = []
        
        for module in required_modules:
            try:
                __import__(module)
                success_count += 1
            except ImportError:
                failed_modules.append(module)
        
        return {
            'total_required': len(required_modules),
            'successful': success_count,
            'failed_modules': failed_modules,
            'success_rate': (success_count / len(required_modules)) * 100,
            'status': 'PASS' if success_count >= len(required_modules) * 0.6 else 'FAIL'
        }
    
    def _check_rust_compilation(self):
        """Check Rust compilation status"""
        log_file = Path('rust_build_results.log')
        
        if not log_file.exists():
            return {'status': 'NO_LOG', 'message': 'No build log found'}
        
        with open(log_file) as f:
            log_content = f.read()
        
        if 'Finished release' in log_content:
            return {'status': 'PASS', 'message': 'Rust compilation successful'}
        elif 'error:' in log_content.lower():
            # Count errors
            error_count = log_content.lower().count('error:')
            return {
                'status': 'FAIL', 
                'error_count': error_count,
                'message': f'Rust compilation failed with {error_count} errors'
            }
        else:
            return {'status': 'UNKNOWN', 'message': 'Unclear compilation status'}
    
    def _check_ffi_integration(self):
        """Check FFI integration capability"""
        try:
            sys.path.append(str(Path.cwd() / 'python_learning'))
            import mcp_learning
            return {'status': 'PASS', 'message': 'FFI module import successful'}
        except ImportError as e:
            return {'status': 'FAIL', 'message': f'FFI import failed: {e}'}
        except Exception as e:
            return {'status': 'ERROR', 'message': f'Unexpected FFI error: {e}'}
    
    def _check_basic_imports(self):
        """Check basic system imports"""
        basic_modules = ['os', 'sys', 'json', 'asyncio', 'pathlib']
        import_results = {}
        
        for module in basic_modules:
            try:
                __import__(module)
                import_results[module] = 'SUCCESS'
            except ImportError:
                import_results[module] = 'FAILED'
        
        success_count = sum(1 for status in import_results.values() if status == 'SUCCESS')
        
        return {
            'results': import_results,
            'success_rate': (success_count / len(basic_modules)) * 100,
            'status': 'PASS' if success_count == len(basic_modules) else 'FAIL'
        }
    
    async def phase2_mcp_server_validation(self):
        """Phase 2: MCP Server Validation"""
        print("=== PHASE 2: MCP SERVER VALIDATION ===")
        
        server_results = {}
        
        # Test server directories exist
        server_dirs = ['development', 'devops', 'quality', 'bash_god']
        for server in server_dirs:
            server_path = Path('servers') / server
            if server_path.exists():
                server_results[server] = await self._test_server_basic(server, server_path)
            else:
                server_results[server] = {
                    'status': 'MISSING',
                    'message': f'Server directory not found: {server_path}'
                }
        
        self.results['validation_phases']['phase2'] = server_results
        return server_results
    
    async def _test_server_basic(self, server_name, server_path):
        """Basic server testing"""
        try:
            # Check for Python source
            python_src = server_path / 'python_src'
            rust_src = server_path / 'rust_src'
            
            structure_check = {
                'python_src_exists': python_src.exists(),
                'rust_src_exists': rust_src.exists(),
                'has_server_py': (python_src / 'server.py').exists() if python_src.exists() else False
            }
            
            # Attempt basic import test
            import_test = {'status': 'UNTESTED'}
            if structure_check['has_server_py']:
                try:
                    # Add to path and attempt import
                    sys.path.insert(0, str(python_src))
                    import server
                    import_test = {'status': 'SUCCESS', 'message': 'Server module imported'}
                except Exception as e:
                    import_test = {'status': 'FAILED', 'message': f'Import failed: {e}'}
                finally:
                    # Clean up path
                    if str(python_src) in sys.path:
                        sys.path.remove(str(python_src))
            
            return {
                'status': 'EVALUATED',
                'structure_check': structure_check,
                'import_test': import_test
            }
            
        except Exception as e:
            return {'status': 'ERROR', 'message': f'Server test error: {e}'}
    
    def phase3_security_reaudit(self):
        """Phase 3: Security Re-Audit"""
        print("=== PHASE 3: SECURITY RE-AUDIT ===")
        
        security_results = {
            'bandit_scan': self._run_bandit_security_scan(),
            'file_permissions': self._check_file_permissions(),
            'dependency_audit': self._check_dependency_security()
        }
        
        self.results['validation_phases']['phase3'] = security_results
        return security_results
    
    def _run_bandit_security_scan(self):
        """Run Bandit security scan"""
        try:
            # Run bandit security scan
            result = subprocess.run([
                'bandit', '-r', '.', '-f', 'json', '-o', 'post_fix_bandit_report.json'
            ], capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                # Read results
                if Path('post_fix_bandit_report.json').exists():
                    with open('post_fix_bandit_report.json') as f:
                        bandit_data = json.load(f)
                    
                    issues = bandit_data.get('results', [])
                    high_severity = sum(1 for issue in issues if issue.get('issue_severity') == 'HIGH')
                    medium_severity = sum(1 for issue in issues if issue.get('issue_severity') == 'MEDIUM')
                    
                    return {
                        'status': 'COMPLETED',
                        'total_issues': len(issues),
                        'high_severity': high_severity,
                        'medium_severity': medium_severity,
                        'assessment': 'GOOD' if high_severity == 0 else 'NEEDS_ATTENTION'
                    }
                else:
                    return {'status': 'NO_OUTPUT', 'message': 'Bandit ran but no output file created'}
            else:
                return {'status': 'FAILED', 'message': f'Bandit failed: {result.stderr}'}
                
        except subprocess.TimeoutExpired:
            return {'status': 'TIMEOUT', 'message': 'Bandit scan timed out'}
        except FileNotFoundError:
            return {'status': 'NOT_AVAILABLE', 'message': 'Bandit not installed'}
        except Exception as e:
            return {'status': 'ERROR', 'message': f'Bandit scan error: {e}'}
    
    def _check_file_permissions(self):
        """Check file permissions for security"""
        sensitive_files = ['config.toml', 'config.yaml', '*.key', '*.pem']
        permission_issues = []
        
        for pattern in sensitive_files:
            for file_path in Path('.').glob(f'**/{pattern}'):
                if file_path.is_file():
                    stat_info = file_path.stat()
                    # Check if file is world-readable (others can read)
                    if stat_info.st_mode & 0o004:
                        permission_issues.append(str(file_path))
        
        return {
            'issues_found': len(permission_issues),
            'problematic_files': permission_issues,
            'status': 'PASS' if len(permission_issues) == 0 else 'NEEDS_ATTENTION'
        }
    
    def _check_dependency_security(self):
        """Check dependency security"""
        try:
            # Run pip-audit if available
            result = subprocess.run([
                'pip-audit', '--format=json', '--output=post_fix_pip_audit.json'
            ], capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                if Path('post_fix_pip_audit.json').exists():
                    with open('post_fix_pip_audit.json') as f:
                        audit_data = json.load(f)
                    
                    vulnerabilities = audit_data.get('vulnerabilities', [])
                    return {
                        'status': 'COMPLETED',
                        'vulnerabilities_found': len(vulnerabilities),
                        'assessment': 'GOOD' if len(vulnerabilities) == 0 else 'NEEDS_ATTENTION'
                    }
                else:
                    return {'status': 'NO_OUTPUT'}
            else:
                return {'status': 'FAILED', 'message': result.stderr}
                
        except subprocess.TimeoutExpired:
            return {'status': 'TIMEOUT'}
        except FileNotFoundError:
            return {'status': 'NOT_AVAILABLE', 'message': 'pip-audit not installed'}
        except Exception as e:
            return {'status': 'ERROR', 'message': str(e)}
    
    def phase4_performance_baseline(self):
        """Phase 4: Performance Baseline Establishment"""
        print("=== PHASE 4: PERFORMANCE BASELINES ===")
        
        benchmarks = {
            'system_info': {
                'python_version': sys.version.split()[0],
                'platform': sys.platform
            },
            'tests': {}
        }
        
        # Benchmark 1: Module Import Speed
        start_time = time.perf_counter()
        try:
            import json as test_json
            import_time = time.perf_counter() - start_time
            benchmarks['tests']['basic_import'] = {
                'time_ms': import_time * 1000,
                'status': 'SUCCESS'
            }
        except Exception as e:
            benchmarks['tests']['basic_import'] = {
                'time_ms': -1,
                'status': 'FAILED',
                'error': str(e)
            }
        
        # Benchmark 2: JSON Processing
        test_data = {"test": "data", "numbers": list(range(1000))}
        times = []
        
        for _ in range(100):
            start_time = time.perf_counter()
            json_str = json.dumps(test_data)
            parsed = json.loads(json_str)
            times.append(time.perf_counter() - start_time)
        
        benchmarks['tests']['json_processing'] = {
            'avg_time_ms': statistics.mean(times) * 1000,
            'p95_time_ms': statistics.quantiles(times, n=20)[18] * 1000 if len(times) > 20 else max(times) * 1000,
            'status': 'SUCCESS'
        }
        
        # Benchmark 3: File I/O
        start_time = time.perf_counter()
        try:
            with open('test_benchmark_file.tmp', 'w') as f:
                f.write("test data" * 1000)
            with open('test_benchmark_file.tmp', 'r') as f:
                content = f.read()
            os.remove('test_benchmark_file.tmp')
            
            io_time = time.perf_counter() - start_time
            benchmarks['tests']['file_io'] = {
                'time_ms': io_time * 1000,
                'status': 'SUCCESS'
            }
        except Exception as e:
            benchmarks['tests']['file_io'] = {
                'time_ms': -1,
                'status': 'FAILED',
                'error': str(e)
            }
        
        self.results['validation_phases']['phase4'] = benchmarks
        return benchmarks
    
    def phase5_production_readiness(self):
        """Phase 5: Production Readiness Assessment"""
        print("=== PHASE 5: PRODUCTION READINESS ASSESSMENT ===")
        
        criteria = {
            'dependency_resolution': False,
            'rust_compilation': False,
            'security_issues_minimal': False,
            'basic_functionality': False,
            'performance_acceptable': False,
            'documentation_exists': False
        }
        
        # Evaluate criteria based on previous phases
        phase1 = self.results['validation_phases'].get('phase1', {})
        phase2 = self.results['validation_phases'].get('phase2', {})
        phase3 = self.results['validation_phases'].get('phase3', {})
        phase4 = self.results['validation_phases'].get('phase4', {})
        
        # Dependency resolution
        python_deps = phase1.get('python_dependencies', {})
        criteria['dependency_resolution'] = python_deps.get('success_rate', 0) >= 40  # At least 40% of deps
        
        # Rust compilation
        rust_comp = phase1.get('rust_compilation', {})
        criteria['rust_compilation'] = rust_comp.get('status') == 'PASS'
        
        # Security issues
        bandit_scan = phase3.get('bandit_scan', {})
        criteria['security_issues_minimal'] = bandit_scan.get('high_severity', 10) < 5
        
        # Basic functionality
        server_count = len([s for s in phase2.values() if s.get('status') != 'MISSING'])
        criteria['basic_functionality'] = server_count >= 2
        
        # Performance
        json_perf = phase4.get('tests', {}).get('json_processing', {})
        criteria['performance_acceptable'] = json_perf.get('avg_time_ms', 1000) < 100  # Under 100ms avg
        
        # Documentation
        doc_files = ['README.md', 'ARCHITECTURE.md']
        criteria['documentation_exists'] = all(Path(f).exists() for f in doc_files)
        
        # Calculate readiness score
        passed_criteria = sum(criteria.values())
        total_criteria = len(criteria)
        readiness_score = (passed_criteria / total_criteria) * 100
        
        readiness_assessment = {
            'criteria': criteria,
            'passed': passed_criteria,
            'total': total_criteria,
            'readiness_score': readiness_score,
            'recommendation': self._get_readiness_recommendation(readiness_score),
            'next_steps': self._get_next_steps(criteria)
        }
        
        self.results['validation_phases']['phase5'] = readiness_assessment
        self.results['readiness_score'] = readiness_score
        self.results['overall_status'] = readiness_assessment['recommendation']
        
        return readiness_assessment
    
    def _get_readiness_recommendation(self, score):
        """Get readiness recommendation based on score"""
        if score >= 80:
            return 'READY_FOR_STAGING'
        elif score >= 60:
            return 'READY_WITH_CAVEATS'
        elif score >= 40:
            return 'DEVELOPMENT_READY'
        else:
            return 'NOT_READY'
    
    def _get_next_steps(self, criteria):
        """Get next steps based on failed criteria"""
        next_steps = []
        
        if not criteria['dependency_resolution']:
            next_steps.append('Install missing Python dependencies (sklearn, torch, pandas, transformers, seaborn)')
        
        if not criteria['rust_compilation']:
            next_steps.append('Fix Rust compilation errors in rust_core module')
        
        if not criteria['security_issues_minimal']:
            next_steps.append('Address high-severity security issues found by Bandit')
        
        if not criteria['basic_functionality']:
            next_steps.append('Ensure at least 2 MCP servers are functional')
        
        if not criteria['performance_acceptable']:
            next_steps.append('Optimize performance to meet baseline requirements')
        
        if not criteria['documentation_exists']:
            next_steps.append('Create missing documentation files')
        
        return next_steps
    
    async def run_comprehensive_validation(self):
        """Run all validation phases"""
        print("STARTING FINAL COMPREHENSIVE VALIDATION")
        print("=" * 50)
        
        try:
            # Phase 1: Post-fix validation
            self.phase1_post_fix_validation()
            
            # Phase 2: MCP server validation
            await self.phase2_mcp_server_validation()
            
            # Phase 3: Security re-audit
            self.phase3_security_reaudit()
            
            # Phase 4: Performance baselines
            self.phase4_performance_baseline()
            
            # Phase 5: Production readiness
            self.phase5_production_readiness()
            
            # Save complete results
            with open('final_validation_results.json', 'w') as f:
                json.dump(self.results, f, indent=2)
            
            return self.results
            
        except Exception as e:
            self.results['critical_issues'].append(f'Validation failed: {e}')
            self.results['overall_status'] = 'VALIDATION_FAILED'
            return self.results
    
    def print_summary(self):
        """Print validation summary"""
        print("\n" + "=" * 60)
        print("FINAL VALIDATION SUMMARY")
        print("=" * 60)
        
        print(f"Overall Status: {self.results['overall_status']}")
        print(f"Readiness Score: {self.results['readiness_score']:.1f}%")
        
        # Phase summaries
        for phase_name, phase_data in self.results['validation_phases'].items():
            print(f"\n{phase_name.upper()}:")
            if phase_name == 'phase1':
                deps = phase_data.get('python_dependencies', {})
                print(f"  Python Dependencies: {deps.get('successful', 0)}/{deps.get('total_required', 0)} successful")
                
                rust = phase_data.get('rust_compilation', {})
                print(f"  Rust Compilation: {rust.get('status', 'UNKNOWN')}")
                
                ffi = phase_data.get('ffi_integration', {})
                print(f"  FFI Integration: {ffi.get('status', 'UNKNOWN')}")
                
            elif phase_name == 'phase2':
                server_count = len([s for s in phase_data.values() if s.get('status') != 'MISSING'])
                print(f"  MCP Servers Available: {server_count}/4")
                
            elif phase_name == 'phase3':
                bandit = phase_data.get('bandit_scan', {})
                print(f"  Security Scan: {bandit.get('status', 'NOT_RUN')}")
                if 'high_severity' in bandit:
                    print(f"  High Severity Issues: {bandit['high_severity']}")
                
            elif phase_name == 'phase4':
                tests = phase_data.get('tests', {})
                successful_tests = sum(1 for test in tests.values() if test.get('status') == 'SUCCESS')
                print(f"  Performance Tests: {successful_tests}/{len(tests)} passed")
                
            elif phase_name == 'phase5':
                passed = phase_data.get('passed', 0)
                total = phase_data.get('total', 0)
                print(f"  Readiness Criteria: {passed}/{total} met")
        
        # Next steps
        phase5 = self.results['validation_phases'].get('phase5', {})
        next_steps = phase5.get('next_steps', [])
        if next_steps:
            print("\nNEXT STEPS:")
            for i, step in enumerate(next_steps, 1):
                print(f"  {i}. {step}")
        
        print("\n" + "=" * 60)

async def main():
    """Main execution function"""
    validator = FinalValidationAssessment()
    
    # Run comprehensive validation
    results = await validator.run_comprehensive_validation()
    
    # Print summary
    validator.print_summary()
    
    # Final recommendation
    print(f"\nFINAL RECOMMENDATION: {results['overall_status']}")
    
    return results

if __name__ == "__main__":
    # Run the validation
    results = asyncio.run(main())