#!/usr/bin/env python3
"""
Git Performance Monitor for CODE Project
Analyzes and optimizes git repository performance
"""
import subprocess
import time
import os
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple

class GitPerformanceMonitor:
    def __init__(self):
        self.repo_path = Path.cwd()
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "repository": str(self.repo_path),
            "benchmarks": {},
            "analysis": {},
            "recommendations": []
        }
        
    def measure_command(self, cmd: List[str]) -> Tuple[float, bool]:
        """Measure execution time of a git command"""
        try:
            start = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True)
            duration = time.time() - start
            success = result.returncode == 0
            return duration, success
        except Exception as e:
            print(f"Error running {' '.join(cmd)}: {e}")
            return 0.0, False
    
    def benchmark_operations(self):
        """Benchmark common git operations"""
        print("🚀 Running Git Performance Benchmarks\n")
        
        operations = [
            (["git", "status"], "Status", 0.5),
            (["git", "status", "--porcelain"], "Status (porcelain)", 0.3),
            (["git", "log", "--oneline", "-10"], "Log (10 commits)", 0.5),
            (["git", "log", "--oneline", "-100"], "Log (100 commits)", 1.0),
            (["git", "diff"], "Diff (unstaged)", 0.5),
            (["git", "diff", "--cached"], "Diff (staged)", 0.5),
            (["git", "branch", "-a"], "List all branches", 0.3),
            (["git", "ls-files"], "List tracked files", 1.0),
            (["git", "rev-list", "--all", "--count"], "Count commits", 2.0),
            (["git", "fsck", "--connectivity-only"], "Check connectivity", 5.0),
        ]
        
        print(f"{'Operation':<30} {'Time':>10} {'Status':>10} {'Performance':>15}")
        print("-" * 70)
        
        for cmd, name, threshold in operations:
            duration, success = self.measure_command(cmd)
            status = "✅" if success else "❌"
            
            if duration > threshold:
                perf = "🔴 Slow"
            elif duration > threshold * 0.5:
                perf = "🟡 OK"
            else:
                perf = "🟢 Fast"
            
            print(f"{name:<30} {duration:>8.3f}s {status:>10} {perf:>15}")
            
            self.results["benchmarks"][name] = {
                "duration": duration,
                "success": success,
                "threshold": threshold,
                "performance": perf.split()[1]
            }
    
    def analyze_repository(self):
        """Analyze repository statistics"""
        print("\n\n📊 Repository Analysis\n")
        
        # Repository size
        size_output = subprocess.check_output(
            ["git", "count-objects", "-v", "-H"],
            text=True
        )
        
        size_info = {}
        for line in size_output.strip().split("\n"):
            if ": " in line:
                key, value = line.split(": ", 1)
                size_info[key] = value
        
        self.results["analysis"]["size"] = size_info
        
        print("Repository Size:")
        for key, value in size_info.items():
            print(f"  {key}: {value}")
        
        # File statistics
        print("\nFile Statistics:")
        
        # Total files
        files = subprocess.check_output(
            ["git", "ls-files"],
            text=True
        ).strip().split("\n")
        file_count = len(files)
        print(f"  Total tracked files: {file_count:,}")
        
        # File types
        extensions = {}
        for file in files:
            ext = Path(file).suffix.lower() or "no extension"
            extensions[ext] = extensions.get(ext, 0) + 1
        
        print(f"  File types: {len(extensions)}")
        print("  Top 5 extensions:")
        for ext, count in sorted(extensions.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"    {ext}: {count}")
        
        self.results["analysis"]["files"] = {
            "total": file_count,
            "extensions": dict(sorted(extensions.items(), key=lambda x: x[1], reverse=True)[:10])
        }
        
        # Commit statistics
        print("\nCommit Statistics:")
        
        # Total commits
        commit_count = subprocess.check_output(
            ["git", "rev-list", "--all", "--count"],
            text=True
        ).strip()
        print(f"  Total commits: {commit_count}")
        
        # Recent commits
        recent_commits = subprocess.check_output(
            ["git", "log", "--since=30.days", "--oneline"],
            text=True
        ).strip().split("\n")
        print(f"  Commits (last 30 days): {len(recent_commits)}")
        
        # Contributors
        contributors = subprocess.check_output(
            ["git", "shortlog", "-sn", "--all"],
            text=True
        ).strip().split("\n")
        print(f"  Total contributors: {len(contributors)}")
        
        self.results["analysis"]["commits"] = {
            "total": int(commit_count),
            "last_30_days": len(recent_commits),
            "contributors": len(contributors)
        }
        
        # Branch statistics
        print("\nBranch Statistics:")
        
        # Local branches
        local_branches = subprocess.check_output(
            ["git", "branch"],
            text=True
        ).strip().split("\n")
        print(f"  Local branches: {len(local_branches)}")
        
        # Remote branches
        remote_branches = subprocess.check_output(
            ["git", "branch", "-r"],
            text=True
        ).strip().split("\n")
        print(f"  Remote branches: {len(remote_branches)}")
        
        # Stale branches (no commits in 90 days)
        stale_branches = []
        for branch in local_branches:
            branch = branch.strip().replace("* ", "")
            try:
                last_commit = subprocess.check_output(
                    ["git", "log", "-1", "--format=%cr", branch],
                    text=True
                ).strip()
                # Simple check for "months" or "years" in the relative date
                if "months" in last_commit or "years" in last_commit:
                    stale_branches.append(branch)
            except:
                pass
        
        print(f"  Stale branches: {len(stale_branches)}")
        
        self.results["analysis"]["branches"] = {
            "local": len(local_branches),
            "remote": len(remote_branches),
            "stale": len(stale_branches)
        }
    
    def check_optimizations(self):
        """Check for possible optimizations"""
        print("\n\n🔍 Checking Optimizations\n")
        
        optimizations = []
        
        # Check commit graph
        commit_graph_path = self.repo_path / ".git" / "objects" / "info" / "commit-graph"
        if not commit_graph_path.exists():
            print("❌ Commit graph not found")
            optimizations.append({
                "issue": "Missing commit graph",
                "impact": "Slower commit walks",
                "fix": "git commit-graph write --reachable"
            })
        else:
            print("✅ Commit graph exists")
        
        # Check maintenance
        try:
            maintenance_status = subprocess.check_output(
                ["git", "config", "--get", "maintenance.auto"],
                text=True
            ).strip()
            if maintenance_status != "true":
                print("❌ Automatic maintenance disabled")
                optimizations.append({
                    "issue": "Automatic maintenance disabled",
                    "impact": "Manual optimization required",
                    "fix": "git maintenance start"
                })
            else:
                print("✅ Automatic maintenance enabled")
        except subprocess.CalledProcessError:
            print("❌ Automatic maintenance not configured")
            optimizations.append({
                "issue": "Automatic maintenance not configured",
                "impact": "Repository may degrade over time",
                "fix": "git maintenance start"
            })
        
        # Check for large files
        large_files = []
        try:
            # Find files larger than 50MB
            for file in Path(".").rglob("*"):
                if file.is_file() and ".git" not in str(file):
                    try:
                        size = file.stat().st_size
                        if size > 50 * 1024 * 1024:  # 50MB
                            large_files.append((str(file), size))
                    except:
                        pass
            
            if large_files:
                print(f"❌ Found {len(large_files)} large files (>50MB)")
                optimizations.append({
                    "issue": f"{len(large_files)} large files not in LFS",
                    "impact": "Slow clones and fetches",
                    "fix": "Consider using Git LFS for large files"
                })
            else:
                print("✅ No large files found")
        except Exception as e:
            print(f"⚠️  Error checking for large files: {e}")
        
        # Check pack files
        pack_dir = self.repo_path / ".git" / "objects" / "pack"
        if pack_dir.exists():
            pack_files = list(pack_dir.glob("*.pack"))
            if len(pack_files) > 5:
                print(f"❌ Too many pack files ({len(pack_files)})")
                optimizations.append({
                    "issue": f"Too many pack files ({len(pack_files)})",
                    "impact": "Slower operations",
                    "fix": "git gc --aggressive"
                })
            else:
                print(f"✅ Pack files OK ({len(pack_files)})")
        
        # Check index version
        try:
            index_version = subprocess.check_output(
                ["git", "config", "--get", "index.version"],
                text=True
            ).strip()
            if index_version != "4":
                print(f"❌ Using index version {index_version} (not optimal)")
                optimizations.append({
                    "issue": f"Using index version {index_version}",
                    "impact": "Slower index operations",
                    "fix": "git config index.version 4"
                })
            else:
                print("✅ Using index version 4")
        except subprocess.CalledProcessError:
            print("❌ Index version not set")
            optimizations.append({
                "issue": "Index version not configured",
                "impact": "Using default (slower) index",
                "fix": "git config index.version 4"
            })
        
        self.results["recommendations"] = optimizations
        
        return optimizations
    
    def generate_report(self):
        """Generate performance report"""
        print("\n\n📝 Performance Report Summary\n")
        
        # Overall health score
        total_checks = 5
        passed_checks = total_checks - len(self.results["recommendations"])
        health_score = (passed_checks / total_checks) * 100
        
        if health_score >= 80:
            health_status = "🟢 Excellent"
        elif health_score >= 60:
            health_status = "🟡 Good"
        else:
            health_status = "🔴 Needs Attention"
        
        print(f"Overall Health Score: {health_score:.0f}% {health_status}")
        
        # Performance summary
        slow_operations = [
            name for name, data in self.results["benchmarks"].items()
            if data["performance"] == "Slow"
        ]
        
        if slow_operations:
            print(f"\nSlow Operations Detected: {len(slow_operations)}")
            for op in slow_operations:
                print(f"  - {op}")
        else:
            print("\nAll operations performing well! 🎉")
        
        # Recommendations
        if self.results["recommendations"]:
            print(f"\n💡 Recommendations ({len(self.results['recommendations'])})")
            for i, rec in enumerate(self.results["recommendations"], 1):
                print(f"\n{i}. {rec['issue']}")
                print(f"   Impact: {rec['impact']}")
                print(f"   Fix: {rec['fix']}")
        
        # Save detailed report
        report_path = Path("git-performance-report.json")
        with open(report_path, "w") as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n\nDetailed report saved to: {report_path}")
    
    def optimize_repository(self):
        """Apply automatic optimizations"""
        response = input("\n\nApply automatic optimizations? (y/n): ")
        if response.lower() != 'y':
            return
        
        print("\n🔧 Applying optimizations...\n")
        
        optimizations = [
            ("Updating commit graph", ["git", "commit-graph", "write", "--reachable"]),
            ("Running maintenance", ["git", "maintenance", "run", "--auto"]),
            ("Optimizing repository", ["git", "gc", "--auto"]),
            ("Updating index", ["git", "update-index", "--refresh"]),
        ]
        
        for desc, cmd in optimizations:
            print(f"{desc}... ", end="", flush=True)
            try:
                subprocess.run(cmd, check=True, capture_output=True)
                print("✅")
            except subprocess.CalledProcessError as e:
                print(f"❌ Failed: {e}")
        
        # Set optimal configurations
        configs = [
            ("core.preloadindex", "true"),
            ("core.fscache", "true"),
            ("core.untrackedCache", "true"),
            ("core.commitGraph", "true"),
            ("feature.manyFiles", "true"),
            ("index.version", "4"),
            ("index.threads", "true"),
            ("pack.threads", "0"),
            ("maintenance.auto", "true"),
        ]
        
        print("\nSetting optimal configurations:")
        for key, value in configs:
            try:
                subprocess.run(["git", "config", key, value], check=True)
                print(f"  {key} = {value} ✅")
            except subprocess.CalledProcessError:
                print(f"  {key} = {value} ❌")
        
        print("\n✅ Optimizations complete!")

def main():
    """Main entry point"""
    monitor = GitPerformanceMonitor()
    
    print("Git Performance Monitor for CODE Project")
    print("=" * 50)
    
    # Run all checks
    monitor.benchmark_operations()
    monitor.analyze_repository()
    monitor.check_optimizations()
    monitor.generate_report()
    
    # Offer to optimize
    monitor.optimize_repository()

if __name__ == "__main__":
    main()
