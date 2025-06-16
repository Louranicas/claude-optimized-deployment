#!/usr/bin/env python3
"""
SLO Governance CLI Tool

Command-line interface for managing SLO governance processes including:
- SLO reviews and approvals
- Change proposals and tracking
- Compliance reporting
- Historical analysis
"""

import argparse
import asyncio
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

import yaml
from rich.console import Console
from rich.table import Table
from rich.progress import track
from rich.panel import Panel
from rich.text import Text

# Add src to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from src.monitoring.sli_slo_tracking import (
    SLOTrackingSystem,
    SLOGovernance,
    SLOReporter,
    TimeWindow
)

console = Console()


class SLOGovernanceCLI:
    """CLI interface for SLO governance operations."""
    
    def __init__(self):
        self.governance = SLOGovernance()
        self.reporter = SLOReporter()
        self.tracking_system = None
    
    async def initialize(self):
        """Initialize the tracking system."""
        self.tracking_system = SLOTrackingSystem()
        await self.tracking_system.initialize()
    
    def list_slos(self, filter_priority: Optional[str] = None):
        """List all defined SLOs with their current status."""
        # Load SLO definitions
        config_path = Path(__file__).parent.parent / "config" / "slo_definitions.yaml"
        with open(config_path) as f:
            config = yaml.safe_load(f)
        
        slos = config.get("slos", {})
        
        table = Table(title="SLO Definitions")
        table.add_column("SLO Name", style="cyan")
        table.add_column("SLI", style="green")
        table.add_column("Target", style="yellow")
        table.add_column("Time Window", style="blue")
        table.add_column("Priority", style="red")
        table.add_column("Business Impact", style="magenta")
        
        for slo_name, slo_config in slos.items():
            priority = slo_config.get("priority", "medium")
            
            if filter_priority and priority != filter_priority:
                continue
            
            table.add_row(
                slo_name,
                slo_config["sli_name"],
                f"{slo_config['target']}% ({slo_config['comparison']})",
                slo_config["time_window"],
                priority,
                slo_config.get("business_impact", "N/A")
            )
        
        console.print(table)
    
    def schedule_review(
        self,
        slo_name: str,
        review_date: str,
        reviewers: List[str],
        review_type: str = "regular"
    ):
        """Schedule an SLO review."""
        try:
            review_datetime = datetime.fromisoformat(review_date)
            self.governance.schedule_review(
                slo_name,
                review_datetime,
                reviewers,
                review_type
            )
            console.print(f"✅ Review scheduled for {slo_name} on {review_date}")
        except ValueError as e:
            console.print(f"❌ Invalid date format: {e}")
    
    def list_pending_reviews(self):
        """List pending SLO reviews."""
        pending = self.governance.get_pending_reviews()
        
        if not pending:
            console.print("✅ No pending reviews")
            return
        
        table = Table(title="Pending SLO Reviews")
        table.add_column("SLO Name", style="cyan")
        table.add_column("Review Date", style="yellow")
        table.add_column("Days Overdue", style="red")
        table.add_column("Reviewers", style="blue")
        table.add_column("Type", style="green")
        
        for review in pending:
            overdue_style = "red" if review["days_overdue"] > 0 else "green"
            table.add_row(
                review["slo_name"],
                review["review_date"].strftime("%Y-%m-%d"),
                str(review["days_overdue"]),
                ", ".join(review["reviewers"]),
                review["review_type"]
            )
        
        console.print(table)
    
    def propose_change(
        self,
        slo_name: str,
        changes_file: str,
        justification: str,
        proposer: str
    ):
        """Propose a change to an SLO."""
        try:
            with open(changes_file) as f:
                changes = json.load(f)
            
            change_id = self.governance.propose_slo_change(
                slo_name,
                changes,
                justification,
                proposer
            )
            
            console.print(f"✅ Change proposal submitted: {change_id}")
            console.print(f"SLO: {slo_name}")
            console.print(f"Proposer: {proposer}")
            console.print(f"Justification: {justification}")
            
        except FileNotFoundError:
            console.print(f"❌ Changes file not found: {changes_file}")
        except json.JSONDecodeError as e:
            console.print(f"❌ Invalid JSON in changes file: {e}")
    
    def approve_change(self, change_id: str, approver: str, comments: str = None):
        """Approve an SLO change."""
        self.governance.approve_change(change_id, approver, comments)
        console.print(f"✅ Change {change_id} approved by {approver}")
        if comments:
            console.print(f"Comments: {comments}")
    
    def list_changes(self, status_filter: Optional[str] = None):
        """List SLO change proposals."""
        changes = self.governance.slo_changes
        
        if status_filter:
            changes = [c for c in changes if c["status"] == status_filter]
        
        table = Table(title="SLO Change Proposals")
        table.add_column("Change ID", style="cyan")
        table.add_column("SLO Name", style="green")
        table.add_column("Proposer", style="yellow")
        table.add_column("Status", style="red")
        table.add_column("Proposed Date", style="blue")
        table.add_column("Approvals", style="magenta")
        
        for change in changes:
            status_style = {
                "proposed": "yellow",
                "approved": "green",
                "rejected": "red"
            }.get(change["status"], "white")
            
            table.add_row(
                change["change_id"],
                change["slo_name"],
                change["proposer"],
                Text(change["status"], style=status_style),
                change["proposed_date"].strftime("%Y-%m-%d"),
                str(len(change["approvals"]))
            )
        
        console.print(table)
    
    async def generate_report(
        self,
        output_file: Optional[str] = None,
        format: str = "json",
        slo_names: Optional[List[str]] = None,
        days: int = 30
    ):
        """Generate SLO compliance report."""
        console.print("📊 Generating SLO compliance report...")
        
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=days)
        
        report = self.reporter.generate_report(
            slo_names=slo_names,
            time_range=(start_time, end_time),
            format=format
        )
        
        if output_file:
            if format == "json":
                with open(output_file, 'w') as f:
                    json.dump(report, f, indent=2, default=str)
            else:
                with open(output_file, 'w') as f:
                    f.write(report)
            console.print(f"✅ Report saved to {output_file}")
        else:
            if format == "json":
                console.print_json(json.dumps(report, indent=2, default=str))
            else:
                console.print(report)
    
    async def analyze_trends(
        self,
        slo_name: str,
        time_window: str = "rolling_7d",
        days: int = 7
    ):
        """Analyze SLO trends."""
        console.print(f"📈 Analyzing trends for {slo_name}...")
        
        window = TimeWindow(time_window)
        analysis = self.reporter.analyze_trends(
            slo_name,
            window,
            timedelta(days=days)
        )
        
        if "error" in analysis:
            console.print(f"❌ {analysis['error']}")
            return
        
        # Display trend analysis
        panel_content = f"""
**SLO:** {analysis['slo_name']}
**Time Window:** {analysis['time_window']}
**Analysis Period:** {analysis['analysis_period']} days
**Data Points:** {analysis['data_points']}

**Trend Analysis:**
• Overall Trend: {analysis['trend']['overall']}
• Improvement: {analysis['trend']['improvement_percentage']:.2f}%
• Current Compliance: {analysis['trend']['current_compliance']:.2f}%
• Average Compliance: {analysis['trend']['average_compliance']:.2f}%
• Volatility: {analysis['trend']['volatility']:.2f}%

**Predictions:**
• Breach Time: {analysis['predictions']['estimated_breach_time'] or 'N/A'}
• Confidence: {analysis['predictions']['confidence']:.1f}%
        """
        
        panel = Panel(
            panel_content,
            title=f"Trend Analysis: {slo_name}",
            border_style="blue"
        )
        console.print(panel)
    
    def validate_config(self, config_file: Optional[str] = None):
        """Validate SLO configuration file."""
        if not config_file:
            config_file = Path(__file__).parent.parent / "config" / "slo_definitions.yaml"
        
        console.print(f"🔍 Validating configuration: {config_file}")
        
        try:
            with open(config_file) as f:
                config = yaml.safe_load(f)
            
            # Validate structure
            required_sections = ["slis", "slos", "error_budget_policies"]
            for section in required_sections:
                if section not in config:
                    console.print(f"❌ Missing required section: {section}")
                    return False
            
            # Validate SLIs
            slis = config["slis"]
            slo_slis = {slo["sli_name"] for slo in config["slos"].values()}
            
            for sli_name in slo_slis:
                if sli_name not in slis:
                    console.print(f"❌ SLO references undefined SLI: {sli_name}")
                    return False
            
            # Validate SLO targets
            for slo_name, slo_config in config["slos"].items():
                target = slo_config.get("target")
                if not isinstance(target, (int, float)) or not (0 <= target <= 100):
                    console.print(f"❌ Invalid target for {slo_name}: {target}")
                    return False
                
                comparison = slo_config.get("comparison")
                if comparison not in ["gte", "lte", "gt", "lt"]:
                    console.print(f"❌ Invalid comparison for {slo_name}: {comparison}")
                    return False
            
            console.print("✅ Configuration is valid")
            return True
            
        except FileNotFoundError:
            console.print(f"❌ Configuration file not found: {config_file}")
            return False
        except yaml.YAMLError as e:
            console.print(f"❌ YAML parsing error: {e}")
            return False
    
    def show_dashboard_summary(self):
        """Show a summary dashboard of SLO status."""
        # This would integrate with the actual tracking system
        # For now, show a mock dashboard
        
        console.print("📊 SLO Dashboard Summary")
        console.print()
        
        # Summary stats table
        summary_table = Table(title="SLO Summary")
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="green")
        
        summary_table.add_row("Total SLOs", "12")
        summary_table.add_row("Meeting Target", "10")
        summary_table.add_row("At Risk", "1")
        summary_table.add_row("Breaching", "1")
        summary_table.add_row("Overall Health", "83%")
        
        console.print(summary_table)
        console.print()
        
        # SLO status table
        status_table = Table(title="SLO Status Details")
        status_table.add_column("SLO Name", style="cyan")
        status_table.add_column("Current", style="yellow")
        status_table.add_column("Target", style="blue")
        status_table.add_column("Error Budget", style="red")
        status_table.add_column("Status", style="green")
        
        # Mock data - would be real data in production
        mock_slos = [
            ("api_availability_monthly", "99.95%", "99.9%", "75%", "✅ Meeting"),
            ("api_latency_p99_daily", "98.2%", "95%", "45%", "✅ Meeting"),
            ("database_availability_monthly", "99.85%", "99.95%", "15%", "⚠️ At Risk"),
            ("auth_availability_monthly", "99.88%", "99.99%", "5%", "❌ Breaching"),
        ]
        
        for slo_data in mock_slos:
            name, current, target, budget, status = slo_data
            status_color = "green" if "Meeting" in status else "yellow" if "Risk" in status else "red"
            status_table.add_row(
                name,
                current,
                target,
                budget,
                Text(status, style=status_color)
            )
        
        console.print(status_table)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="SLO Governance CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s list-slos --priority critical
  %(prog)s schedule-review api_availability 2024-02-01 --reviewers alice,bob
  %(prog)s propose-change api_availability changes.json --justification "Improve target"
  %(prog)s generate-report --format markdown --days 30
  %(prog)s analyze-trends api_availability --time-window rolling_7d
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # List SLOs command
    list_parser = subparsers.add_parser("list-slos", help="List SLO definitions")
    list_parser.add_argument(
        "--priority",
        choices=["critical", "high", "medium", "low"],
        help="Filter by priority"
    )
    
    # Schedule review command
    review_parser = subparsers.add_parser("schedule-review", help="Schedule SLO review")
    review_parser.add_argument("slo_name", help="SLO name")
    review_parser.add_argument("review_date", help="Review date (YYYY-MM-DD)")
    review_parser.add_argument(
        "--reviewers",
        required=True,
        help="Comma-separated list of reviewers"
    )
    review_parser.add_argument(
        "--type",
        default="regular",
        choices=["regular", "emergency", "quarterly"],
        help="Review type"
    )
    
    # List pending reviews command
    subparsers.add_parser("list-reviews", help="List pending reviews")
    
    # Propose change command
    change_parser = subparsers.add_parser("propose-change", help="Propose SLO change")
    change_parser.add_argument("slo_name", help="SLO name")
    change_parser.add_argument("changes_file", help="JSON file with proposed changes")
    change_parser.add_argument("--justification", required=True, help="Change justification")
    change_parser.add_argument("--proposer", required=True, help="Proposer name")
    
    # Approve change command
    approve_parser = subparsers.add_parser("approve-change", help="Approve SLO change")
    approve_parser.add_argument("change_id", help="Change ID")
    approve_parser.add_argument("--approver", required=True, help="Approver name")
    approve_parser.add_argument("--comments", help="Approval comments")
    
    # List changes command
    changes_parser = subparsers.add_parser("list-changes", help="List change proposals")
    changes_parser.add_argument(
        "--status",
        choices=["proposed", "approved", "rejected"],
        help="Filter by status"
    )
    
    # Generate report command
    report_parser = subparsers.add_parser("generate-report", help="Generate compliance report")
    report_parser.add_argument("--output", help="Output file")
    report_parser.add_argument(
        "--format",
        choices=["json", "markdown"],
        default="json",
        help="Report format"
    )
    report_parser.add_argument("--slos", help="Comma-separated list of SLO names")
    report_parser.add_argument("--days", type=int, default=30, help="Report period in days")
    
    # Analyze trends command
    trends_parser = subparsers.add_parser("analyze-trends", help="Analyze SLO trends")
    trends_parser.add_argument("slo_name", help="SLO name")
    trends_parser.add_argument(
        "--time-window",
        default="rolling_7d",
        choices=["rolling_1h", "rolling_24h", "rolling_7d", "rolling_30d"],
        help="Time window"
    )
    trends_parser.add_argument("--days", type=int, default=7, help="Analysis period in days")
    
    # Validate config command
    validate_parser = subparsers.add_parser("validate-config", help="Validate configuration")
    validate_parser.add_argument("--config", help="Configuration file path")
    
    # Dashboard command
    subparsers.add_parser("dashboard", help="Show dashboard summary")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize CLI
    cli = SLOGovernanceCLI()
    
    async def run_async_command():
        await cli.initialize()
        
        if args.command == "generate-report":
            slo_names = args.slos.split(",") if args.slos else None
            await cli.generate_report(
                args.output,
                args.format,
                slo_names,
                args.days
            )
        elif args.command == "analyze-trends":
            await cli.analyze_trends(
                args.slo_name,
                args.time_window,
                args.days
            )
    
    # Execute command
    try:
        if args.command == "list-slos":
            cli.list_slos(args.priority)
        elif args.command == "schedule-review":
            reviewers = args.reviewers.split(",")
            cli.schedule_review(args.slo_name, args.review_date, reviewers, args.type)
        elif args.command == "list-reviews":
            cli.list_pending_reviews()
        elif args.command == "propose-change":
            cli.propose_change(
                args.slo_name,
                args.changes_file,
                args.justification,
                args.proposer
            )
        elif args.command == "approve-change":
            cli.approve_change(args.change_id, args.approver, args.comments)
        elif args.command == "list-changes":
            cli.list_changes(args.status)
        elif args.command == "validate-config":
            cli.validate_config(args.config)
        elif args.command == "dashboard":
            cli.show_dashboard_summary()
        elif args.command in ["generate-report", "analyze-trends"]:
            asyncio.run(run_async_command())
    except KeyboardInterrupt:
        console.print("\n❌ Operation cancelled")
        sys.exit(1)
    except Exception as e:
        console.print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()