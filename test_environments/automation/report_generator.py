"""
Report Generator - Comprehensive test result reporting and visualization.

This module provides advanced report generation capabilities including
HTML dashboards, PDF reports, and interactive visualizations.
"""

import base64
import json
import logging
import os
from datetime import datetime, timedelta
from enum import Enum
from io import BytesIO
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import tempfile

import jinja2
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import seaborn as sns
import pandas as pd
import numpy as np
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.lineplots import LinePlot
from reportlab.graphics.charts.barcharts import VerticalBarChart

from prometheus_client import Counter, Histogram

logger = logging.getLogger(__name__)

# Metrics
reports_generated = Counter('reports_generated_total', 'Total reports generated', ['format'])
report_generation_duration = Histogram('report_generation_duration_seconds', 'Report generation duration')


class ReportFormat(Enum):
    """Report output formats."""
    HTML = "html"
    PDF = "pdf"
    JSON = "json"
    CSV = "csv"
    DASHBOARD = "dashboard"


class ChartType(Enum):
    """Chart types for visualizations."""
    LINE = "line"
    BAR = "bar"
    PIE = "pie"
    SCATTER = "scatter"
    HEATMAP = "heatmap"
    HISTOGRAM = "histogram"


class ReportGenerator:
    """Advanced report generator with multiple output formats."""
    
    def __init__(self, template_dir: Optional[str] = None):
        self.template_dir = template_dir or str(Path(__file__).parent / "templates")
        self._setup_templates()
        self._setup_styles()
        
        # Create output directories
        self.output_dir = Path("reports")
        self.output_dir.mkdir(exist_ok=True)
        (self.output_dir / "assets").mkdir(exist_ok=True)
        
        logger.info("Report generator initialized")
        
    def _setup_templates(self) -> None:
        """Setup Jinja2 templates."""
        # Create template directory if it doesn't exist
        Path(self.template_dir).mkdir(parents=True, exist_ok=True)
        
        # Create default templates if they don't exist
        self._create_default_templates()
        
        # Setup Jinja2 environment
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(self.template_dir),
            autoescape=jinja2.select_autoescape(['html', 'xml'])
        )
        
        # Add custom filters
        self.jinja_env.filters['datetime'] = self._format_datetime
        self.jinja_env.filters['duration'] = self._format_duration
        self.jinja_env.filters['percentage'] = self._format_percentage
        
    def _setup_styles(self) -> None:
        """Setup plotting styles."""
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
        
        # Custom color scheme
        self.colors = {
            'primary': '#2E86AB',
            'secondary': '#A23B72',
            'success': '#2ECC71',
            'warning': '#F39C12',
            'danger': '#E74C3C',
            'info': '#3498DB',
            'light': '#ECF0F1',
            'dark': '#2C3E50'
        }
        
    def _create_default_templates(self) -> None:
        """Create default HTML templates."""
        # Main dashboard template
        dashboard_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Test Execution Report - {{ execution.suite.name }}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .metric-card { border-left: 4px solid #007bff; }
        .anomaly-high { border-left-color: #dc3545; }
        .anomaly-medium { border-left-color: #ffc107; }
        .anomaly-low { border-left-color: #17a2b8; }
        .trend-increasing { color: #28a745; }
        .trend-decreasing { color: #dc3545; }
        .trend-stable { color: #6c757d; }
        .chart-container { height: 400px; margin: 20px 0; }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark bg-dark">
        <div class="container-fluid">
            <span class="navbar-brand">Test Execution Report</span>
            <span class="text-white">Generated: {{ report_time | datetime }}</span>
        </div>
    </nav>
    
    <div class="container-fluid mt-4">
        <!-- Executive Summary -->
        <div class="row mb-4">
            <div class="col-12">
                <h2><i class="fas fa-chart-line"></i> Executive Summary</h2>
                <div class="row">
                    <div class="col-md-3">
                        <div class="card metric-card">
                            <div class="card-body">
                                <h5 class="card-title">Quality Score</h5>
                                <h3 class="{% if quality_score >= 80 %}text-success{% elif quality_score >= 60 %}text-warning{% else %}text-danger{% endif %}">
                                    {{ quality_score | round(1) }}%
                                </h3>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card metric-card">
                            <div class="card-body">
                                <h5 class="card-title">Test Success Rate</h5>
                                <h3 class="{% if summary.execution_summary.success_rate >= 0.9 %}text-success{% elif summary.execution_summary.success_rate >= 0.7 %}text-warning{% else %}text-danger{% endif %}">
                                    {{ (summary.execution_summary.success_rate * 100) | round(1) }}%
                                </h3>
                                <small>{{ summary.execution_summary.passed_tests }}/{{ summary.execution_summary.total_tests }} tests</small>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card metric-card">
                            <div class="card-body">
                                <h5 class="card-title">Total Duration</h5>
                                <h3>{{ summary.execution_summary.duration_stats.total | duration }}</h3>
                                <small>Avg: {{ summary.execution_summary.duration_stats.average | duration }}</small>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card metric-card">
                            <div class="card-body">
                                <h5 class="card-title">Anomalies</h5>
                                <h3 class="{% if summary.anomaly_summary.total == 0 %}text-success{% elif summary.anomaly_summary.total <= 3 %}text-warning{% else %}text-danger{% endif %}">
                                    {{ summary.anomaly_summary.total }}
                                </h3>
                                <small>detected</small>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Charts Section -->
        {% if charts %}
        <div class="row mb-4">
            <div class="col-12">
                <h3><i class="fas fa-chart-bar"></i> Performance Analytics</h3>
                <div class="row">
                    {% for chart in charts %}
                    <div class="col-md-6 mb-3">
                        <div class="card">
                            <div class="card-header">{{ chart.title }}</div>
                            <div class="card-body">
                                <img src="data:image/png;base64,{{ chart.data }}" class="img-fluid" alt="{{ chart.title }}">
                            </div>
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>
        {% endif %}
        
        <!-- Anomalies Section -->
        {% if anomalies %}
        <div class="row mb-4">
            <div class="col-12">
                <h3><i class="fas fa-exclamation-triangle"></i> Detected Anomalies</h3>
                <div class="table-responsive">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>Test</th>
                                <th>Metric</th>
                                <th>Expected</th>
                                <th>Actual</th>
                                <th>Deviation</th>
                                <th>Severity</th>
                                <th>Detection Method</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for anomaly in anomalies %}
                            <tr class="anomaly-{{ anomaly.severity }}">
                                <td>{{ anomaly.test_name }}</td>
                                <td>{{ anomaly.metric_name }}</td>
                                <td>{{ anomaly.expected_value | round(2) }}</td>
                                <td>{{ anomaly.actual_value | round(2) }}</td>
                                <td>{{ anomaly.deviation_percent | round(1) }}%</td>
                                <td>
                                    <span class="badge bg-{% if anomaly.severity == 'critical' %}danger{% elif anomaly.severity == 'high' %}warning{% else %}info{% endif %}">
                                        {{ anomaly.severity | title }}
                                    </span>
                                </td>
                                <td>{{ anomaly.detection_method }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        {% endif %}
        
        <!-- Trends Section -->
        {% if trends %}
        <div class="row mb-4">
            <div class="col-12">
                <h3><i class="fas fa-trending-up"></i> Trend Analysis</h3>
                <div class="table-responsive">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>Test</th>
                                <th>Metric</th>
                                <th>Direction</th>
                                <th>R²</th>
                                <th>Confidence</th>
                                <th>Samples</th>
                                <th>Significance</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for trend in trends %}
                            <tr>
                                <td>{{ trend.test_name }}</td>
                                <td>{{ trend.metric_name }}</td>
                                <td>
                                    <span class="trend-{{ trend.trend_direction }}">
                                        <i class="fas fa-arrow-{% if trend.trend_direction == 'increasing' %}up{% elif trend.trend_direction == 'decreasing' %}down{% else %}right{% endif %}"></i>
                                        {{ trend.trend_direction | title }}
                                    </span>
                                </td>
                                <td>{{ (trend.r_squared * 100) | round(1) }}%</td>
                                <td>{{ (trend.confidence_level * 100) | round(1) }}%</td>
                                <td>{{ trend.sample_count }}</td>
                                <td>
                                    <span class="badge bg-{% if trend.significance == 'high' %}danger{% elif trend.significance == 'medium' %}warning{% else %}secondary{% endif %}">
                                        {{ trend.significance | title }}
                                    </span>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        {% endif %}
        
        <!-- Recommendations Section -->
        {% if recommendations %}
        <div class="row mb-4">
            <div class="col-12">
                <h3><i class="fas fa-lightbulb"></i> Recommendations</h3>
                <div class="alert alert-info">
                    <ul class="mb-0">
                        {% for recommendation in recommendations %}
                        <li>{{ recommendation }}</li>
                        {% endfor %}
                    </ul>
                </div>
            </div>
        </div>
        {% endif %}
        
        <!-- Test Details Section -->
        <div class="row">
            <div class="col-12">
                <h3><i class="fas fa-list"></i> Test Results Details</h3>
                <div class="table-responsive">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>Test Name</th>
                                <th>Status</th>
                                <th>Duration</th>
                                <th>Start Time</th>
                                <th>End Time</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for result in results %}
                            <tr>
                                <td>{{ result.test_name }}</td>
                                <td>
                                    <span class="badge bg-{% if result.success %}success{% else %}danger{% endif %}">
                                        {% if result.success %}Passed{% else %}Failed{% endif %}
                                    </span>
                                </td>
                                <td>{{ result.duration | duration }}</td>
                                <td>{{ result.start_time | datetime }}</td>
                                <td>{{ result.end_time | datetime }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
        '''
        
        template_path = Path(self.template_dir) / "dashboard.html"
        if not template_path.exists():
            with open(template_path, 'w') as f:
                f.write(dashboard_template)
                
    def _format_datetime(self, dt: datetime) -> str:
        """Format datetime for display."""
        if isinstance(dt, str):
            dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S')
        
    def _format_duration(self, seconds: float) -> str:
        """Format duration for display."""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f}m"
        else:
            hours = seconds / 3600
            return f"{hours:.1f}h"
            
    def _format_percentage(self, value: float) -> str:
        """Format percentage for display."""
        return f"{value:.1f}%"
        
    async def generate_report(self, execution: Any, format_type: ReportFormat,
                            output_dir: Optional[Path] = None) -> Path:
        """Generate comprehensive test report."""
        start_time = datetime.now()
        
        try:
            output_dir = output_dir or self.output_dir
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"test_report_{timestamp}.{format_type.value}"
            output_path = output_dir / filename
            
            if format_type == ReportFormat.HTML or format_type == ReportFormat.DASHBOARD:
                await self._generate_html_report(execution, output_path)
            elif format_type == ReportFormat.PDF:
                await self._generate_pdf_report(execution, output_path)
            elif format_type == ReportFormat.JSON:
                await self._generate_json_report(execution, output_path)
            elif format_type == ReportFormat.CSV:
                await self._generate_csv_report(execution, output_path)
            else:
                raise ValueError(f"Unsupported report format: {format_type}")
                
            # Update metrics
            duration = (datetime.now() - start_time).total_seconds()
            report_generation_duration.observe(duration)
            reports_generated.labels(format=format_type.value).inc()
            
            logger.info(f"Generated {format_type.value} report: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            raise
            
    async def _generate_html_report(self, execution: Any, output_path: Path) -> None:
        """Generate HTML dashboard report."""
        # Extract data from execution
        results = getattr(execution, 'results', [])
        processed_results = getattr(execution, 'metadata', {}).get('processed_results', {})
        
        # Generate charts
        charts = await self._generate_charts(results, processed_results)
        
        # Prepare template data
        template_data = {
            'execution': execution,
            'results': results,
            'summary': processed_results.get('summary', {}),
            'quality_score': processed_results.get('quality_score', 0),
            'anomalies': processed_results.get('anomalies', []),
            'trends': processed_results.get('trends', []),
            'recommendations': processed_results.get('recommendations', []),
            'charts': charts,
            'report_time': datetime.now()
        }
        
        # Render template
        template = self.jinja_env.get_template('dashboard.html')
        html_content = template.render(**template_data)
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
    async def _generate_pdf_report(self, execution: Any, output_path: Path) -> None:
        """Generate PDF report."""
        # Create PDF document
        doc = SimpleDocTemplate(str(output_path), pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#2C3E50')
        )
        
        story.append(Paragraph(f"Test Execution Report", title_style))
        story.append(Paragraph(f"Suite: {getattr(execution.suite, 'name', 'Unknown')}", styles['Heading2']))
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", styles['Heading2']))
        
        results = getattr(execution, 'results', [])
        processed_results = getattr(execution, 'metadata', {}).get('processed_results', {})
        
        total_tests = len(results)
        passed_tests = sum(1 for r in results if getattr(r, 'success', True))
        success_rate = passed_tests / total_tests if total_tests > 0 else 0
        
        summary_data = [
            ['Metric', 'Value'],
            ['Total Tests', str(total_tests)],
            ['Passed Tests', str(passed_tests)],
            ['Failed Tests', str(total_tests - passed_tests)],
            ['Success Rate', f"{success_rate:.1%}"],
            ['Quality Score', f"{processed_results.get('quality_score', 0):.1f}%"]
        ]
        
        summary_table = Table(summary_data)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Test Results Table
        story.append(Paragraph("Test Results", styles['Heading2']))
        
        if results:
            result_data = [['Test Name', 'Status', 'Duration (s)', 'Start Time']]
            
            for result in results[:20]:  # Limit to first 20 results
                status = 'PASS' if getattr(result, 'success', True) else 'FAIL'
                duration = f"{getattr(result, 'duration', 0):.2f}"
                start_time = getattr(result, 'start_time', datetime.now()).strftime('%H:%M:%S')
                
                result_data.append([
                    getattr(result, 'test_name', 'Unknown'),
                    status,
                    duration,
                    start_time
                ])
                
            result_table = Table(result_data)
            result_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(result_table)
            
        # Recommendations
        recommendations = processed_results.get('recommendations', [])
        if recommendations:
            story.append(Spacer(1, 20))
            story.append(Paragraph("Recommendations", styles['Heading2']))
            
            for i, rec in enumerate(recommendations, 1):
                story.append(Paragraph(f"{i}. {rec}", styles['Normal']))
                
        # Build PDF
        doc.build(story)
        
    async def _generate_json_report(self, execution: Any, output_path: Path) -> None:
        """Generate JSON report."""
        report_data = {
            'execution_id': execution.id,
            'suite_name': getattr(execution.suite, 'name', 'Unknown'),
            'generated_at': datetime.now().isoformat(),
            'status': execution.status.value if hasattr(execution.status, 'value') else str(execution.status),
            'start_time': execution.start_time.isoformat() if execution.start_time else None,
            'end_time': execution.end_time.isoformat() if execution.end_time else None,
            'duration': (execution.end_time - execution.start_time).total_seconds() 
                       if execution.end_time and execution.start_time else 0,
            'results': [],
            'processed_results': getattr(execution, 'metadata', {}).get('processed_results', {})
        }
        
        # Add test results
        for result in getattr(execution, 'results', []):
            result_data = {
                'test_name': getattr(result, 'test_name', 'Unknown'),
                'success': getattr(result, 'success', True),
                'duration': getattr(result, 'duration', 0),
                'start_time': getattr(result, 'start_time', datetime.now()).isoformat(),
                'end_time': getattr(result, 'end_time', datetime.now()).isoformat(),
                'output': getattr(result, 'output', ''),
                'error': getattr(result, 'error', ''),
                'exit_code': getattr(result, 'exit_code', 0),
                'resource_usage': getattr(result, 'resource_usage', {}),
                'artifacts': getattr(result, 'artifacts', [])
            }
            report_data['results'].append(result_data)
            
        # Write JSON file
        with open(output_path, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
            
    async def _generate_csv_report(self, execution: Any, output_path: Path) -> None:
        """Generate CSV report."""
        results = getattr(execution, 'results', [])
        
        # Prepare data for CSV
        csv_data = []
        for result in results:
            row = {
                'test_name': getattr(result, 'test_name', 'Unknown'),
                'success': getattr(result, 'success', True),
                'duration': getattr(result, 'duration', 0),
                'start_time': getattr(result, 'start_time', datetime.now()).isoformat(),
                'end_time': getattr(result, 'end_time', datetime.now()).isoformat(),
                'exit_code': getattr(result, 'exit_code', 0),
                'error': getattr(result, 'error', '').replace('\n', ' ').replace(',', ';')
            }
            
            # Add resource usage columns
            resource_usage = getattr(result, 'resource_usage', {})
            for key, value in resource_usage.items():
                row[f'resource_{key}'] = value
                
            csv_data.append(row)
            
        # Write CSV using pandas
        df = pd.DataFrame(csv_data)
        df.to_csv(output_path, index=False)
        
    async def _generate_charts(self, results: List[Any], 
                             processed_results: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate charts for the report."""
        charts = []
        
        try:
            # Test duration chart
            if results:
                duration_chart = await self._create_duration_chart(results)
                if duration_chart:
                    charts.append(duration_chart)
                    
            # Success rate pie chart
            success_chart = await self._create_success_rate_chart(results)
            if success_chart:
                charts.append(success_chart)
                
            # Resource usage chart
            resource_chart = await self._create_resource_usage_chart(results)
            if resource_chart:
                charts.append(resource_chart)
                
            # Anomaly severity chart
            anomalies = processed_results.get('anomalies', [])
            if anomalies:
                anomaly_chart = await self._create_anomaly_chart(anomalies)
                if anomaly_chart:
                    charts.append(anomaly_chart)
                    
        except Exception as e:
            logger.warning(f"Error generating charts: {e}")
            
        return charts
        
    async def _create_duration_chart(self, results: List[Any]) -> Optional[Dict[str, str]]:
        """Create test duration chart."""
        try:
            durations = []
            test_names = []
            
            for result in results:
                duration = getattr(result, 'duration', 0)
                name = getattr(result, 'test_name', 'Unknown')
                if duration > 0:
                    durations.append(duration)
                    test_names.append(name[:20] + '...' if len(name) > 20 else name)
                    
            if not durations:
                return None
                
            # Create bar chart
            plt.figure(figsize=(12, 6))
            bars = plt.bar(test_names, durations, color=self.colors['primary'])
            
            # Add value labels on bars
            for bar, duration in zip(bars, durations):
                height = bar.get_height()
                plt.text(bar.get_x() + bar.get_width()/2., height,
                        f'{duration:.1f}s', ha='center', va='bottom')
                        
            plt.title('Test Execution Duration', fontsize=16, fontweight='bold')
            plt.xlabel('Test Name')
            plt.ylabel('Duration (seconds)')
            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()
            
            # Convert to base64
            img_buffer = BytesIO()
            plt.savefig(img_buffer, format='png', dpi=300, bbox_inches='tight')
            img_buffer.seek(0)
            img_data = base64.b64encode(img_buffer.getvalue()).decode('utf-8')
            plt.close()
            
            return {
                'title': 'Test Execution Duration',
                'type': 'bar',
                'data': img_data
            }
            
        except Exception as e:
            logger.warning(f"Error creating duration chart: {e}")
            return None
            
    async def _create_success_rate_chart(self, results: List[Any]) -> Optional[Dict[str, str]]:
        """Create success rate pie chart."""
        try:
            if not results:
                return None
                
            passed = sum(1 for r in results if getattr(r, 'success', True))
            failed = len(results) - passed
            
            if passed == 0 and failed == 0:
                return None
                
            # Create pie chart
            plt.figure(figsize=(8, 8))
            sizes = [passed, failed]
            labels = [f'Passed ({passed})', f'Failed ({failed})']
            colors = [self.colors['success'], self.colors['danger']]
            
            wedges, texts, autotexts = plt.pie(sizes, labels=labels, colors=colors, 
                                             autopct='%1.1f%%', startangle=90)
            
            plt.title('Test Success Rate', fontsize=16, fontweight='bold')
            plt.axis('equal')
            
            # Convert to base64
            img_buffer = BytesIO()
            plt.savefig(img_buffer, format='png', dpi=300, bbox_inches='tight')
            img_buffer.seek(0)
            img_data = base64.b64encode(img_buffer.getvalue()).decode('utf-8')
            plt.close()
            
            return {
                'title': 'Test Success Rate',
                'type': 'pie',
                'data': img_data
            }
            
        except Exception as e:
            logger.warning(f"Error creating success rate chart: {e}")
            return None
            
    async def _create_resource_usage_chart(self, results: List[Any]) -> Optional[Dict[str, str]]:
        """Create resource usage chart."""
        try:
            memory_usage = []
            cpu_usage = []
            test_names = []
            
            for result in results:
                resource_usage = getattr(result, 'resource_usage', {})
                name = getattr(result, 'test_name', 'Unknown')
                
                if resource_usage:
                    memory = resource_usage.get('peak_memory_mb', 0)
                    cpu = resource_usage.get('peak_cpu_percent', 0)
                    
                    if memory > 0 or cpu > 0:
                        memory_usage.append(memory)
                        cpu_usage.append(cpu)
                        test_names.append(name[:15] + '...' if len(name) > 15 else name)
                        
            if not memory_usage and not cpu_usage:
                return None
                
            # Create dual-axis chart
            fig, ax1 = plt.subplots(figsize=(12, 6))
            
            # Memory usage (left axis)
            color = self.colors['primary']
            ax1.set_xlabel('Tests')
            ax1.set_ylabel('Memory Usage (MB)', color=color)
            bars1 = ax1.bar([i - 0.2 for i in range(len(test_names))], memory_usage, 
                           0.4, label='Memory (MB)', color=color, alpha=0.7)
            ax1.tick_params(axis='y', labelcolor=color)
            
            # CPU usage (right axis)
            ax2 = ax1.twinx()
            color = self.colors['secondary']
            ax2.set_ylabel('CPU Usage (%)', color=color)
            bars2 = ax2.bar([i + 0.2 for i in range(len(test_names))], cpu_usage, 
                           0.4, label='CPU (%)', color=color, alpha=0.7)
            ax2.tick_params(axis='y', labelcolor=color)
            
            # Set x-axis labels
            ax1.set_xticks(range(len(test_names)))
            ax1.set_xticklabels(test_names, rotation=45, ha='right')
            
            plt.title('Resource Usage by Test', fontsize=16, fontweight='bold')
            
            # Add legend
            lines1, labels1 = ax1.get_legend_handles_labels()
            lines2, labels2 = ax2.get_legend_handles_labels()
            ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left')
            
            plt.tight_layout()
            
            # Convert to base64
            img_buffer = BytesIO()
            plt.savefig(img_buffer, format='png', dpi=300, bbox_inches='tight')
            img_buffer.seek(0)
            img_data = base64.b64encode(img_buffer.getvalue()).decode('utf-8')
            plt.close()
            
            return {
                'title': 'Resource Usage by Test',
                'type': 'bar',
                'data': img_data
            }
            
        except Exception as e:
            logger.warning(f"Error creating resource usage chart: {e}")
            return None
            
    async def _create_anomaly_chart(self, anomalies: List[Any]) -> Optional[Dict[str, str]]:
        """Create anomaly severity distribution chart."""
        try:
            if not anomalies:
                return None
                
            # Count anomalies by severity
            severity_counts = {}
            for anomaly in anomalies:
                severity = getattr(anomaly, 'severity', 'unknown')
                if hasattr(severity, 'value'):
                    severity = severity.value
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
            if not severity_counts:
                return None
                
            # Create bar chart
            plt.figure(figsize=(10, 6))
            severities = list(severity_counts.keys())
            counts = list(severity_counts.values())
            
            # Color map for severities
            severity_colors = {
                'critical': self.colors['danger'],
                'high': self.colors['warning'],
                'medium': self.colors['info'],
                'low': self.colors['secondary'],
                'info': self.colors['light']
            }
            
            colors = [severity_colors.get(s, self.colors['primary']) for s in severities]
            
            bars = plt.bar(severities, counts, color=colors)
            
            # Add value labels on bars
            for bar, count in zip(bars, counts):
                height = bar.get_height()
                plt.text(bar.get_x() + bar.get_width()/2., height,
                        str(count), ha='center', va='bottom')
                        
            plt.title('Anomaly Distribution by Severity', fontsize=16, fontweight='bold')
            plt.xlabel('Severity Level')
            plt.ylabel('Number of Anomalies')
            plt.xticks(rotation=45)
            plt.tight_layout()
            
            # Convert to base64
            img_buffer = BytesIO()
            plt.savefig(img_buffer, format='png', dpi=300, bbox_inches='tight')
            img_buffer.seek(0)
            img_data = base64.b64encode(img_buffer.getvalue()).decode('utf-8')
            plt.close()
            
            return {
                'title': 'Anomaly Distribution by Severity',
                'type': 'bar',
                'data': img_data
            }
            
        except Exception as e:
            logger.warning(f"Error creating anomaly chart: {e}")
            return None


# Example usage
if __name__ == "__main__":
    import asyncio
    from dataclasses import dataclass
    from datetime import datetime
    
    @dataclass
    class MockTestSuite:
        name: str = "Performance Test Suite"
        
    @dataclass
    class MockExecution:
        id: str = "test-123"
        suite: MockTestSuite = None
        status: str = "completed"
        start_time: datetime = None
        end_time: datetime = None
        results: list = None
        metadata: dict = None
        
        def __post_init__(self):
            if self.suite is None:
                self.suite = MockTestSuite()
            if self.start_time is None:
                self.start_time = datetime.now()
            if self.end_time is None:
                self.end_time = datetime.now()
            if self.results is None:
                self.results = []
            if self.metadata is None:
                self.metadata = {}
                
    async def test_report_generation():
        generator = ReportGenerator()
        execution = MockExecution()
        
        # Generate HTML report
        html_path = await generator.generate_report(execution, ReportFormat.HTML)
        print(f"Generated HTML report: {html_path}")
        
        # Generate PDF report
        pdf_path = await generator.generate_report(execution, ReportFormat.PDF)
        print(f"Generated PDF report: {pdf_path}")
        
    asyncio.run(test_report_generation())