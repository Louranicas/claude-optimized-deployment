#!/usr/bin/env python3
"""
Performance Charts Generator for CODE v1.0.0
===========================================

Creates comprehensive performance visualization charts from benchmark results.
"""

import json
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from pathlib import Path

def load_performance_data():
    """Load the latest performance benchmark data"""
    reports_dir = Path('/home/louranicas/projects/claude-optimized-deployment/performance_reports')
    
    # Find the latest performance report
    json_files = list(reports_dir.glob('performance_report_*.json'))
    if not json_files:
        raise FileNotFoundError("No performance reports found")
    
    latest_file = max(json_files, key=lambda x: x.stat().st_mtime)
    
    with open(latest_file, 'r') as f:
        return json.load(f)

def create_performance_dashboard():
    """Create a comprehensive performance dashboard"""
    # Load data
    data = load_performance_data()
    results = data['results']
    
    # Set up the plotting style
    plt.style.use('default')
    sns.set_palette("husl")
    
    # Create figure with subplots
    fig = plt.figure(figsize=(20, 16))
    fig.suptitle('CODE v1.0.0 - Comprehensive Performance Dashboard', fontsize=20, fontweight='bold', y=0.98)
    
    # Extract data for plotting
    test_names = [r['test_name'].replace('_', ' ').title() for r in results]
    throughputs = [r['throughput'] for r in results]
    latencies_p95 = [r['latency_p95'] * 1000 for r in results]  # Convert to ms
    memory_peak = [r['memory_usage']['peak_mb'] for r in results]
    success_rates = [r['success_rate'] for r in results]
    cpu_usage = [r['cpu_usage'] for r in results]
    
    # 1. Throughput Comparison (Top Left)
    ax1 = plt.subplot(3, 3, 1)
    bars1 = ax1.bar(range(len(test_names)), throughputs, color='skyblue', edgecolor='navy', alpha=0.7)
    ax1.set_title('Throughput Performance', fontsize=14, fontweight='bold')
    ax1.set_ylabel('Operations per Second')
    ax1.set_yscale('log')  # Log scale for better visualization
    ax1.tick_params(axis='x', rotation=45)
    
    # Add value labels on bars
    for i, bar in enumerate(bars1):
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height * 1.1, f'{throughputs[i]:.0f}',
                ha='center', va='bottom', fontsize=8)
    
    # 2. Latency Comparison (Top Center)
    ax2 = plt.subplot(3, 3, 2)
    bars2 = ax2.bar(range(len(test_names)), latencies_p95, color='lightcoral', edgecolor='darkred', alpha=0.7)
    ax2.set_title('Latency P95 Performance', fontsize=14, fontweight='bold')
    ax2.set_ylabel('Latency (ms)')
    ax2.tick_params(axis='x', rotation=45)
    
    # Add value labels
    for i, bar in enumerate(bars2):
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height * 1.1, f'{latencies_p95[i]:.2f}',
                ha='center', va='bottom', fontsize=8)
    
    # 3. Memory Usage (Top Right)
    ax3 = plt.subplot(3, 3, 3)
    bars3 = ax3.bar(range(len(test_names)), memory_peak, color='lightgreen', edgecolor='darkgreen', alpha=0.7)
    ax3.set_title('Peak Memory Usage', fontsize=14, fontweight='bold')
    ax3.set_ylabel('Memory (MB)')
    ax3.tick_params(axis='x', rotation=45)
    
    # Add value labels
    for i, bar in enumerate(bars3):
        height = bar.get_height()
        ax3.text(bar.get_x() + bar.get_width()/2., height * 1.1, f'{memory_peak[i]:.1f}',
                ha='center', va='bottom', fontsize=8)
    
    # 4. Success Rate (Middle Left)
    ax4 = plt.subplot(3, 3, 4)
    bars4 = ax4.bar(range(len(test_names)), success_rates, color='gold', edgecolor='orange', alpha=0.7)
    ax4.set_title('Success Rate', fontsize=14, fontweight='bold')
    ax4.set_ylabel('Success Rate (%)')
    ax4.set_ylim(0, 105)
    ax4.tick_params(axis='x', rotation=45)
    
    # Add value labels
    for i, bar in enumerate(bars4):
        height = bar.get_height()
        ax4.text(bar.get_x() + bar.get_width()/2., height + 1, f'{success_rates[i]:.1f}%',
                ha='center', va='bottom', fontsize=8)
    
    # 5. CPU Usage (Middle Center)
    ax5 = plt.subplot(3, 3, 5)
    bars5 = ax5.bar(range(len(test_names)), cpu_usage, color='purple', edgecolor='indigo', alpha=0.7)
    ax5.set_title('CPU Usage', fontsize=14, fontweight='bold')
    ax5.set_ylabel('CPU Usage (%)')
    ax5.tick_params(axis='x', rotation=45)
    
    # Add value labels
    for i, bar in enumerate(bars5):
        height = bar.get_height()
        ax5.text(bar.get_x() + bar.get_width()/2., height * 1.1, f'{cpu_usage[i]:.1f}%',
                ha='center', va='bottom', fontsize=8)
    
    # 6. Performance Score Comparison (Middle Right)
    ax6 = plt.subplot(3, 3, 6)
    
    # Calculate performance scores
    performance_scores = []
    for i in range(len(results)):
        # Normalize metrics (0-100 scale)
        throughput_score = min(100, throughputs[i] / max(throughputs) * 100)
        latency_score = max(0, 100 - (latencies_p95[i] / max(latencies_p95) * 100))
        success_score = success_rates[i]
        memory_score = max(0, 100 - (memory_peak[i] / max(memory_peak) * 100))
        
        overall_score = (throughput_score + latency_score + success_score + memory_score) / 4
        performance_scores.append(overall_score)
    
    bars6 = ax6.bar(range(len(test_names)), performance_scores, color='teal', edgecolor='darkslategray', alpha=0.7)
    ax6.set_title('Overall Performance Score', fontsize=14, fontweight='bold')
    ax6.set_ylabel('Performance Score (0-100)')
    ax6.set_ylim(0, 105)
    ax6.tick_params(axis='x', rotation=45)
    
    # Add value labels
    for i, bar in enumerate(bars6):
        height = bar.get_height()
        ax6.text(bar.get_x() + bar.get_width()/2., height + 1, f'{performance_scores[i]:.1f}',
                ha='center', va='bottom', fontsize=8)
    
    # 7. Component Performance Comparison (Bottom Left)
    ax7 = plt.subplot(3, 3, 7)
    
    # Group by component categories
    component_categories = {
        'Rust Acceleration': ['rust_infrastructure_scanning', 'rust_config_parsing', 'rust_simd_operations'],
        'Caching System': ['cache_write_performance', 'cache_read_performance', 'cache_invalidation_performance'],
        'Circuit Breaker': ['circuit_breaker_normal', 'circuit_breaker_failures'],
        'Retry Logic': ['retry_exponential_backoff', 'retry_fixed_delay'],
        'System Load': ['cpu_intensive_load', 'memory_intensive_load', 'io_intensive_load'],
        'Memory Management': ['memory_allocation_patterns', 'garbage_collection_efficiency']
    }
    
    component_scores = []
    component_names = []
    
    for category, tests in component_categories.items():
        category_throughputs = []
        for test in tests:
            for result in results:
                if result['test_name'] in test:
                    category_throughputs.append(result['throughput'])
        
        if category_throughputs:
            avg_throughput = np.mean(category_throughputs)
            component_scores.append(avg_throughput)
            component_names.append(category)
    
    bars7 = ax7.barh(range(len(component_names)), component_scores, color='orange', alpha=0.7)
    ax7.set_title('Component Throughput Comparison', fontsize=14, fontweight='bold')
    ax7.set_xlabel('Average Throughput (ops/sec)')
    ax7.set_yticks(range(len(component_names)))
    ax7.set_yticklabels(component_names)
    ax7.set_xscale('log')
    
    # 8. Performance Trends (Bottom Center)
    ax8 = plt.subplot(3, 3, 8)
    
    # Create performance trend over test sequence
    test_sequence = range(len(results))
    trend_throughputs = [r['throughput'] for r in results]
    
    ax8.plot(test_sequence, trend_throughputs, marker='o', linewidth=2, markersize=6, color='red')
    ax8.set_title('Performance Trend During Testing', fontsize=14, fontweight='bold')
    ax8.set_xlabel('Test Sequence')
    ax8.set_ylabel('Throughput (ops/sec)')
    ax8.set_yscale('log')
    ax8.grid(True, alpha=0.3)
    
    # Add trend line
    if len(trend_throughputs) > 1:
        z = np.polyfit(test_sequence, np.log(trend_throughputs), 1)
        p = np.poly1d(z)
        ax8.plot(test_sequence, np.exp(p(test_sequence)), "--", alpha=0.7, color='blue', label='Trend')
        ax8.legend()
    
    # 9. System Resource Utilization (Bottom Right)
    ax9 = plt.subplot(3, 3, 9)
    
    # Create resource utilization summary
    avg_cpu = np.mean(cpu_usage)
    avg_memory = np.mean(memory_peak)
    max_cpu = max(cpu_usage)
    max_memory = max(memory_peak)
    
    categories = ['Avg CPU %', 'Max CPU %', 'Avg Memory MB', 'Max Memory MB']
    values = [avg_cpu, max_cpu, avg_memory, max_memory]
    colors = ['lightblue', 'darkblue', 'lightgreen', 'darkgreen']
    
    bars9 = ax9.bar(categories, values, color=colors, alpha=0.7)
    ax9.set_title('System Resource Utilization', fontsize=14, fontweight='bold')
    ax9.set_ylabel('Value')
    ax9.tick_params(axis='x', rotation=45)
    
    # Add value labels
    for i, bar in enumerate(bars9):
        height = bar.get_height()
        ax9.text(bar.get_x() + bar.get_width()/2., height * 1.1, f'{values[i]:.1f}',
                ha='center', va='bottom', fontsize=10)
    
    # Adjust layout and remove x-labels for most subplots to save space
    for i, ax in enumerate([ax1, ax2, ax3, ax4, ax5, ax6]):
        if i < 6:  # Top and middle rows
            ax.set_xticklabels([])
    
    # Only show x-labels for bottom row
    for i, ax in enumerate([ax7, ax8, ax9]):
        if i == 0:  # ax7 already has y-labels
            continue
        elif i == 1:  # ax8
            ax.set_xticklabels([f'T{j+1}' for j in range(len(test_names))], rotation=45)
    
    plt.tight_layout()
    
    # Save the dashboard
    output_path = Path('/home/louranicas/projects/claude-optimized-deployment/performance_reports/performance_dashboard.png')
    plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    
    print(f"✅ Performance dashboard saved to: {output_path}")
    return output_path

def create_summary_report():
    """Create a summary performance report with key metrics"""
    data = load_performance_data()
    summary = data['summary']
    
    # Create summary visualization
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
    fig.suptitle('CODE v1.0.0 - Performance Summary Report', fontsize=18, fontweight='bold')
    
    # 1. Overall Performance Grade
    grade = summary['performance_grade']
    grade_colors = {'A+': 'green', 'A': 'lightgreen', 'B': 'yellow', 'C': 'orange', 'D': 'red'}
    grade_letter = grade.split(' ')[0]
    
    ax1.pie([1], labels=[grade], colors=[grade_colors.get(grade_letter, 'gray')], 
            autopct='%1.1f%%', startangle=90, textprops={'fontsize': 14, 'fontweight': 'bold'})
    ax1.set_title('Overall Performance Grade', fontsize=14, fontweight='bold')
    
    # 2. Key Metrics
    metrics = ['Total Throughput\n(ops/sec)', 'Average Latency\n(ms)', 'Success Rate\n(%)', 'Memory Usage\n(MB)']
    values = [
        summary['total_throughput_ops_per_sec'],
        summary['average_latency_ms'],
        summary['average_success_rate_percent'],
        summary['total_memory_used_mb']
    ]
    
    bars = ax2.bar(metrics, values, color=['skyblue', 'lightcoral', 'gold', 'lightgreen'], alpha=0.7)
    ax2.set_title('Key Performance Metrics', fontsize=14, fontweight='bold')
    ax2.set_ylabel('Value')
    
    # Add value labels
    for i, bar in enumerate(bars):
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height * 1.1, f'{values[i]:.1f}',
                ha='center', va='bottom', fontsize=10, fontweight='bold')
    
    # 3. Best Performing Tests
    results = data['results']
    fastest_test = summary['fastest_test']
    highest_throughput_test = summary['highest_throughput_test']
    
    best_tests = [fastest_test, highest_throughput_test]
    best_labels = ['Fastest Test', 'Highest Throughput']
    
    ax3.barh(best_labels, [1, 1], color=['purple', 'teal'], alpha=0.7)
    ax3.set_title('Best Performing Tests', fontsize=14, fontweight='bold')
    ax3.set_xlim(0, 1.2)
    
    # Add test names as text
    for i, test in enumerate(best_tests):
        ax3.text(0.5, i, test.replace('_', ' ').title(), ha='center', va='center', 
                fontsize=10, fontweight='bold', color='white')
    
    # 4. System Information
    system_info = data['benchmark_info']['system_baseline']
    info_text = f"""System Configuration:
    
CPU Cores: {system_info['cpu_count']}
Total Memory: {system_info['memory_total'] / 1024**3:.1f} GB
Available Memory: {system_info['memory_available'] / 1024**3:.1f} GB
Platform: {system_info['platform'].title()}
Python: {system_info['python_version'].split()[0]}

Test Duration: {data['benchmark_info']['duration']:.1f} seconds
Total Tests: {data['benchmark_info']['total_tests']}"""
    
    ax4.text(0.1, 0.5, info_text, transform=ax4.transAxes, fontsize=12,
            verticalalignment='center', bbox=dict(boxstyle='round', facecolor='lightgray', alpha=0.8))
    ax4.set_title('Test Environment', fontsize=14, fontweight='bold')
    ax4.axis('off')
    
    plt.tight_layout()
    
    # Save the summary
    output_path = Path('/home/louranicas/projects/claude-optimized-deployment/performance_reports/performance_summary.png')
    plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    
    print(f"✅ Performance summary saved to: {output_path}")
    return output_path

def main():
    """Main function to generate all performance charts"""
    print("📊 Generating Performance Charts for CODE v1.0.0")
    print("=" * 60)
    
    try:
        # Create comprehensive dashboard
        dashboard_path = create_performance_dashboard()
        
        # Create summary report
        summary_path = create_summary_report()
        
        print("\n🎉 Performance visualization complete!")
        print(f"📈 Dashboard: {dashboard_path}")
        print(f"📋 Summary: {summary_path}")
        print("=" * 60)
        
    except Exception as e:
        print(f"❌ Error generating charts: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()