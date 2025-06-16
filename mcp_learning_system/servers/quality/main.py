#!/usr/bin/env python3
"""
Quality MCP Server - Main Entry Point
Comprehensive quality analysis server with ML-powered insights and automated testing
"""

import asyncio
import logging
import sys
import os
import json
import traceback
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
import argparse

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

# Import server components
from python_src.quality_learning import QualityLearning, QualityMetrics, QualityReport

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class QualityMCPServer:
    """
    Main Quality MCP Server with comprehensive quality analysis capabilities
    Provides code quality assessment, test analysis, and ML-powered recommendations
    """
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path
        self.config = self._load_config()
        
        # Initialize components
        self.quality_learning = QualityLearning()
        
        # Server state
        self.is_running = False
        self.start_time = None
        
        # Quality analysis cache
        self.analysis_cache = {}
        self.cache_timeout = timedelta(minutes=30)
        
        # Metrics tracking
        self.metrics = {
            'analyses_performed': 0,
            'files_analyzed': 0,
            'issues_detected': 0,
            'recommendations_made': 0,
            'ml_predictions': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'uptime_seconds': 0
        }
        
        logger.info("Quality MCP Server initialized")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load server configuration"""
        default_config = {
            'server': {
                'name': 'quality-mcp-server',
                'version': '1.0.0',
                'port': 8086,
                'host': '0.0.0.0'
            },
            'quality': {
                'analysis': {
                    'max_file_size_mb': 10,
                    'timeout_seconds': 30,
                    'enable_ml_predictions': True,
                    'enable_caching': True
                },
                'thresholds': {
                    'complexity_warning': 10,
                    'complexity_error': 20,
                    'coverage_warning': 80,
                    'coverage_error': 60,
                    'duplicates_warning': 5,
                    'duplicates_error': 10
                },
                'frameworks': {
                    'pytest': True,
                    'unittest': True,
                    'coverage': True,
                    'bandit': True,
                    'mypy': True,
                    'black': True,
                    'pylint': True
                }
            },
            'ml': {
                'model_update_interval': 3600,  # 1 hour
                'min_training_samples': 100,
                'prediction_confidence_threshold': 0.7
            }
        }
        
        if self.config_path and Path(self.config_path).exists():
            try:
                import yaml
                with open(self.config_path, 'r') as f:
                    loaded_config = yaml.safe_load(f)
                # Merge with defaults
                default_config.update(loaded_config)
            except Exception as e:
                logger.warning(f"Failed to load config from {self.config_path}: {e}")
        
        return default_config
    
    async def start_server(self):
        """Start the Quality MCP Server"""
        logger.info("Starting Quality MCP Server...")
        
        self.start_time = datetime.utcnow()
        self.is_running = True
        
        try:
            # Start background tasks
            tasks = [
                asyncio.create_task(self._main_server_loop()),
                asyncio.create_task(self._cache_cleanup_loop()),
                asyncio.create_task(self._ml_training_loop()),
                asyncio.create_task(self._metrics_update_loop())
            ]
            
            logger.info(f"Quality MCP Server started on {self.config['server']['host']}:{self.config['server']['port']}")
            
            # Wait for all tasks
            await asyncio.gather(*tasks)
            
        except Exception as e:
            logger.error(f"Server error: {e}")
            await self.stop_server()
    
    async def stop_server(self):
        """Stop the Quality MCP Server"""
        logger.info("Stopping Quality MCP Server...")
        self.is_running = False
        logger.info("Quality MCP Server stopped")
    
    async def _main_server_loop(self):
        """Main server processing loop"""
        while self.is_running:
            try:
                # Update metrics
                self._update_metrics()
                
                # Process any queued analyses
                await self._process_analysis_queue()
                
                await asyncio.sleep(1)  # Main loop frequency
                
            except Exception as e:
                logger.error(f"Error in main server loop: {e}")
                await asyncio.sleep(5)
    
    async def _cache_cleanup_loop(self):
        """Cache cleanup loop"""
        while self.is_running:
            try:
                current_time = datetime.utcnow()
                expired_keys = []
                
                for key, (data, timestamp) in self.analysis_cache.items():
                    if current_time - timestamp > self.cache_timeout:
                        expired_keys.append(key)
                
                for key in expired_keys:
                    del self.analysis_cache[key]
                
                if expired_keys:
                    logger.info(f"Cleaned up {len(expired_keys)} expired cache entries")
                
                await asyncio.sleep(600)  # Cleanup every 10 minutes
                
            except Exception as e:
                logger.error(f"Error in cache cleanup loop: {e}")
                await asyncio.sleep(600)
    
    async def _ml_training_loop(self):
        """ML model training loop"""
        while self.is_running:
            try:
                if self.config['ml']['model_update_interval'] > 0:
                    logger.info("Starting ML model training...")
                    
                    # Train quality prediction models
                    training_results = await self.quality_learning.update_models()
                    
                    if training_results.get('success'):
                        self.metrics['ml_predictions'] += training_results.get('predictions_made', 0)
                        logger.info(f"ML training completed: {training_results}")
                    
                    await asyncio.sleep(self.config['ml']['model_update_interval'])
                else:
                    await asyncio.sleep(3600)  # Check hourly if disabled
                
            except Exception as e:
                logger.error(f"Error in ML training loop: {e}")
                await asyncio.sleep(1800)  # Back off on error
    
    async def _metrics_update_loop(self):
        """Metrics update loop"""
        while self.is_running:
            try:
                self._update_metrics()
                await asyncio.sleep(60)  # Update every minute
                
            except Exception as e:
                logger.error(f"Error in metrics update loop: {e}")
                await asyncio.sleep(60)
    
    def _update_metrics(self):
        """Update server metrics"""
        if self.start_time:
            self.metrics['uptime_seconds'] = (datetime.utcnow() - self.start_time).total_seconds()
    
    async def _process_analysis_queue(self):
        """Process any queued quality analyses"""
        # Placeholder for queue processing
        pass
    
    # Public API Methods
    
    async def analyze_file_quality(self, file_path: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Analyze quality of a single file"""
        try:
            self.metrics['analyses_performed'] += 1
            self.metrics['files_analyzed'] += 1
            
            file_path_obj = Path(file_path)
            if not file_path_obj.exists():
                return {
                    'error': f'File not found: {file_path}',
                    'status': 'error'
                }
            
            # Check cache first
            cache_key = f"{file_path}:{file_path_obj.stat().st_mtime}"
            if self.config['quality']['analysis']['enable_caching'] and cache_key in self.analysis_cache:
                self.metrics['cache_hits'] += 1
                cached_data, _ = self.analysis_cache[cache_key]
                return cached_data
            
            self.metrics['cache_misses'] += 1
            
            # Perform quality analysis
            logger.info(f"Analyzing file quality: {file_path}")
            
            quality_report = await self.quality_learning.analyze_file_comprehensive(
                file_path, options or {}
            )
            
            # Count issues
            if quality_report.issues:
                self.metrics['issues_detected'] += len(quality_report.issues)
            
            if quality_report.recommendations:
                self.metrics['recommendations_made'] += len(quality_report.recommendations)
            
            # Prepare response
            response = {
                'file_path': file_path,
                'analysis_timestamp': datetime.utcnow().isoformat(),
                'status': 'success',
                'metrics': quality_report.metrics.__dict__,
                'issues': [issue.__dict__ for issue in quality_report.issues],
                'recommendations': quality_report.recommendations,
                'overall_score': quality_report.overall_score,
                'grade': quality_report.grade,
                'summary': quality_report.summary
            }
            
            # Cache the result
            if self.config['quality']['analysis']['enable_caching']:
                self.analysis_cache[cache_key] = (response, datetime.utcnow())
            
            return response
            
        except Exception as e:
            logger.error(f"Error analyzing file quality: {e}")
            logger.error(traceback.format_exc())
            return {
                'error': str(e),
                'status': 'error',
                'file_path': file_path
            }
    
    async def analyze_project_quality(self, project_path: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Analyze quality of an entire project"""
        try:
            self.metrics['analyses_performed'] += 1
            
            project_path_obj = Path(project_path)
            if not project_path_obj.exists():
                return {
                    'error': f'Project path not found: {project_path}',
                    'status': 'error'
                }
            
            logger.info(f"Analyzing project quality: {project_path}")
            
            # Find Python files
            python_files = list(project_path_obj.rglob('*.py'))
            if not python_files:
                return {
                    'error': 'No Python files found in project',
                    'status': 'error'
                }
            
            # Analyze each file
            file_analyses = []
            total_issues = 0
            total_recommendations = 0
            
            for py_file in python_files:
                if py_file.stat().st_size > self.config['quality']['analysis']['max_file_size_mb'] * 1024 * 1024:
                    logger.warning(f"Skipping large file: {py_file}")
                    continue
                
                file_analysis = await self.analyze_file_quality(str(py_file), options)
                if file_analysis.get('status') == 'success':
                    file_analyses.append(file_analysis)
                    total_issues += len(file_analysis.get('issues', []))
                    total_recommendations += len(file_analysis.get('recommendations', []))
                    self.metrics['files_analyzed'] += 1
            
            # Calculate project-level metrics
            if file_analyses:
                avg_score = sum(fa.get('overall_score', 0) for fa in file_analyses) / len(file_analyses)
                project_grade = self._calculate_project_grade(avg_score)
            else:
                avg_score = 0
                project_grade = 'F'
            
            # Generate project summary
            project_summary = await self._generate_project_summary(
                project_path, file_analyses, total_issues, total_recommendations
            )
            
            response = {
                'project_path': project_path,
                'analysis_timestamp': datetime.utcnow().isoformat(),
                'status': 'success',
                'summary': {
                    'files_analyzed': len(file_analyses),
                    'total_issues': total_issues,
                    'total_recommendations': total_recommendations,
                    'average_score': avg_score,
                    'project_grade': project_grade,
                    'analysis_summary': project_summary
                },
                'file_analyses': file_analyses[:10],  # Limit to first 10 for response size
                'total_files': len(file_analyses)
            }
            
            return response
            
        except Exception as e:
            logger.error(f"Error analyzing project quality: {e}")
            logger.error(traceback.format_exc())
            return {
                'error': str(e),
                'status': 'error',
                'project_path': project_path
            }
    
    async def get_quality_recommendations(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Get ML-powered quality recommendations"""
        try:
            self.metrics['ml_predictions'] += 1
            
            logger.info("Generating quality recommendations")
            
            recommendations = await self.quality_learning.get_smart_recommendations(context)
            
            return {
                'status': 'success',
                'timestamp': datetime.utcnow().isoformat(),
                'recommendations': recommendations,
                'context': context
            }
            
        except Exception as e:
            logger.error(f"Error getting recommendations: {e}")
            return {
                'error': str(e),
                'status': 'error'
            }
    
    async def run_quality_suite(self, target_path: str) -> Dict[str, Any]:
        """Run comprehensive quality analysis suite"""
        try:
            logger.info(f"Running quality suite on: {target_path}")
            
            # Run comprehensive analysis
            suite_results = await self.quality_learning.run_comprehensive_quality_suite(target_path)
            
            return {
                'status': 'success',
                'timestamp': datetime.utcnow().isoformat(),
                'target_path': target_path,
                'results': suite_results
            }
            
        except Exception as e:
            logger.error(f"Error running quality suite: {e}")
            return {
                'error': str(e),
                'status': 'error'
            }
    
    def _calculate_project_grade(self, score: float) -> str:
        """Calculate project grade based on average score"""
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'
    
    async def _generate_project_summary(self, project_path: str, file_analyses: List[Dict], 
                                      total_issues: int, total_recommendations: int) -> str:
        """Generate a summary of project quality analysis"""
        summary_parts = []
        
        if file_analyses:
            best_file = max(file_analyses, key=lambda x: x.get('overall_score', 0))
            worst_file = min(file_analyses, key=lambda x: x.get('overall_score', 0))
            
            summary_parts.append(f"Analyzed {len(file_analyses)} Python files.")
            summary_parts.append(f"Found {total_issues} total issues and generated {total_recommendations} recommendations.")
            summary_parts.append(f"Best file: {Path(best_file['file_path']).name} (score: {best_file.get('overall_score', 0):.1f})")
            summary_parts.append(f"Worst file: {Path(worst_file['file_path']).name} (score: {worst_file.get('overall_score', 0):.1f})")
        else:
            summary_parts.append("No files could be analyzed.")
        
        return " ".join(summary_parts)
    
    async def get_server_status(self) -> Dict[str, Any]:
        """Get server status and metrics"""
        return {
            'status': 'running' if self.is_running else 'stopped',
            'uptime_seconds': self.metrics['uptime_seconds'],
            'metrics': self.metrics.copy(),
            'config': {
                'name': self.config['server']['name'],
                'version': self.config['server']['version'],
                'ml_enabled': self.config['quality']['analysis']['enable_ml_predictions'],
                'caching_enabled': self.config['quality']['analysis']['enable_caching']
            },
            'cache_stats': {
                'entries': len(self.analysis_cache),
                'hit_rate': (self.metrics['cache_hits'] / max(1, self.metrics['cache_hits'] + self.metrics['cache_misses'])) * 100
            }
        }


async def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Quality MCP Server')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--port', type=int, help='Server port')
    parser.add_argument('--host', help='Server host')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create server instance
    server = QualityMCPServer(config_path=args.config)
    
    # Override config with CLI args
    if args.port:
        server.config['server']['port'] = args.port
    if args.host:
        server.config['server']['host'] = args.host
    
    try:
        # Start server
        await server.start_server()
        
    except KeyboardInterrupt:
        logger.info("Received shutdown signal")
        await server.stop_server()
        
    except Exception as e:
        logger.error(f"Server failed: {e}")
        await server.stop_server()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())