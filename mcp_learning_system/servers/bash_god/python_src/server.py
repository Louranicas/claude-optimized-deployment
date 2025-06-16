"""BASH_GOD Python Server - Main server integration"""

import asyncio
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import traceback

from .learning import BashGodLearning
from .command_predictor import CommandPredictor
from .chain_optimizer import ChainOptimizer
from .context_analyzer import ContextAnalyzer
from .safety_learner import SafetyLearner

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BashGodPythonServer:
    """Main Python server for BASH_GOD MCP integration"""
    
    def __init__(self):
        self.learning_system = BashGodLearning()
        self.rust_server = None  # Will be initialized with Rust binding
        self.learning_enabled = True
        self.performance_monitoring = True
        
        # Statistics tracking
        self.stats = {
            'commands_generated': 0,
            'patterns_learned': 0,
            'optimizations_applied': 0,
            'safety_checks_performed': 0,
            'total_requests': 0,
        }
        
        logger.info("BASH_GOD Python Server initialized")
    
    async def initialize_rust_integration(self):
        """Initialize integration with Rust backend"""
        try:
            # Import Rust module
            import bash_god_mcp
            self.rust_server = bash_god_mcp.PyBashGodServer()
            logger.info("Rust integration initialized successfully")
        except ImportError as e:
            logger.warning(f"Rust integration not available: {e}")
            logger.info("Running in Python-only mode")
    
    async def generate_intelligent_command(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Generate intelligent command using learning system"""
        try:
            self.stats['total_requests'] += 1
            
            task = request.get('task', '')
            context = request.get('context', {})
            constraints = request.get('constraints', [])
            dry_run = request.get('dry_run', False)
            
            logger.info(f"Generating command for task: {task}")
            
            # Use Rust backend if available
            if self.rust_server:
                try:
                    rust_response = await self._use_rust_backend(request)
                    if rust_response:
                        return rust_response
                except Exception as e:
                    logger.warning(f"Rust backend failed, falling back to Python: {e}")
            
            # Python fallback
            commands = self.learning_system.generate_intelligent_command(task, context)
            
            # Optimize commands
            optimized_commands = await self._optimize_commands(commands, context)
            
            # Apply safety checks
            safe_commands = await self._apply_safety_checks(optimized_commands, context)
            
            # Create response
            response = {
                'command': ' && '.join(safe_commands) if len(safe_commands) > 1 else safe_commands[0] if safe_commands else '',
                'commands': safe_commands,
                'explanation': f"Generated intelligent command chain for: {task}",
                'approach': self._determine_approach(task, context),
                'optimizations': await self._get_optimizations_applied(commands, optimized_commands),
                'safety_checks': await self._get_safety_checks_applied(optimized_commands, safe_commands),
                'alternatives': await self._generate_alternatives(task, context),
                'confidence': self._calculate_confidence(task, context),
                'dry_run': dry_run,
            }
            
            if dry_run:
                response['command'] = f"echo 'DRY RUN: {response['command']}'"
                response['commands'] = [f"echo 'DRY RUN: {cmd}'" for cmd in response['commands']]
            
            self.stats['commands_generated'] += 1
            
            return response
            
        except Exception as e:
            logger.error(f"Error generating command: {e}")
            logger.error(traceback.format_exc())
            return {
                'error': str(e),
                'command': '',
                'explanation': 'Failed to generate command',
                'confidence': 0.0,
            }
    
    async def _use_rust_backend(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Use Rust backend for command generation"""
        try:
            request_json = json.dumps(request)
            response_json = self.rust_server.generate_command(request_json)
            return json.loads(response_json)
        except Exception as e:
            logger.error(f"Rust backend error: {e}")
            return None
    
    async def _optimize_commands(self, commands: List[str], context: Dict[str, Any]) -> List[str]:
        """Optimize command chain"""
        try:
            optimizer = self.learning_system.chain_optimizer
            optimized = optimizer.optimize_for_context(commands, context)
            
            if optimized != commands:
                self.stats['optimizations_applied'] += 1
                logger.info(f"Applied optimizations: {len(commands)} -> {len(optimized)} commands")
            
            return optimized
        except Exception as e:
            logger.error(f"Optimization error: {e}")
            return commands
    
    async def _apply_safety_checks(self, commands: List[str], context: Dict[str, Any]) -> List[str]:
        """Apply safety checks to commands"""
        try:
            safety_learner = self.learning_system.safety_learner
            safe_commands = safety_learner.make_safe(commands)
            
            if safe_commands != commands:
                self.stats['safety_checks_performed'] += 1
                logger.info("Applied safety checks to commands")
            
            return safe_commands
        except Exception as e:
            logger.error(f"Safety check error: {e}")
            return commands
    
    def _determine_approach(self, task: str, context: Dict[str, Any]) -> str:
        """Determine the approach used"""
        try:
            predictor = self.learning_system.command_predictor
            return predictor.predict_approach(task, context)
        except Exception as e:
            logger.error(f"Approach determination error: {e}")
            return 'unknown'
    
    async def _get_optimizations_applied(self, original: List[str], optimized: List[str]) -> List[str]:
        """Get list of optimizations applied"""
        optimizations = []
        
        if len(optimized) < len(original):
            optimizations.append(f"Reduced command count from {len(original)} to {len(optimized)}")
        
        for i, (orig, opt) in enumerate(zip(original, optimized)):
            if orig != opt:
                optimizations.append(f"Command {i+1}: Optimized for performance")
        
        return optimizations
    
    async def _get_safety_checks_applied(self, original: List[str], safe: List[str]) -> List[str]:
        """Get list of safety checks applied"""
        safety_checks = []
        
        for i, (orig, safe_cmd) in enumerate(zip(original, safe)):
            if orig != safe_cmd:
                if '-i' in safe_cmd and '-i' not in orig:
                    safety_checks.append(f"Added interactive mode to command {i+1}")
                if 'read -p' in safe_cmd:
                    safety_checks.append(f"Added confirmation prompt to command {i+1}")
                if '[ -e' in safe_cmd:
                    safety_checks.append(f"Added existence check to command {i+1}")
        
        return safety_checks
    
    async def _generate_alternatives(self, task: str, context: Dict[str, Any]) -> List[str]:
        """Generate alternative approaches"""
        alternatives = []
        
        try:
            predictor = self.learning_system.command_predictor
            
            # Get approach suggestions
            suggestions = predictor.suggest_approach_combination(task, context)
            alternatives.extend(suggestions)
            
            # Get similar task suggestions
            similar_tasks = predictor.get_similar_tasks(task, top_k=3)
            for similar_task, similarity in similar_tasks:
                if similarity > 0.7:
                    alternatives.append(f"Similar approach used for: {similar_task}")
            
        except Exception as e:
            logger.error(f"Alternative generation error: {e}")
        
        return alternatives[:5]  # Limit to 5 alternatives
    
    def _calculate_confidence(self, task: str, context: Dict[str, Any]) -> float:
        """Calculate confidence in generated command"""
        try:
            # Base confidence
            confidence = 0.7
            
            # Increase confidence if we have similar patterns
            predictor = self.learning_system.command_predictor
            similar_tasks = predictor.get_similar_tasks(task, top_k=1)
            
            if similar_tasks:
                similarity = similar_tasks[0][1]
                confidence += similarity * 0.3
            
            # Increase confidence based on context completeness
            context_score = len(context) / 10.0  # Assume 10 is good context
            confidence += min(context_score * 0.2, 0.2)
            
            # Decrease confidence for complex tasks
            if len(task.split()) > 20:
                confidence -= 0.1
            
            return min(max(confidence, 0.0), 1.0)
            
        except Exception as e:
            logger.error(f"Confidence calculation error: {e}")
            return 0.5
    
    async def learn_from_execution(self, execution_data: Dict[str, Any]) -> Dict[str, Any]:
        """Learn from command execution"""
        try:
            if not self.learning_enabled:
                return {'status': 'learning_disabled'}
            
            # Use Rust backend if available
            if self.rust_server:
                try:
                    execution_json = json.dumps(execution_data)
                    self.rust_server.learn_pattern(execution_json)
                except Exception as e:
                    logger.warning(f"Rust learning failed: {e}")
            
            # Python learning
            task = execution_data.get('task', '')
            command = execution_data.get('command', '')
            success = execution_data.get('success', False)
            duration_ms = execution_data.get('duration_ms', 0)
            
            # Learn command patterns
            predictor = self.learning_system.command_predictor
            approach = predictor.predict_approach(task, execution_data.get('context', {}))
            predictor.learn_from_execution(task, approach, success, duration_ms)
            
            # Learn optimizations
            if success and duration_ms > 0:
                optimizer = self.learning_system.chain_optimizer
                suggestions = optimizer.suggest_improvements(command)
                if suggestions:
                    logger.info(f"Performance suggestions for '{command}': {suggestions}")
            
            # Learn safety patterns
            if not success:
                safety_learner = self.learning_system.safety_learner
                incident_data = {
                    'command': command,
                    'success': success,
                    'error': execution_data.get('error', ''),
                    'timestamp': datetime.now().timestamp(),
                    'context': execution_data.get('context', {}),
                }
                # Would analyze this in batch later
            
            self.stats['patterns_learned'] += 1
            
            return {
                'status': 'learned',
                'patterns_learned': self.stats['patterns_learned'],
            }
            
        except Exception as e:
            logger.error(f"Learning error: {e}")
            return {'status': 'error', 'error': str(e)}
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get system status and statistics"""
        try:
            # Get Rust status if available
            rust_status = {}
            if self.rust_server:
                try:
                    rust_info = self.rust_server.get_system_info()
                    rust_status = json.loads(rust_info)
                except Exception as e:
                    logger.warning(f"Failed to get Rust status: {e}")
            
            # Get Python learning stats
            learning_stats = self.learning_system.get_learning_stats()
            
            return {
                'python_server': {
                    'status': 'running',
                    'learning_enabled': self.learning_enabled,
                    'stats': self.stats,
                    'learning_stats': learning_stats,
                },
                'rust_server': rust_status,
                'memory_usage': await self._get_memory_usage(),
                'uptime': datetime.now().isoformat(),
            }
            
        except Exception as e:
            logger.error(f"Status check error: {e}")
            return {'error': str(e)}
    
    async def _get_memory_usage(self) -> Dict[str, Any]:
        """Get memory usage information"""
        try:
            if self.rust_server:
                memory_json = self.rust_server.get_memory_usage()
                return json.loads(memory_json)
            else:
                # Python-only memory estimation
                import psutil
                process = psutil.Process()
                return {
                    'python_memory_mb': process.memory_info().rss / 1024 / 1024,
                    'system_memory_percent': psutil.virtual_memory().percent,
                }
        except Exception as e:
            logger.error(f"Memory usage error: {e}")
            return {}
    
    async def validate_command(self, command: str) -> Dict[str, Any]:
        """Validate command safety"""
        try:
            # Use Rust backend if available
            if self.rust_server:
                try:
                    validation_json = self.rust_server.validate_command(command)
                    return json.loads(validation_json)
                except Exception as e:
                    logger.warning(f"Rust validation failed: {e}")
            
            # Python fallback
            safety_learner = self.learning_system.safety_learner
            risk_assessment = safety_learner.assess_risk(command)
            
            return {
                'is_safe': risk_assessment['risk_level'] in ['low', 'medium'],
                'risk_level': risk_assessment['risk_level'],
                'risk_score': risk_assessment['risk_score'],
                'warnings': risk_assessment['risk_factors'],
                'mitigations': risk_assessment['mitigations'],
            }
            
        except Exception as e:
            logger.error(f"Validation error: {e}")
            return {
                'is_safe': False,
                'error': str(e),
            }
    
    async def export_knowledge(self) -> Dict[str, Any]:
        """Export learned knowledge"""
        try:
            # Export Python knowledge
            python_knowledge = self.learning_system.export_knowledge()
            
            # Export Rust patterns if available
            rust_patterns = {}
            if self.rust_server:
                try:
                    patterns_json = self.rust_server.export_learned_patterns()
                    rust_patterns = json.loads(patterns_json)
                except Exception as e:
                    logger.warning(f"Failed to export Rust patterns: {e}")
            
            return {
                'python_knowledge': python_knowledge,
                'rust_patterns': rust_patterns,
                'export_timestamp': datetime.now().isoformat(),
                'stats': self.stats,
            }
            
        except Exception as e:
            logger.error(f"Knowledge export error: {e}")
            return {'error': str(e)}
    
    async def import_knowledge(self, knowledge_data: Dict[str, Any]) -> Dict[str, Any]:
        """Import previously learned knowledge"""
        try:
            # Import Python knowledge
            if 'python_knowledge' in knowledge_data:
                self.learning_system.import_knowledge(knowledge_data['python_knowledge'])
            
            # Import Rust patterns if available
            if 'rust_patterns' in knowledge_data and self.rust_server:
                try:
                    patterns_json = json.dumps(knowledge_data['rust_patterns'])
                    self.rust_server.import_learned_patterns(patterns_json)
                except Exception as e:
                    logger.warning(f"Failed to import Rust patterns: {e}")
            
            return {
                'status': 'imported',
                'timestamp': datetime.now().isoformat(),
            }
            
        except Exception as e:
            logger.error(f"Knowledge import error: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def set_learning_enabled(self, enabled: bool):
        """Enable or disable learning"""
        self.learning_enabled = enabled
        logger.info(f"Learning {'enabled' if enabled else 'disabled'}")
    
    def set_performance_monitoring(self, enabled: bool):
        """Enable or disable performance monitoring"""
        self.performance_monitoring = enabled
        logger.info(f"Performance monitoring {'enabled' if enabled else 'disabled'}")


# Example usage and integration
async def main():
    """Example usage of BASH_GOD Python Server"""
    server = BashGodPythonServer()
    await server.initialize_rust_integration()
    
    # Example command generation
    request = {
        'task': 'find large files in current directory',
        'context': {
            'cwd': '/home/user/project',
            'cpu_cores': 8,
            'memory_gb': 16,
            'tools': {'ripgrep': True, 'fd': True},
        },
        'constraints': ['fast execution'],
        'dry_run': False,
    }
    
    response = await server.generate_intelligent_command(request)
    print(f"Generated command: {response['command']}")
    print(f"Explanation: {response['explanation']}")
    print(f"Confidence: {response['confidence']}")
    
    # Example learning
    execution_data = {
        'task': 'find large files in current directory',
        'command': response['command'],
        'success': True,
        'duration_ms': 1500,
        'context': request['context'],
    }
    
    learn_response = await server.learn_from_execution(execution_data)
    print(f"Learning result: {learn_response}")


if __name__ == '__main__':
    asyncio.run(main())