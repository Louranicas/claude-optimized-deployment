"""Integration layer between Python learning system and Rust MCP server"""

import asyncio
from typing import Dict, Any, List, Optional
from pathlib import Path
import logging
import json
from datetime import datetime

from .learning import DevelopmentLearning, CodeChange
from .embeddings import CodeEmbeddingModel

logger = logging.getLogger(__name__)

class DevelopmentMCPIntegration:
    """Integration between Python ML components and Rust MCP server"""
    
    def __init__(self, rust_server_path: Optional[str] = None):
        self.learning_system = DevelopmentLearning()
        self.rust_server_path = rust_server_path
        self.is_connected = False
        self.pending_updates = []
        
    async def connect(self):
        """Connect to Rust MCP server"""
        if self.rust_server_path:
            # In production, this would establish actual connection
            logger.info(f"Connecting to Rust server at {self.rust_server_path}")
            self.is_connected = True
        else:
            logger.warning("No Rust server path provided, running in standalone mode")
            self.is_connected = False
    
    async def process_code_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Process code request through learning system"""
        try:
            # Check if we have learned patterns for this context
            context_embedding = await self.learning_system.code_embeddings.encode(
                request.get('content', '')
            )
            
            # Get prediction
            prediction = await self.learning_system.predict_next_code(request)
            
            # Track for learning
            self.pending_updates.append({
                'request': request,
                'prediction': prediction,
                'timestamp': datetime.now(),
            })
            
            # Process pending updates periodically
            if len(self.pending_updates) >= 10:
                await self._process_pending_updates()
            
            return {
                'success': True,
                'response': prediction,
                'learning_enabled': True,
            }
            
        except Exception as e:
            logger.error(f"Error processing code request: {e}")
            return {
                'success': False,
                'error': str(e),
                'response': {
                    'suggestion': '// Error processing request',
                    'confidence': 0.0,
                }
            }
    
    async def learn_from_session(self, session_data: Dict[str, Any]):
        """Learn from a coding session"""
        try:
            # Extract code changes
            code_changes = []
            
            for change in session_data.get('changes', []):
                code_change = CodeChange(
                    file_path=change['file_path'],
                    language=change['language'],
                    before=change.get('before', ''),
                    after=change.get('after', ''),
                    change_type=change.get('type', 'edit'),
                    timestamp=datetime.fromisoformat(change['timestamp']),
                )
                code_changes.append(code_change)
            
            # Learn patterns
            if code_changes:
                learning_update = await self.learning_system.learn_coding_patterns(code_changes)
                
                logger.info(f"Learned from {len(code_changes)} changes, "
                          f"extracted {len(learning_update.patterns)} patterns")
                
                # Send update to Rust server if connected
                if self.is_connected:
                    await self._send_learning_update(learning_update)
                
                return {
                    'success': True,
                    'patterns_learned': len(learning_update.patterns),
                    'confidence': learning_update.confidence,
                }
            
            return {
                'success': True,
                'patterns_learned': 0,
                'message': 'No changes to learn from',
            }
            
        except Exception as e:
            logger.error(f"Error learning from session: {e}")
            return {
                'success': False,
                'error': str(e),
            }
    
    async def _process_pending_updates(self):
        """Process pending learning updates"""
        if not self.pending_updates:
            return
        
        # Convert to code changes
        code_changes = []
        
        for update in self.pending_updates:
            request = update['request']
            prediction = update['prediction']
            
            # Create synthetic code change for learning
            code_change = CodeChange(
                file_path=request.get('file_path', 'unknown'),
                language=request.get('language', 'unknown'),
                before=request.get('content', ''),
                after=prediction.get('suggestion', ''),
                change_type='prediction',
                timestamp=update['timestamp'],
            )
            code_changes.append(code_change)
        
        # Learn from changes
        if code_changes:
            await self.learning_system.learn_coding_patterns(code_changes)
        
        # Clear pending updates
        self.pending_updates.clear()
    
    async def _send_learning_update(self, update):
        """Send learning update to Rust server"""
        # In production, this would send via IPC/socket
        logger.debug(f"Sending learning update with {len(update.patterns)} patterns")
    
    async def get_insights(self) -> Dict[str, Any]:
        """Get learning insights and statistics"""
        stats = self.learning_system.get_learning_stats()
        memory = self.learning_system.code_embeddings.get_memory_usage()
        
        return {
            'learning_stats': stats,
            'memory_usage': memory,
            'pending_updates': len(self.pending_updates),
            'is_connected': self.is_connected,
        }
    
    async def export_models(self, directory: str):
        """Export all learned models"""
        directory_path = Path(directory)
        directory_path.mkdir(parents=True, exist_ok=True)
        
        # Export main model
        model_path = directory_path / 'development_model.pkl'
        await self.learning_system.export_model(str(model_path))
        
        # Export metadata
        metadata = {
            'export_time': datetime.now().isoformat(),
            'learning_stats': self.learning_system.get_learning_stats(),
            'model_version': '1.0.0',
        }
        
        metadata_path = directory_path / 'model_metadata.json'
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"Exported models to {directory}")
        
        return {
            'success': True,
            'model_path': str(model_path),
            'metadata_path': str(metadata_path),
        }
    
    async def import_models(self, directory: str):
        """Import previously learned models"""
        directory_path = Path(directory)
        
        # Import main model
        model_path = directory_path / 'development_model.pkl'
        if model_path.exists():
            await self.learning_system.import_model(str(model_path))
            logger.info(f"Imported model from {model_path}")
            
            # Load metadata
            metadata_path = directory_path / 'model_metadata.json'
            if metadata_path.exists():
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                
                return {
                    'success': True,
                    'import_time': datetime.now().isoformat(),
                    'model_metadata': metadata,
                }
        
        return {
            'success': False,
            'error': 'Model files not found',
        }
    
    def get_memory_allocation(self) -> Dict[str, float]:
        """Get current memory allocation in MB"""
        embeddings_memory = self.learning_system.code_embeddings.get_memory_usage()
        
        return {
            'embeddings': embeddings_memory['total_mb'],
            'learning_history': len(self.learning_system.learning_history) * 0.001,  # Rough estimate
            'pending_updates': len(self.pending_updates) * 0.001,  # Rough estimate
            'total': embeddings_memory['total_mb'] + 
                    len(self.learning_system.learning_history) * 0.001 +
                    len(self.pending_updates) * 0.001,
        }


# Standalone functions for testing
async def test_integration():
    """Test the integration layer"""
    integration = DevelopmentMCPIntegration()
    await integration.connect()
    
    # Test code request
    request = {
        'file_path': 'test.py',
        'content': 'def hello():\n    ',
        'context': 'function_completion',
        'language': 'python',
        'intent': 'complete',
    }
    
    response = await integration.process_code_request(request)
    print(f"Response: {response}")
    
    # Test learning
    session_data = {
        'changes': [
            {
                'file_path': 'test.py',
                'language': 'python',
                'before': 'def hello():\n    pass',
                'after': 'def hello():\n    print("Hello, world!")',
                'type': 'edit',
                'timestamp': datetime.now().isoformat(),
            }
        ]
    }
    
    learning_result = await integration.learn_from_session(session_data)
    print(f"Learning result: {learning_result}")
    
    # Get insights
    insights = await integration.get_insights()
    print(f"Insights: {insights}")


if __name__ == "__main__":
    asyncio.run(test_integration())